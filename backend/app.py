"""
WireCub server.

One FastAPI application for both places WireCub runs:

* On a machine (Docker, the installer, uvicorn) it keeps everything on local
  disk and serves the interface itself.
* On Vercel it runs as a function. The function's disk is scratch space and
  requests can land on different instances, so captures arrive in chunks
  small enough for the platform's request limit, and reports, carved files
  and the history index live in a private Vercel Blob store.

Either way the analysis runs inside the request that asks for it and streams
its progress back as newline-delimited JSON. That keeps the two deployments
on one code path and needs neither WebSockets nor background workers that
outlive a request.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import os
import queue
import re
import shutil
import sqlite3
import threading
import time
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager, closing
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from engine import export, reputation
from engine.analyzer import Analyzer
from engine.reader import CaptureError, detect_format
from engine.serialize import build_report
from storage import BlobStore, LocalStore, StoreError

VERSION = "1.4"

BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR.parent / "public"

# Hosted means running as a Vercel function (Vercel sets VERCEL=1), or any
# deployment that asks for the Blob store explicitly.
HOSTED = bool(os.environ.get("VERCEL")) or os.environ.get("WIRECUB_STORE") == "blob"

if HOSTED:
    DATA_DIR = Path(os.environ.get("WIRECUB_SCRATCH", "/tmp/wirecub"))
else:
    DATA_DIR = Path(os.environ.get("WIRECUB_DATA", BASE_DIR.parent / "data"))

WORK_DIR = DATA_DIR / "work"
FEED_DIR = DATA_DIR / "feeds"
LEGACY_DB = DATA_DIR / "wirecub.db"


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


# A Vercel function takes at most 4.5 MB per request, so hosted uploads are
# cut into 4 MiB pieces. Locally the pieces are larger to keep a 10 GB
# upload to a few hundred requests.
CHUNK_BYTES = 4 * 1024 * 1024 if HOSTED else 32 * 1024 * 1024

# Hosted captures are bounded by the function: scratch disk, 2 GB of memory
# on the Hobby plan and five minutes per request. 200 MB fits comfortably.
MAX_UPLOAD_BYTES = _env_int(
    "WIRECUB_MAX_UPLOAD", 200 * 1024**2 if HOSTED else 10 * 1024**3
)

# Stop just short of the platform's hard limit so the analyst gets an
# explanation rather than a dropped connection. Zero means no budget.
TIME_BUDGET = _env_int("WIRECUB_TIME_BUDGET", 280 if HOSTED else 0)

# Hosted analyses expire; a public deployment should not accumulate other
# people's credentials forever. Zero keeps everything.
RETENTION_DAYS = _env_int("WIRECUB_RETENTION_DAYS", 7 if HOSTED else 0)

ACCESS_KEY = os.environ.get("WIRECUB_ACCESS_KEY", "").strip()
CRON_SECRET = os.environ.get("CRON_SECRET", "").strip()

# Largest response a Vercel function may return.
HOSTED_RESPONSE_LIMIT = 4_400_000

ALLOWED_SUFFIXES = (
    ".pcap", ".pcapng", ".cap", ".dmp", ".gz", ".bz2", ".zst", ".ntar",
)

_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_UPLOAD_RE = re.compile(r"^[0-9a-f]{24}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def _size_label(n: int) -> str:
    for unit, size in (("GB", 1024**3), ("MB", 1024**2), ("KB", 1024)):
        if n >= size:
            value = n / size
            return f"{value:.0f} {unit}" if value >= 10 or value == int(value) else f"{value:.1f} {unit}"
    return f"{n} B"


MAX_UPLOAD_LABEL = _size_label(MAX_UPLOAD_BYTES)


def _check_id(job_id: str) -> str:
    """Every identifier becomes part of a storage key, so it is checked first."""
    if not _ID_RE.fullmatch(job_id or ""):
        raise HTTPException(status_code=400, detail="Not a valid analysis id.")
    return job_id


def _check_upload(upload_id: str) -> str:
    if not _UPLOAD_RE.fullmatch(upload_id or ""):
        raise HTTPException(status_code=400, detail="Not a valid upload id.")
    return upload_id


def _clean_filename(name: str) -> str:
    """Keep a readable name for display; it is never used as a path."""
    leaf = re.split(r"[\\/]", str(name or ""))[-1]
    leaf = "".join(ch for ch in leaf if ch.isprintable()).strip()
    return leaf[:180] or "capture.pcap"


def _attachment(name: str) -> str:
    """Content-Disposition that survives quotes and non-Latin names."""
    ascii_name = name.encode("ascii", "replace").decode().replace('"', "_").replace("?", "_")
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}"


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

_STORE = None
_STORE_ERROR: str | None = None
_STORE_LOCK = threading.Lock()


def _store():
    global _STORE, _STORE_ERROR
    with _STORE_LOCK:
        if _STORE is None and _STORE_ERROR is None:
            try:
                _STORE = BlobStore() if HOSTED else LocalStore(DATA_DIR)
            except StoreError as exc:
                _STORE_ERROR = str(exc)
        if _STORE is None:
            raise HTTPException(status_code=503, detail=_STORE_ERROR)
        return _STORE


def _report_key(job_id: str) -> str:
    return f"reports/{job_id}.json.gz"


# The last few reports stay parsed in memory: exporting, the reputation tab
# and comparing all re-read the same report within seconds.
_REPORT_CACHE: "OrderedDict[str, dict]" = OrderedDict()
_REPORT_CACHE_LOCK = threading.Lock()


def _load_report_bytes(job_id: str) -> bytes:
    """The report as stored: gzip-compressed JSON."""
    store = _store()
    data = store.get(_report_key(job_id))
    if data is None and not HOSTED:
        # Reports written by WireCub 1.3 were plain JSON.
        legacy = store.get(f"reports/{job_id}.json")
        if legacy is not None:
            return gzip.compress(legacy, compresslevel=5)
    if data is None:
        raise HTTPException(status_code=404, detail="No report for that analysis.")
    return data


def _load_report(job_id: str) -> dict:
    _check_id(job_id)
    with _REPORT_CACHE_LOCK:
        if job_id in _REPORT_CACHE:
            _REPORT_CACHE.move_to_end(job_id)
            return _REPORT_CACHE[job_id]
    report = json.loads(gzip.decompress(_load_report_bytes(job_id)))
    with _REPORT_CACHE_LOCK:
        _REPORT_CACHE[job_id] = report
        while len(_REPORT_CACHE) > 4:
            _REPORT_CACHE.popitem(last=False)
    return report


def _forget_report(job_id: str) -> None:
    with _REPORT_CACHE_LOCK:
        _REPORT_CACHE.pop(job_id, None)


def _accepts_gzip(request: Request) -> bool:
    return "gzip" in request.headers.get("accept-encoding", "").lower()


def _payload(request: Request, body: bytes, media_type: str,
             headers: dict | None = None, precompressed: bool = False) -> Response:
    """
    Send a body, compressed when the client allows it.

    Reports compress about tenfold, which is what keeps them under the
    hosted response ceiling.
    """
    headers = dict(headers or {})
    headers.setdefault("Cache-Control", "private, no-store")
    headers["Vary"] = "Accept-Encoding"

    if precompressed:
        if _accepts_gzip(request):
            headers["Content-Encoding"] = "gzip"
        else:
            body = gzip.decompress(body)
    elif len(body) > 1024 and _accepts_gzip(request):
        body = gzip.compress(body, compresslevel=5)
        headers["Content-Encoding"] = "gzip"

    if HOSTED and len(body) > HOSTED_RESPONSE_LIMIT:
        raise HTTPException(
            status_code=413,
            detail="This response is larger than the hosted version can "
                   "return. Run WireCub locally for captures this size.",
        )
    return Response(body, media_type=media_type, headers=headers)


def _json(request: Request, obj) -> Response:
    return _payload(request, json.dumps(obj).encode(), "application/json")


# ---------------------------------------------------------------------------
# History index
# ---------------------------------------------------------------------------

def _index_entry(job: "Job", report: dict) -> dict:
    stats = report.get("stats", {})
    return {
        "id": job.id,
        "filename": job.filename,
        "size": job.size,
        "mode": "full",
        "created": job.created,
        "duration": report.get("meta", {}).get("analysis_seconds"),
        "packets": report.get("capture", {}).get("packets"),
        "hosts": stats.get("hosts"),
        "findings": stats.get("findings_total"),
        "risk_score": stats.get("risk_score"),
        "risk_band": stats.get("risk_band"),
        "verdict": stats.get("verdict"),
    }


def _migrate_legacy_history() -> None:
    """Carry the SQLite history of WireCub 1.3 into the file index, once."""
    if HOSTED or not LEGACY_DB.exists():
        return
    store = _store()
    try:
        with closing(sqlite3.connect(LEGACY_DB)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM analyses").fetchall()
        for row in rows:
            entry = {k: row[k] for k in row.keys() if k != "report_path"}
            if _ID_RE.fullmatch(entry.get("id") or ""):
                store.put(f"index/{entry['id']}.json", json.dumps(entry).encode(),
                          "application/json")
        LEGACY_DB.rename(LEGACY_DB.with_suffix(".db.migrated"))
    except (sqlite3.Error, OSError, StoreError):
        pass


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

@dataclass
class Job:
    id: str
    filename: str
    size: int
    created: float = field(default_factory=time.time)
    analyzer: Analyzer | None = None
    cancelled: bool = False
    timed_out: bool = False

    def cancel(self):
        self.cancelled = True
        if self.analyzer:
            self.analyzer.cancel()


# Only analyses that are running right now. Finished reports live in the
# store, not here, so memory does not grow with every capture analysed.
JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()

# Parsing is CPU bound: more concurrent analyses than cores makes every one
# of them slower. Later arrivals wait their turn and are told so.
MAX_WORKERS = max(1, min(4, os.cpu_count() or 2))
SLOTS = threading.Semaphore(MAX_WORKERS)


class _Cancelled(Exception):
    pass


def _assemble_capture(upload_id: str, job: Job, chunks: int, dest: Path, emit) -> None:
    """Put the uploaded pieces back together as one file on local disk."""
    store = _store()
    if not HOSTED:
        source = DATA_DIR / "uploads" / f"{upload_id}.part"
        if not source.exists():
            raise CaptureError("The upload was not found. Upload the capture again.")
        dest.parent.mkdir(parents=True, exist_ok=True)
        source.replace(dest)
        return

    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as out:
        for index in range(chunks):
            if job.cancelled:
                raise _Cancelled()
            piece = store.get(f"uploads/{upload_id}/{index:06d}")
            if piece is None:
                raise CaptureError(
                    f"Part {index + 1} of {chunks} never arrived. Upload the "
                    "capture again."
                )
            out.write(piece)
            emit("receiving", 4.0 * (index + 1) / chunks,
                 f"Receiving capture — part {index + 1} of {chunks}")


def _run_analysis(job: Job, upload_id: str, chunks: int, emit) -> dict:
    """Everything between an upload finishing and a report existing."""
    store = _store()
    work = WORK_DIR / job.id
    if HOSTED:
        capture_path = work / "capture"
        artifact_dir = work / "artifacts"
    else:
        capture_path = DATA_DIR / "captures" / f"{job.id}_{uuid.uuid4().hex[:4]}"
        artifact_dir = DATA_DIR / "artifacts" / job.id

    succeeded = False
    try:
        emit("receiving", 0.0, "Receiving capture")
        _assemble_capture(upload_id, job, chunks, capture_path, emit)

        actual = capture_path.stat().st_size
        if actual != job.size:
            raise CaptureError(
                f"The upload is incomplete ({actual:,} of {job.size:,} bytes "
                "arrived). Upload the capture again."
            )
        detect_format(str(capture_path))  # raises CaptureError when not a capture

        def progress(phase: str, percent: float, message: str):
            # The engine reports 0–100; receiving took the first few percent.
            emit(phase, 4.0 + percent * 0.94, message)

        analyzer = Analyzer(
            str(capture_path), deep=True, progress=progress,
            artifact_dir=str(artifact_dir),
        )
        job.analyzer = analyzer
        if job.cancelled:
            raise _Cancelled()

        timer = None
        if TIME_BUDGET > 0:
            def out_of_time():
                job.timed_out = True
                analyzer.cancel()
            timer = threading.Timer(TIME_BUDGET, out_of_time)
            timer.daemon = True
            timer.start()
        try:
            result = analyzer.run()
        finally:
            if timer:
                timer.cancel()

        if job.timed_out:
            raise CaptureError(
                f"The analysis did not finish within {TIME_BUDGET} seconds, the "
                "most a hosted request can run. Split the capture with "
                "editcap -c, or run WireCub locally for captures this size."
            )
        if analyzer._cancelled or job.cancelled:
            raise _Cancelled()

        emit("saving", 98.5, "Saving the report")
        report = build_report(
            result,
            meta={
                "job_id": job.id,
                "filename": job.filename,
                "file_size": job.size,
                "mode": "full",
                "analysed_at": time.time(),
                "analysis_seconds": round(result.duration_wall, 2),
                "tool": "WireCub",
                "version": VERSION,
            },
        )
        encoded = gzip.compress(json.dumps(report).encode(), compresslevel=5)

        if HOSTED and artifact_dir.exists():
            for path in artifact_dir.iterdir():
                if path.is_file() and _SHA_RE.fullmatch(path.stem):
                    store.put_file(f"artifacts/{job.id}/{path.name}", path)

        store.put(_report_key(job.id), encoded, "application/gzip")
        store.put(f"index/{job.id}.json",
                  json.dumps(_index_entry(job, report)).encode(),
                  "application/json")
        succeeded = True
        return report

    finally:
        if not HOSTED and not succeeded:
            # A capture that could not be analysed is not kept around.
            capture_path.unlink(missing_ok=True)
            shutil.rmtree(artifact_dir, ignore_errors=True)
        if HOSTED:
            shutil.rmtree(work, ignore_errors=True)
            try:
                store.delete_prefix(f"uploads/{upload_id}/")
            except StoreError:
                pass  # the daily cleanup removes stragglers


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    try:
        await run_in_threadpool(_migrate_legacy_history)
    except HTTPException:
        pass
    yield


app = FastAPI(title="WireCub", version=VERSION, lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


# ---------------------------------------------------------------- access key

def _session_token() -> str:
    return hmac.new(ACCESS_KEY.encode(), b"wirecub-session-v1", hashlib.sha256).hexdigest()


def _authorised(request: Request) -> bool:
    if not ACCESS_KEY:
        return True
    header = request.headers.get("x-wirecub-key", "")
    if header and hmac.compare_digest(header, ACCESS_KEY):
        return True
    cookie = request.cookies.get("wirecub_session", "")
    return bool(cookie) and hmac.compare_digest(cookie, _session_token())


_OPEN_PATHS = {"/api/config", "/api/auth", "/api/health", "/api/version",
               "/api/maintenance/cleanup"}


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and path not in _OPEN_PATHS and not _authorised(request):
        return JSONResponse(
            {"detail": "This WireCub needs its access key.", "auth": True},
            status_code=401,
        )
    response = await call_next(request)
    if path.startswith("/api/"):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


@app.post("/api/auth")
async def login(request: Request):
    if not ACCESS_KEY:
        return {"authenticated": True}
    try:
        body = await request.json()
    except ValueError:
        body = {}
    key = str((body or {}).get("key", ""))
    if not key or not hmac.compare_digest(key, ACCESS_KEY):
        # A pause per wrong guess; instances do not share state, so this is
        # the rate limit that works everywhere.
        time.sleep(0.6)
        raise HTTPException(status_code=401, detail="That key is not right.")
    response = JSONResponse({"authenticated": True})
    response.set_cookie(
        "wirecub_session", _session_token(),
        max_age=30 * 24 * 3600, httponly=True, samesite="strict",
        secure=request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto") == "https",
        path="/",
    )
    return response


@app.post("/api/auth/logout")
async def logout():
    response = JSONResponse({"authenticated": False})
    response.delete_cookie("wirecub_session", path="/")
    return response


# -------------------------------------------------------------------- config

@app.get("/api/config")
async def get_config(request: Request):
    store_error = None
    try:
        _store()
    except HTTPException as exc:
        store_error = exc.detail
    return {
        "hosted": HOSTED,
        "max_upload_bytes": MAX_UPLOAD_BYTES,
        "max_upload_label": MAX_UPLOAD_LABEL,
        "chunk_bytes": CHUNK_BYTES,
        "accepted_formats": list(ALLOWED_SUFFIXES),
        "time_budget_seconds": TIME_BUDGET,
        "retention_days": RETENTION_DAYS,
        "auth_required": bool(ACCESS_KEY),
        "authenticated": _authorised(request),
        "store_ready": store_error is None,
        "store_error": store_error,
        "open_to_public": HOSTED and not ACCESS_KEY,
    }


# -------------------------------------------------------------------- upload

@app.post("/api/uploads")
async def start_upload(request: Request):
    """Announce a capture before sending it: name and size are checked first."""
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="Expected a JSON body.")
    filename = _clean_filename(body.get("filename"))
    try:
        size = int(body.get("size", 0))
    except (TypeError, ValueError):
        size = 0

    if not filename.lower().endswith(ALLOWED_SUFFIXES):
        raise HTTPException(
            status_code=400,
            detail="That file type is not supported. WireCub reads .pcap, "
                   ".pcapng and .cap captures, optionally gzip, bzip2 or zstd "
                   "compressed.",
        )
    if size <= 0:
        raise HTTPException(status_code=400, detail="The file is empty.")
    if size > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Capture exceeds the {MAX_UPLOAD_LABEL} limit"
                   + (" of the hosted version. Split it with editcap -c, or "
                      "run WireCub locally." if HOSTED else "."),
        )
    _store()
    upload_id = uuid.uuid4().hex[:24]
    if not HOSTED:
        (DATA_DIR / "uploads").mkdir(parents=True, exist_ok=True)
        (DATA_DIR / "uploads" / f"{upload_id}.part").write_bytes(b"")
    return {
        "upload_id": upload_id,
        "chunk_bytes": CHUNK_BYTES,
        "chunks": -(-size // CHUNK_BYTES),
    }


@app.put("/api/uploads/{upload_id}/{index}")
async def upload_chunk(upload_id: str, index: int, request: Request):
    _check_upload(upload_id)
    if index < 0 or index * CHUNK_BYTES >= MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="Chunk index out of range.")

    data = bytearray()
    async for piece in request.stream():
        data.extend(piece)
        if len(data) > CHUNK_BYTES:
            raise HTTPException(status_code=413, detail="Chunk is larger than agreed.")
    if not data:
        raise HTTPException(status_code=400, detail="Empty chunk.")

    store = _store()
    try:
        if HOSTED:
            await run_in_threadpool(
                store.put, f"uploads/{upload_id}/{index:06d}", bytes(data)
            )
        else:
            if not (DATA_DIR / "uploads" / f"{upload_id}.part").exists():
                raise HTTPException(status_code=404, detail="Unknown upload.")
            await run_in_threadpool(
                store.append_chunk, f"uploads/{upload_id}.part", index,
                CHUNK_BYTES, bytes(data),
            )
    except StoreError as exc:
        raise HTTPException(status_code=409 if not HOSTED else 502, detail=str(exc))
    return {"received": index, "bytes": len(data)}


@app.post("/api/uploads/{upload_id}/analyze")
async def analyze_upload(upload_id: str, request: Request):
    """
    Analyse an uploaded capture, streaming progress as it goes.

    Each line of the response is one JSON event: progress, then exactly one
    of done, failed or cancelled.
    """
    _check_upload(upload_id)
    try:
        body = await request.json()
    except ValueError:
        body = {}
    try:
        size = int(body.get("size", 0))
        chunks = int(body.get("chunks", 0))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Size and chunk count are required.")
    if size <= 0 or size > MAX_UPLOAD_BYTES or chunks != -(-size // CHUNK_BYTES):
        raise HTTPException(status_code=400, detail="Size and chunk count do not agree.")
    _store()

    job = Job(id=uuid.uuid4().hex[:16], filename=_clean_filename(body.get("filename")),
              size=size)
    events: "queue.Queue[dict | None]" = queue.Queue()
    last = {"at": 0.0, "percent": -1.0}

    def emit(phase: str, percent: float, message: str, force: bool = False):
        now = time.monotonic()
        # Progress arrives thousands of times; a few updates a second is
        # plenty for a progress bar.
        if not force and now - last["at"] < 0.25 and percent - last["percent"] < 2:
            return
        last["at"], last["percent"] = now, percent
        events.put({"type": "progress", "job_id": job.id, "phase": phase,
                    "percent": round(min(100.0, max(0.0, percent)), 1),
                    "message": message})

    def worker():
        with JOBS_LOCK:
            JOBS[job.id] = job
        if not SLOTS.acquire(blocking=False):
            emit("queued", 0.0, "Waiting for another analysis to finish", force=True)
            while not SLOTS.acquire(timeout=1):
                if job.cancelled:
                    with JOBS_LOCK:
                        JOBS.pop(job.id, None)
                    events.put({"type": "cancelled", "job_id": job.id})
                    events.put(None)
                    return
        try:
            _run_analysis(job, upload_id, chunks, emit)
            events.put({"type": "done", "job_id": job.id})
        except _Cancelled:
            events.put({"type": "cancelled", "job_id": job.id})
        except CaptureError as exc:
            events.put({"type": "failed", "job_id": job.id, "error": str(exc)})
        except HTTPException as exc:
            events.put({"type": "failed", "job_id": job.id, "error": str(exc.detail)})
        except StoreError as exc:
            events.put({"type": "failed", "job_id": job.id,
                        "error": f"Could not save the result: {exc}"})
        except Exception as exc:  # noqa: BLE001
            events.put({"type": "failed", "job_id": job.id,
                        "error": f"Analysis failed: {type(exc).__name__}: {exc}"})
        finally:
            with JOBS_LOCK:
                JOBS.pop(job.id, None)
            SLOTS.release()
            events.put(None)

    threading.Thread(target=worker, daemon=True, name=f"wirecub-{job.id}").start()

    def stream():
        yield json.dumps({"type": "started", "job_id": job.id}) + "\n"
        try:
            while True:
                try:
                    event = events.get(timeout=10)
                except queue.Empty:
                    # Keeps proxies from treating a long parse as a dead link.
                    yield json.dumps({"type": "ping"}) + "\n"
                    continue
                if event is None:
                    return
                yield json.dumps(event) + "\n"
        finally:
            # The client went away (closed the tab or pressed Cancel): stop
            # spending CPU on a result nobody will read.
            job.cancel()

    return StreamingResponse(
        stream(), media_type="application/x-ndjson",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@app.post("/api/jobs/{job_id}/cancel")
async def cancel_job(job_id: str):
    _check_id(job_id)
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job:
        job.cancel()
    return {"id": job_id, "cancelled": bool(job)}


# ------------------------------------------------------------------- reports

@app.get("/api/reports/{job_id}")
async def get_report(job_id: str, request: Request):
    _check_id(job_id)
    data = await run_in_threadpool(_load_report_bytes, job_id)
    return _payload(request, data, "application/json", precompressed=True)


@app.get("/api/reports/{job_id}/download")
async def download_report(job_id: str, request: Request):
    _check_id(job_id)
    data = await run_in_threadpool(_load_report_bytes, job_id)
    return _payload(
        request, data, "application/json",
        headers={"Content-Disposition": _attachment(f"wirecub-{job_id}.json")},
        precompressed=True,
    )


@lru_cache(maxsize=1)
def _logo_data_uri() -> str | None:
    """Inline the logo so an exported report stays a single file."""
    for logo in (BASE_DIR / "assets" / "logo.png", PUBLIC_DIR / "app" / "logo.png"):
        if logo.exists():
            encoded = base64.b64encode(logo.read_bytes()).decode("ascii")
            return f"data:image/png;base64,{encoded}"
    return None


# The HTML report carries capture content. It is escaped, and this policy
# makes sure nothing in it could run even if something slipped through.
_REPORT_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
               "font-src data:; base-uri 'none'; form-action 'none'")


@app.get("/api/reports/{job_id}/export/{fmt}")
async def export_report(job_id: str, fmt: str, request: Request, table: str = "findings"):
    """Export an analysis as HTML, STIX 2.1, MISP or CSV."""
    report = await run_in_threadpool(_load_report, job_id)
    stem = Path(report.get("meta", {}).get("filename", "capture")).stem or "capture"

    if fmt == "html":
        document = export.build_html_report(report, _logo_data_uri())
        return _payload(request, document.encode(), "text/html; charset=utf-8", {
            "Content-Disposition": _attachment(f"wirecub-{stem}.html"),
            "Content-Security-Policy": _REPORT_CSP,
        })
    if fmt == "stix":
        return _payload(request, json.dumps(export.build_stix(report), indent=2).encode(),
                        "application/json",
                        {"Content-Disposition": _attachment(f"wirecub-{stem}-stix.json")})
    if fmt == "misp":
        return _payload(request, json.dumps(export.build_misp_event(report), indent=2).encode(),
                        "application/json",
                        {"Content-Disposition": _attachment(f"wirecub-{stem}-misp.json")})
    if fmt == "csv":
        try:
            data = export.build_csv(report, table)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return _payload(request, data.encode(), "text/csv; charset=utf-8", {
            "Content-Disposition": _attachment(f"wirecub-{stem}-{table}.csv"),
        })
    raise HTTPException(status_code=400,
                        detail="Unknown format. Choose html, stix, misp or csv.")


@app.get("/api/reports/{job_id}/view")
async def view_report(job_id: str, request: Request):
    """The HTML report rendered in the browser rather than downloaded."""
    report = await run_in_threadpool(_load_report, job_id)
    return _payload(
        request, export.build_html_report(report, _logo_data_uri()).encode(),
        "text/html; charset=utf-8",
        {"Content-Security-Policy": _REPORT_CSP},
    )


@app.get("/api/reports/{job_id}/files/{sha256}")
async def download_artifact(job_id: str, sha256: str, request: Request):
    """
    Retrieve a file that was carved out of the capture.

    Served as an octet-stream with a hash-derived filename: the name a
    server or SMB client supplied is attacker-controlled input and is not
    used to write or serve anything.
    """
    _check_id(job_id)
    sha256 = sha256.lower()
    if not _SHA_RE.fullmatch(sha256):
        raise HTTPException(status_code=400, detail="Not a valid SHA-256 hash.")

    data = await run_in_threadpool(_store().get, f"artifacts/{job_id}/{sha256}.bin")
    if data is None:
        raise HTTPException(
            status_code=404,
            detail="That file was not retained. Files above the size cap are "
                   "hashed but not stored.",
        )
    report = await run_in_threadpool(_load_report, job_id)
    record = next((f for f in report.get("files", []) if f.get("sha256") == sha256), None)
    extension = re.sub(r"[^a-z0-9]", "", str((record or {}).get("extension", "bin")).lower())[:8] or "bin"

    return _payload(request, data, "application/octet-stream", {
        "Content-Disposition": _attachment(f"{sha256[:16]}.{extension}"),
        # Carved files may be live malware. Nothing about the response
        # should encourage a browser to interpret rather than save it.
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; sandbox",
    })


# ---------------------------------------------------------------- reputation

# Loaded once per process and shared. Feeds are a few hundred thousand lines
# at most, so holding them in memory beats re-reading them per request.
_REPUTATION: reputation.ReputationStore | None = None
_REPUTATION_LOCK = threading.Lock()


def _reputation_store() -> reputation.ReputationStore:
    global _REPUTATION
    with _REPUTATION_LOCK:
        if _REPUTATION is None:
            FEED_DIR.mkdir(parents=True, exist_ok=True)
            if HOSTED:
                # A fresh instance starts with an empty disk; the feeds the
                # last refresh stored are pulled back from the Blob store.
                try:
                    store = _store()
                    for item in store.list("feeds/"):
                        name = item["key"].rsplit("/", 1)[-1]
                        target = FEED_DIR / name
                        if not target.exists():
                            data = store.get(item["key"])
                            if data is not None:
                                target.write_bytes(data)
                except (StoreError, HTTPException, OSError):
                    pass
            _REPUTATION = reputation.ReputationStore(FEED_DIR)
        return _REPUTATION


def _persist_feeds() -> None:
    if not HOSTED:
        return
    store = _store()
    for path in FEED_DIR.iterdir():
        if path.is_file() and re.fullmatch(r"[a-z0-9\-]+\.(txt|json)", path.name):
            store.put(f"feeds/{path.name}", path.read_bytes(), "text/plain")


@app.get("/api/reputation/status")
async def reputation_status():
    """Which feeds are cached, how large, and how old."""
    store = await run_in_threadpool(_reputation_store)
    return {
        "ready": store.ready,
        "feeds": store.feed_status(),
        "note": "Every source here is a public list that needs no account "
                "and no API key. Feeds are cached and matched locally, so "
                "analysis never waits on the network.",
    }


@app.post("/api/reputation/refresh")
async def reputation_refresh(force: bool = False):
    """
    Download the public blocklists.

    Never triggered by an analysis. If the machine is isolated the request
    fails cleanly and cached feeds keep working.
    """
    store = await run_in_threadpool(_reputation_store)
    report = await run_in_threadpool(lambda: store.refresh(force=force))
    try:
        await run_in_threadpool(_persist_feeds)
    except (StoreError, OSError):
        pass
    updated = sum(1 for r in report.values() if r.get("status") == "updated")
    failed = [name for name, r in report.items() if r.get("status") == "failed"]
    return {
        "report": report,
        "updated": updated,
        "failed": failed,
        "ready": store.ready,
        "feeds": store.feed_status(),
    }


def _reputation_for(report: dict, dnsbl: bool, online: bool) -> dict:
    store = _reputation_store()
    feeds_ready = store.ready
    verdicts = []
    checked_addresses = 0
    external_hosts = [h for h in report.get("hosts", []) if not h.get("internal")]

    for host in external_hosts:
        checked_addresses += 1
        verdict = store.check_ip(host["ip"])
        if dnsbl and not verdict.listed:
            for hit in reputation.check_dnsbl(host["ip"]):
                verdict.listed = True
                verdict.sources.append(hit)
                verdict.worst_severity = max(
                    verdict.worst_severity, hit["severity"],
                    key=lambda s: reputation.SEVERITY_ORDER.get(s, 0),
                )
        if verdict.listed:
            entry = verdict.to_dict()
            entry["packets"] = host.get("packets")
            entry["bytes"] = host.get("bytes")
            verdicts.append(entry)

    domains = {d["name"] for d in report.get("dns", {}).get("top_domains", [])}
    domains |= {h["host"] for h in report.get("http", {}).get("top_hosts", [])}
    domains |= {t["name"] for t in report.get("tls", {}).get("top_sni", [])}
    for domain in sorted(domains)[:400]:
        verdict = store.check_domain(domain)
        if verdict.listed:
            verdicts.append(verdict.to_dict())

    # Optional live lookup. Off by default: it is the only step that sends
    # anything outward, and it sends addresses rather than capture content.
    context = reputation.lookup_addresses([h["ip"] for h in external_hosts][:200]) if online else {}

    # Every external address gets a row, not only the ones a feed matched.
    by_indicator = {v["indicator"]: v for v in verdicts}
    for host in external_hosts:
        ip = host["ip"]
        entry = by_indicator.get(ip)
        if entry is None:
            entry = {"indicator": ip, "kind": "ip", "listed": False,
                     "sources": [], "worst_severity": "info"}
            verdicts.append(entry)
            by_indicator[ip] = entry
        entry["packets"] = host.get("packets")
        entry["bytes"] = host.get("bytes")
        entry["risk"] = host.get("risk", 0)
        entry["services"] = host.get("services", [])
        entry["context"] = context.get(ip)
        entry["score"], entry["reasons"] = reputation.score_address(entry, context.get(ip))
        # Behaviour observed in this capture outranks a list compiled elsewhere.
        if host.get("risk"):
            bump = min(30, host["risk"] // 2)
            entry["score"] = min(100, entry["score"] + bump)
            entry["reasons"].insert(
                0, f"Detections in this capture scored the host {host['risk']} (+{bump})")
        entry["pivots"] = reputation.pivot_links(ip, "ip")

    for entry in verdicts:
        if "score" not in entry:
            entry["score"], entry["reasons"] = reputation.score_address(entry, None)
            entry["pivots"] = reputation.pivot_links(entry["indicator"], entry.get("kind", "ip"))

    verdicts.sort(key=lambda v: -v.get("score", 0))
    return {
        "available": True,
        "feeds_ready": feeds_ready,
        "feeds_note": None if feeds_ready else
            "Blocklists have not been downloaded yet, so nothing here has "
            "been checked against public intelligence. Scores below come "
            "from this capture's own detections. Downloading the feeds "
            "needs no account or API key.",
        "online_used": online,
        "verdicts": verdicts,
        "addresses_checked": checked_addresses,
        "domains_checked": len(domains),
        "dnsbl_used": dnsbl,
        "feeds": store.feed_status(),
    }


@app.get("/api/reports/{job_id}/reputation")
async def report_reputation(job_id: str, request: Request,
                            dnsbl: bool = False, online: bool = False):
    """Check this analysis's indicators against the cached feeds."""
    report = await run_in_threadpool(_load_report, job_id)
    # Blocking DNS and HTTP stay off the event loop.
    data = await run_in_threadpool(_reputation_for, report, dnsbl, online)
    return _json(request, data)


_INDICATOR_RE = re.compile(r"^[A-Za-z0-9.:\-_]{1,253}$")


@app.get("/api/reputation/lookup/{indicator}")
async def reputation_lookup(indicator: str, kind: str = "ip"):
    """Look one indicator up: blocklists, network context, registry record."""
    if kind not in ("ip", "domain") or not _INDICATOR_RE.fullmatch(indicator):
        raise HTTPException(status_code=400, detail="Not an address or domain.")
    store = await run_in_threadpool(_reputation_store)

    if kind == "ip":
        verdict = store.check_ip(indicator).to_dict()
        context = await run_in_threadpool(reputation.lookup_addresses, [indicator])
        registry = await run_in_threadpool(reputation.lookup_rdap, indicator)
        network = context.get(indicator)
    else:
        verdict = store.check_domain(indicator).to_dict()
        network = None
        registry = None

    score, reasons = reputation.score_address(verdict, network)
    return {
        "indicator": indicator, "kind": kind, "verdict": verdict,
        "context": network, "registry": registry, "score": score,
        "reasons": reasons, "pivots": reputation.pivot_links(indicator, kind),
    }


# ------------------------------------------------------------------- history

@app.get("/api/compare")
async def compare(baseline: str, current: str, request: Request):
    """Compare a capture against an earlier baseline from the same network."""
    _check_id(baseline)
    _check_id(current)
    if baseline == current:
        raise HTTPException(status_code=400, detail="Pick two different analyses to compare.")
    old = await run_in_threadpool(_load_report, baseline)
    new = await run_in_threadpool(_load_report, current)
    return _json(request, export.compare_reports(old, new))


def _history(limit: int) -> list[dict]:
    store = _store()
    keys = [item["key"] for item in store.list("index/")
            if item["key"].endswith(".json")]
    if hasattr(store, "get_many"):
        blobs = store.get_many(keys)
    else:
        blobs = {key: store.get(key) for key in keys}
    rows = []
    for data in blobs.values():
        if not data:
            continue
        try:
            rows.append(json.loads(data))
        except ValueError:
            continue
    rows.sort(key=lambda row: -(row.get("created") or 0))
    return rows[:limit]


@app.get("/api/history")
async def get_history(limit: int = 50):
    limit = max(1, min(200, limit))
    try:
        return await run_in_threadpool(_history, limit)
    except StoreError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


def _delete_analysis(job_id: str) -> None:
    store = _store()
    store.delete_prefix(f"index/{job_id}.json")
    store.delete_prefix(f"reports/{job_id}.json")  # also removes .json.gz
    store.delete_prefix(f"artifacts/{job_id}/")
    if not HOSTED:
        for path in (DATA_DIR / "captures").glob(f"{job_id}_*"):
            path.unlink(missing_ok=True)
    _forget_report(job_id)


@app.delete("/api/history/{job_id}")
async def delete_analysis(job_id: str):
    _check_id(job_id)
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job:
        job.cancel()
    try:
        await run_in_threadpool(_delete_analysis, job_id)
    except StoreError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"deleted": job_id}


# --------------------------------------------------------------- maintenance

def _cleanup() -> dict:
    store = _store()
    now = time.time()
    removed_analyses = 0
    if RETENTION_DAYS > 0:
        cutoff = now - RETENTION_DAYS * 86400
        for item in store.list("index/"):
            job_id = item["key"].rsplit("/", 1)[-1].removesuffix(".json")
            if _ID_RE.fullmatch(job_id) and item["uploaded"] < cutoff:
                _delete_analysis(job_id)
                removed_analyses += 1
    # Uploads that never reached analysis: abandoned tabs, dropped links.
    stale = 0
    for item in store.list("uploads/"):
        if item["uploaded"] < now - 6 * 3600:
            store.delete_prefix(item["key"])
            stale += 1
    return {"removed_analyses": removed_analyses, "removed_upload_parts": stale,
            "retention_days": RETENTION_DAYS}


@app.get("/api/maintenance/cleanup")
async def cleanup(request: Request):
    """Expire old analyses. Vercel Cron calls this once a day."""
    bearer = request.headers.get("authorization", "")
    if CRON_SECRET:
        if not hmac.compare_digest(bearer, f"Bearer {CRON_SECRET}"):
            raise HTTPException(status_code=401, detail="Not authorised.")
    elif ACCESS_KEY and not _authorised(request):
        raise HTTPException(status_code=401, detail="Not authorised.")
    try:
        return await run_in_threadpool(_cleanup)
    except StoreError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@lru_cache(maxsize=1)
def _build_stamp() -> dict:
    """Identify exactly which copy of the interface is running."""
    digest = hashlib.sha256()
    found = False
    for name in ("app.js", "index.html", "styles.css"):
        path = PUBLIC_DIR / "app" / name
        if path.exists():
            digest.update(name.encode())
            digest.update(path.read_bytes())
            found = True
    return {
        "version": VERSION,
        "asset_hash": digest.hexdigest()[:12] if found else "hosted",
        "hosted": HOSTED,
    }


@app.get("/api/version")
async def version():
    return _build_stamp()


@app.get("/api/health")
async def health():
    usage = shutil.disk_usage(DATA_DIR if DATA_DIR.exists() else "/")
    with JOBS_LOCK:
        running = len(JOBS)
    return {
        "status": "ok",
        "version": VERSION,
        "hosted": HOSTED,
        "store": "blob" if HOSTED else "local",
        "store_error": _STORE_ERROR,
        "scratch_free_bytes": usage.free,
        "running_analyses": running,
        "workers": MAX_WORKERS,
    }


# ------------------------------------------------------------------ interface

class NoStoreStatic(StaticFiles):
    """
    Serve the interface with caching disabled.

    These files change with every build and are small. A browser that holds
    on to them makes an upgrade look as if it did nothing.
    """

    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-store, must-revalidate"
        return response


# On Vercel the public/ directory is served by the CDN before a request ever
# reaches this function, so it is only mounted when running on a machine.
if not HOSTED and PUBLIC_DIR.exists():
    app.mount("/", NoStoreStatic(directory=PUBLIC_DIR, html=True), name="static")


if __name__ == "__main__":  # python3 app.py
    import uvicorn

    uvicorn.run(app, host=os.environ.get("WIRECUB_HOST", "127.0.0.1"),
                port=_env_int("WIRECUB_PORT", 8000))
