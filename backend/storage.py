"""
Where WireCub keeps what outlives a request.

Two back ends behind one small interface:

* LocalStore  — a directory on disk. Used when WireCub runs on a machine
  (Docker, the installer, uvicorn). Nothing leaves the host.
* BlobStore   — Vercel Blob with private access. Used on Vercel, where a
  function's disk is scratch space that disappears between requests and
  is not shared between instances.

Keys are slash-separated paths such as ``reports/<id>.json.gz``. They are
built by the server from validated identifiers, never taken from a request
as-is, but both stores still refuse anything that could climb out of the
namespace.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/]{0,300}$")


def _check_key(key: str) -> str:
    if not _KEY_RE.fullmatch(key) or ".." in key or "//" in key:
        raise ValueError(f"invalid storage key: {key!r}")
    return key


class StoreError(RuntimeError):
    """The store could not complete an operation."""


class LocalStore:
    kind = "local"

    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.root / _check_key(key)

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)

    def put_file(self, key: str, source: Path, content_type: str = "application/octet-stream") -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, path)

    def get(self, key: str) -> bytes | None:
        path = self._path(key)
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def list(self, prefix: str) -> list[dict]:
        _check_key(prefix)
        base = self.root / prefix
        # A prefix may name a directory ("reports/") or a file stem.
        search_root = base if base.is_dir() else base.parent
        if not search_root.exists():
            return []
        out = []
        for path in search_root.rglob("*"):
            if not path.is_file() or path.name.endswith(".tmp"):
                continue
            key = path.relative_to(self.root).as_posix()
            if not key.startswith(prefix):
                continue
            stat = path.stat()
            out.append({"key": key, "size": stat.st_size, "uploaded": stat.st_mtime})
        return out

    def get_many(self, keys: list[str]) -> dict[str, bytes | None]:
        return {key: self.get(key) for key in keys}

    def delete_prefix(self, prefix: str) -> int:
        _check_key(prefix)
        target = self.root / prefix.rstrip("/")
        if prefix.endswith("/") and target.is_dir():
            count = sum(1 for p in target.rglob("*") if p.is_file())
            shutil.rmtree(target, ignore_errors=True)
            return count
        count = 0
        for item in self.list(prefix):
            (self.root / item["key"]).unlink(missing_ok=True)
            count += 1
        return count

    def append_chunk(self, key: str, index: int, chunk_size: int, data: bytes) -> int:
        """
        Add one upload chunk to a single growing file.

        Locally the pieces go straight into one file so a 10 GB capture does
        not briefly occupy 20 GB. Chunks must arrive in order; a retry of the
        chunk just written is accepted and ignored.
        """
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        current = path.stat().st_size if path.exists() else 0
        expected = index * chunk_size
        if current == expected + len(data):
            return current  # the same chunk sent twice
        if current != expected:
            raise StoreError(
                f"chunk {index} arrived out of order ({current} bytes held, "
                f"{expected} expected)"
            )
        with open(path, "ab") as out:
            out.write(data)
        return current + len(data)


class BlobStore:
    """
    Vercel Blob, private access, spoken to over its HTTP API.

    Private blobs are never reachable by URL alone: every read goes through
    this server with credentials, which is what a store of packet captures,
    recovered passwords and carved malware needs.

    Two ways in, the same order Vercel's own SDK uses:
      1. OIDC: a store connected to the project gives BLOB_STORE_ID, and
         every request to the function carries a short-lived token in the
         x-vercel-oidc-token header (see set_oidc_token).
      2. A read-write token in BLOB_READ_WRITE_TOKEN.
    """

    kind = "blob"
    API = os.environ.get("VERCEL_BLOB_API_URL", "https://vercel.com/api/blob")
    API_VERSION = "12"
    READ_URL = "https://{store}.private.blob.vercel-storage.com/"

    def __init__(self, prefix: str = "wirecub/"):
        if not self._credentials(check_only=True):
            raise StoreError(
                "No Blob store is connected to this project. In the Vercel "
                "dashboard open Storage, create a Blob store (Private), "
                "connect it to this project, then redeploy."
            )
        self.prefix = prefix

    # -- credentials ----------------------------------------------------

    @staticmethod
    def _credentials(check_only: bool = False) -> tuple[str, str] | None:
        store_id = os.environ.get("BLOB_STORE_ID", "").strip()
        if store_id.startswith("store_"):
            store_id = store_id[len("store_"):]
        oidc = _OIDC["token"] or os.environ.get("VERCEL_OIDC_TOKEN", "").strip()
        if store_id and (oidc or check_only):
            if oidc:
                return oidc, store_id
        rw = (os.environ.get("BLOB_READ_WRITE_TOKEN")
              or os.environ.get("VERCEL_BLOB_READ_WRITE_TOKEN") or "").strip()
        if rw:
            parts = rw.split("_")
            return rw, (parts[3] if len(parts) > 3 else "")
        if store_id and check_only:
            # Connected through OIDC; the token arrives with the first request.
            return "", store_id
        return None

    def _auth(self) -> tuple[str, str]:
        creds = self._credentials()
        if not creds or not creds[0]:
            raise StoreError(
                "The Blob store is connected but no credential reached this "
                "request. Check that OIDC is enabled in the project settings "
                "(Settings → Security → Secure backend access with OIDC "
                "federation), or add BLOB_READ_WRITE_TOKEN."
            )
        return creds

    # -- transport ------------------------------------------------------

    def _request(self, method: str, url: str, body: bytes | None = None,
                 headers: dict | None = None, api: bool = True,
                 allow_404: bool = False):
        token, store_id = self._auth()
        all_headers = {"authorization": f"Bearer {token}"}
        if api:
            all_headers.update({
                "x-api-version": self.API_VERSION,
                "x-vercel-blob-store-id": store_id,
                "x-api-blob-request-id": f"{store_id}:{int(time.time() * 1000)}:{os.urandom(4).hex()}",
            })
        all_headers.update(headers or {})
        last_error = None
        for attempt in range(4):
            if api:
                all_headers["x-api-blob-request-attempt"] = str(attempt)
            request = urllib.request.Request(url, data=body, method=method, headers=all_headers)
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    return response.status, response.read()
            except urllib.error.HTTPError as exc:
                if exc.code == 404 and allow_404:
                    return 404, b""
                detail = exc.read()[:300].decode("utf-8", "replace")
                last_error = f"HTTP {exc.code}: {detail}"
                if exc.code < 500 and exc.code != 429:
                    break
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                last_error = str(exc)
            time.sleep(0.4 * (2 ** attempt))
        raise StoreError(f"Blob {method} failed: {last_error}")

    def _full(self, key: str) -> str:
        return self.prefix + _check_key(key)

    # -- operations -----------------------------------------------------

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        query = urllib.parse.urlencode({"pathname": self._full(key)})
        self._request("PUT", f"{self.API}/?{query}", body=bytes(data), headers={
            "x-vercel-blob-access": "private",
            "x-add-random-suffix": "0",
            "x-allow-overwrite": "1",
            "x-content-type": content_type,
            "content-type": "application/octet-stream",
        })

    def put_file(self, key: str, source: Path, content_type: str = "application/octet-stream") -> None:
        self.put(key, Path(source).read_bytes(), content_type)

    def get(self, key: str) -> bytes | None:
        _, store_id = self._auth()
        url = (self.READ_URL.format(store=store_id)
               + f"{urllib.parse.quote(self._full(key))}?cache=0")
        status, body = self._request("GET", url, api=False, allow_404=True)
        return None if status == 404 else body

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def _list_raw(self, prefix: str):
        cursor = None
        while True:
            params = {"prefix": self.prefix + prefix, "limit": "1000", "mode": "expanded"}
            if cursor:
                params["cursor"] = cursor
            _, body = self._request("GET", f"{self.API}?{urllib.parse.urlencode(params)}")
            page = json.loads(body or b"{}")
            yield from page.get("blobs", [])
            if not page.get("hasMore") or not page.get("cursor"):
                break
            cursor = page["cursor"]

    def list(self, prefix: str) -> list[dict]:
        _check_key(prefix)
        out = []
        for item in self._list_raw(prefix):
            uploaded = time.time()
            stamp = item.get("uploadedAt")
            if stamp:
                try:
                    uploaded = datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
                except ValueError:
                    pass
            out.append({
                "key": item["pathname"][len(self.prefix):],
                "size": item.get("size", 0),
                "uploaded": uploaded,
                "url": item["url"],
            })
        return out

    def delete_prefix(self, prefix: str) -> int:
        urls = [item["url"] for item in self.list(prefix)]
        for start in range(0, len(urls), 500):
            self._request("POST", f"{self.API}/delete",
                          body=json.dumps({"urls": urls[start:start + 500]}).encode(),
                          headers={"content-type": "application/json"})
        return len(urls)

    def get_many(self, keys: list[str]) -> dict[str, bytes | None]:
        with ThreadPoolExecutor(max_workers=8) as pool:
            return dict(zip(keys, pool.map(self.get, keys)))


# The newest OIDC token Vercel sent with a request. It is scoped to this
# project, so any request's token serves every request; the analysis runs
# in a worker thread, which is why this is shared rather than per request.
_OIDC = {"token": ""}


def set_oidc_token(token: str | None) -> None:
    if token:
        _OIDC["token"] = token.strip()
