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

import os
import re
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
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
    Vercel Blob, private access.

    Private blobs are never reachable by URL alone: every read goes through
    this server with the store token, which is what a store of packet
    captures, recovered passwords and carved malware needs.
    """

    kind = "blob"

    def __init__(self, prefix: str = "wirecub/"):
        try:
            from vercel import blob  # noqa: F401
        except ImportError as exc:  # pragma: no cover - deployment error
            raise StoreError(
                "The 'vercel' package is missing. It is listed in "
                "requirements.txt; redeploy so Vercel installs it."
            ) from exc
        if not os.environ.get("BLOB_READ_WRITE_TOKEN"):
            raise StoreError(
                "No Blob store is connected to this project. In the Vercel "
                "dashboard open Storage, create a Blob store and connect it "
                "to WireCub, then redeploy."
            )
        self._blob = blob
        self.prefix = prefix

    def _full(self, key: str) -> str:
        return self.prefix + _check_key(key)

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        try:
            self._blob.put(
                self._full(key), data,
                access="private",
                content_type=content_type,
                add_random_suffix=False,
                overwrite=True,
                multipart=len(data) > 8 * 1024 * 1024,
            )
        except Exception as exc:  # noqa: BLE001
            raise StoreError(f"Blob write failed: {exc}") from exc

    def put_file(self, key: str, source: Path, content_type: str = "application/octet-stream") -> None:
        self.put(key, Path(source).read_bytes(), content_type)

    def get(self, key: str) -> bytes | None:
        try:
            result = self._blob.get(self._full(key), access="private", use_cache=False)
        except self._blob.BlobNotFoundError:
            return None
        except Exception as exc:  # noqa: BLE001
            raise StoreError(f"Blob read failed: {exc}") from exc
        if result is None or getattr(result, "status_code", 200) == 404:
            return None
        return result.content

    def exists(self, key: str) -> bool:
        try:
            self._blob.head(self._full(key))
            return True
        except self._blob.BlobNotFoundError:
            return False
        except Exception:  # noqa: BLE001
            return False

    def _list_raw(self, prefix: str):
        cursor = None
        while True:
            page = self._blob.list_objects(
                prefix=self.prefix + prefix, cursor=cursor, limit=1000
            )
            yield from page.blobs
            if not page.has_more or not page.cursor:
                break
            cursor = page.cursor

    def list(self, prefix: str) -> list[dict]:
        _check_key(prefix)
        try:
            return [
                {
                    "key": item.pathname[len(self.prefix):],
                    "size": item.size,
                    "uploaded": item.uploaded_at.timestamp()
                    if item.uploaded_at else time.time(),
                    "url": item.url,
                }
                for item in self._list_raw(prefix)
            ]
        except Exception as exc:  # noqa: BLE001
            raise StoreError(f"Blob listing failed: {exc}") from exc

    def delete_prefix(self, prefix: str) -> int:
        items = self.list(prefix)
        urls = [item["url"] for item in items]
        for start in range(0, len(urls), 500):
            try:
                self._blob.delete(urls[start:start + 500])
            except Exception as exc:  # noqa: BLE001
                raise StoreError(f"Blob delete failed: {exc}") from exc
        return len(urls)

    def get_many(self, keys: list[str]) -> dict[str, bytes | None]:
        with ThreadPoolExecutor(max_workers=8) as pool:
            return dict(zip(keys, pool.map(self.get, keys)))
