"""
Vercel entrypoint.

Vercel looks for a FastAPI instance named `app` in index.py at the project
root. The server itself lives in backend/, next to the analysis engine, so
this file only puts that directory on the import path and re-exports it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))

from app import app  # noqa: E402,F401
