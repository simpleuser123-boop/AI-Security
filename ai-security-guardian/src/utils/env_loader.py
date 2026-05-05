"""Minimal .env loader for local script execution.

Docker Compose reads .env itself, but ``python main.py`` and
``python -m web.app`` do not. Keep this intentionally small to avoid adding a
runtime dependency for simple KEY=VALUE files.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def load_dotenv_file(path: str | os.PathLike[str] | None = None) -> None:
    """Load missing environment variables from a local .env file."""
    if os.environ.get("FLASK_ENV") == "production":
        return
    if "pytest" in sys.modules:
        return
    if any("pytest" in Path(arg).name.lower() for arg in sys.argv):
        return

    env_path = Path(path) if path is not None else Path.cwd() / ".env"
    if not env_path.exists() or not env_path.is_file():
        return

    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        os.environ[key] = value
