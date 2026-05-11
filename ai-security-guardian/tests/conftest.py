from __future__ import annotations

import os
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_local_deps_env() -> None:
    env_path = ROOT / ".env.host-nondegraded.example"
    if not env_path.exists():
        return
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def pytest_configure(config):
    _load_local_deps_env()
    os.environ.setdefault("FLASK_ENV", "testing")
    os.environ.setdefault("ALERT_STREAM_CONSUMER_AUTOSTART", "false")
    os.environ.setdefault("AUDIT_INTEGRITY_PATROL", "false")
    os.environ.setdefault("REDIS_HOST", "127.0.0.1")
    os.environ.setdefault("REDIS_PORT", "56379")
    os.environ["GUARDIAN_REDIS_DISABLE_CONNECT"] = "false"
    os.environ["REQUIRE_REDIS_AVAILABLE"] = "true"


@pytest.fixture(autouse=True)
def _response_unit_tests_use_null_persistence(request, monkeypatch):
    if Path(str(request.fspath)).name == "test_responder.py":
        monkeypatch.delenv("DATABASE_URL", raising=False)
