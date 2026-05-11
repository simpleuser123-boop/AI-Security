#!/usr/bin/env python3
"""Run local non-degraded tests against real PostgreSQL and Redis.

This entrypoint is intentionally narrow: it validates the local dependency
environment, then runs only the strict non-degraded probes in this file.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import uuid
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_FILE = ROOT / ".env.host-nondegraded.example"
REQUIRED_MODEL_FILES = (
    "intrusion_rf_v1.pkl",
    "ddos_rf_v1.pkl",
    "web_attack_nb_v1.pkl",
    "anomaly_if_v1.pkl",
)


def _load_env(path: Path) -> None:
    if not path.exists():
        raise RuntimeError(f"env file not found: {path}")
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ[key.strip()] = value.strip().strip("'\"")


def _database_url() -> str:
    database_url = os.environ.get("DATABASE_URL", "")
    assert database_url, "DATABASE_URL is required"
    url = make_url(database_url)
    assert url.get_backend_name() == "postgresql", (
        f"DATABASE_URL must be PostgreSQL, got {url.get_backend_name()!r}"
    )
    assert "sqlite" not in database_url.lower(), "SQLite is forbidden"
    assert (url.host or "").lower() == "127.0.0.1", (
        "wrong env for host non-degraded tests: DATABASE_URL must use "
        "127.0.0.1, not Compose service names or localhost"
    )
    return database_url


def _assert_strict_environment() -> None:
    _database_url()
    assert os.environ.get("GUARDIAN_REDIS_DISABLE_CONNECT", "").lower() != "true", (
        "GUARDIAN_REDIS_DISABLE_CONNECT=true is forbidden"
    )
    assert os.environ.get("REQUIRE_REDIS_AVAILABLE", "").lower() == "true", (
        "REQUIRE_REDIS_AVAILABLE must be true"
    )
    assert os.environ.get("REQUIRE_MODELS_READY", "").lower() == "true", (
        "REQUIRE_MODELS_READY must be true"
    )
    assert os.environ.get("REDIS_HOST"), "REDIS_HOST is required"
    assert os.environ.get("REDIS_PORT"), "REDIS_PORT is required"
    assert os.environ.get("REDIS_PASSWORD"), "REDIS_PASSWORD is required"
    assert os.environ.get("REDIS_HOST", "").lower() == "127.0.0.1", (
        "wrong env for host non-degraded tests: REDIS_HOST must be 127.0.0.1, "
        "not Compose service names or localhost"
    )


def _model_dir() -> Path:
    raw = os.environ.get("MODEL_DIR", "models/saved")
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT / path
    return path


def _run_verify_local_deps(env_file: Path) -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_local_deps.py"), str(env_file)],
        cwd=ROOT,
        check=True,
    )


class NoSkipPlugin:
    def __init__(self) -> None:
        self.skipped: list[str] = []

    def pytest_collection_modifyitems(self, config, items):  # noqa: ANN001
        skip_marked = [
            item.nodeid
            for item in items
            if item.get_closest_marker("skip") or item.get_closest_marker("skipif")
        ]
        if skip_marked:
            raise RuntimeError("skip markers are forbidden: " + ", ".join(skip_marked))

    def pytest_runtest_logreport(self, report):  # noqa: ANN001
        if report.skipped:
            self.skipped.append(report.nodeid)

    def pytest_sessionfinish(self, session, exitstatus):  # noqa: ANN001
        if self.skipped:
            terminal = session.config.pluginmanager.get_plugin("terminalreporter")
            if terminal is not None:
                terminal.write_line(
                    "Skipped tests are forbidden: " + ", ".join(self.skipped),
                    red=True,
                )
            session.exitstatus = 1


def test_non_degraded_environment_is_strict() -> None:
    _assert_strict_environment()


def test_application_config_uses_postgresql_and_required_guards() -> None:
    _assert_strict_environment()
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    from config.config import get_config

    cfg = get_config()
    configured_url = cfg.SQLALCHEMY_DATABASE_URI
    assert configured_url == os.environ["DATABASE_URL"]
    assert make_url(configured_url).get_backend_name() == "postgresql"
    assert bool(getattr(cfg, "REQUIRE_REDIS_AVAILABLE", False)) is True
    assert bool(getattr(cfg, "REQUIRE_MODELS_READY", False)) is True


def test_postgresql_real_round_trip() -> None:
    _assert_strict_environment()
    token = uuid.uuid4().hex
    engine = create_engine(_database_url(), pool_pre_ping=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "CREATE TEMPORARY TABLE guardian_non_degraded_probe "
                    "(id text primary key) ON COMMIT DROP"
                )
            )
            conn.execute(
                text("INSERT INTO guardian_non_degraded_probe (id) VALUES (:id)"),
                {"id": token},
            )
            value = conn.execute(
                text("SELECT id FROM guardian_non_degraded_probe WHERE id = :id"),
                {"id": token},
            ).scalar_one()
        assert value == token
    finally:
        engine.dispose()


def test_redis_real_round_trip_and_client_mode() -> None:
    _assert_strict_environment()
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    import redis
    from src.utils.redis_client import RedisClient

    key = f"guardian:non_degraded_probe:{uuid.uuid4().hex}"
    raw = redis.Redis(
        host=os.environ["REDIS_HOST"],
        port=int(os.environ["REDIS_PORT"]),
        db=int(os.environ.get("REDIS_DB", "0")),
        password=os.environ["REDIS_PASSWORD"],
        socket_connect_timeout=2,
        socket_timeout=2,
        decode_responses=True,
    )
    assert raw.ping() is True
    try:
        assert raw.set(key, "ok", ex=30) is True
        assert raw.get(key) == "ok"
    finally:
        raw.delete(key)

    client = RedisClient(
        host=os.environ["REDIS_HOST"],
        port=int(os.environ["REDIS_PORT"]),
        db=int(os.environ.get("REDIS_DB", "0")),
        password=os.environ["REDIS_PASSWORD"],
    )
    assert client.mode == "redis"
    assert client.is_available is True


def test_required_model_files_are_present() -> None:
    _assert_strict_environment()
    model_dir = _model_dir()
    missing = [name for name in REQUIRED_MODEL_FILES if not (model_dir / name).is_file()]
    assert not missing, f"missing required model files: {missing}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run non-degraded local tests with real PostgreSQL and Redis."
    )
    parser.add_argument(
        "--env-file",
        default=str(DEFAULT_ENV_FILE),
        help="env file with local PostgreSQL and Redis settings",
    )
    args = parser.parse_args(argv)

    env_file = Path(args.env_file)
    if not env_file.is_absolute():
        env_file = ROOT / env_file

    _load_env(env_file)
    _assert_strict_environment()
    _run_verify_local_deps(env_file)

    import pytest

    plugin = NoSkipPlugin()
    return int(
        pytest.main(
            [
                "-q",
                "-ra",
                "-o",
                "addopts=",
                str(Path(__file__).resolve()),
            ],
            plugins=[plugin],
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
