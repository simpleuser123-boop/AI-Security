"""Verify local PostgreSQL and Redis are real, reachable services."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_FILE = ROOT / ".env.host-nondegraded.example"


def _load_env(path: Path) -> None:
    if not path.exists():
        raise RuntimeError(f"env file not found: {path}")
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ[key.strip()] = value.strip().strip("'\"")


def _verify_postgres(database_url: str) -> None:
    url = make_url(database_url)
    if url.get_backend_name() != "postgresql":
        raise RuntimeError(f"DATABASE_URL is not PostgreSQL: {url.get_backend_name()}")
    if (url.host or "").lower() != "127.0.0.1":
        raise RuntimeError(
            "wrong env for host dependency verification: DATABASE_URL must use "
            "127.0.0.1. Use .env.host-nondegraded.example for host tests; "
            "do not use Compose service names here."
        )
    local_port = os.environ.get("LOCAL_POSTGRES_PORT")
    if local_port and int(local_port) != int(url.port or 0):
        raise RuntimeError(
            "DATABASE_URL port must match LOCAL_POSTGRES_PORT: "
            f"{url.port!r} != {local_port}"
        )
    engine = create_engine(database_url, pool_pre_ping=True)
    with engine.connect() as conn:
        db_name = conn.execute(text("select current_database()")).scalar_one()
        version = conn.execute(text("select version()")).scalar_one()
    print(f"PostgreSQL connected: database={db_name}")
    print(f"PostgreSQL version: {version.split(',', 1)[0]}")


def _verify_redis_auth_ping() -> None:
    import redis

    if os.environ.get("REDIS_HOST", "").lower() != "127.0.0.1":
        raise RuntimeError(
            "wrong env for host dependency verification: REDIS_HOST must be "
            "127.0.0.1. Use .env.host-nondegraded.example for host tests; "
            "do not use the Compose redis service name here."
        )
    if os.environ.get("LOCAL_REDIS_PORT") and (
        int(os.environ["LOCAL_REDIS_PORT"]) != int(os.environ["REDIS_PORT"])
    ):
        raise RuntimeError(
            "REDIS_PORT must match LOCAL_REDIS_PORT: "
            f"{os.environ['REDIS_PORT']} != {os.environ['LOCAL_REDIS_PORT']}"
        )
    client = redis.Redis(
        host=os.environ["REDIS_HOST"],
        port=int(os.environ["REDIS_PORT"]),
        db=int(os.environ.get("REDIS_DB", "0")),
        password=os.environ["REDIS_PASSWORD"],
        socket_connect_timeout=2,
        socket_timeout=2,
        decode_responses=True,
    )
    pong = client.ping()
    if pong is not True:
        raise RuntimeError(f"Redis AUTH PING did not return PONG: {pong!r}")
    print("Redis AUTH PING: PONG")


def _verify_app_config(database_url: str) -> None:
    sys.path.insert(0, str(ROOT))
    from config.config import get_config

    cfg = get_config()
    configured_url = cfg.SQLALCHEMY_DATABASE_URI
    backend = make_url(configured_url).get_backend_name()
    if configured_url != database_url or backend != "postgresql":
        raise RuntimeError(
            "application config DATABASE_URL is not the local PostgreSQL URL: "
            f"backend={backend!r} value={configured_url!r}"
        )
    print(f"Application DATABASE_URL backend: {backend}")


def _verify_redis_client_mode() -> None:
    sys.path.insert(0, str(ROOT))
    from src.utils.redis_client import RedisClient

    client = RedisClient(
        host=os.environ["REDIS_HOST"],
        port=int(os.environ["REDIS_PORT"]),
        db=int(os.environ.get("REDIS_DB", "0")),
        password=os.environ["REDIS_PASSWORD"],
    )
    if client.mode == "memory" or not client.is_available:
        raise RuntimeError(f"RedisClient is degraded: mode={client.mode!r}")
    print(f"RedisClient mode: {client.mode}")


def main() -> int:
    env_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_ENV_FILE
    _load_env(env_path)

    database_url = os.environ.get("DATABASE_URL", "")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    if not os.environ.get("REDIS_PASSWORD"):
        raise RuntimeError("REDIS_PASSWORD is required")
    if os.environ.get("GUARDIAN_REDIS_DISABLE_CONNECT", "").lower() == "true":
        raise RuntimeError("GUARDIAN_REDIS_DISABLE_CONNECT must not be true")
    if os.environ.get("REQUIRE_REDIS_AVAILABLE", "").lower() != "true":
        raise RuntimeError("REQUIRE_REDIS_AVAILABLE must be true")

    _verify_postgres(database_url)
    _verify_redis_auth_ping()
    _verify_app_config(database_url)
    _verify_redis_client_mode()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
