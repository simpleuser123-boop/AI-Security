"""Run a real Redis -> Guardian -> Web consumer -> DB -> Socket.IO staging drill.

This script intentionally requires a reachable Redis. It does not run as part of
the default unit test suite; use it before staging/production cutover.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI-Security-Guardian staging drill")
    parser.add_argument("--redis-host", default=os.environ.get("REDIS_HOST", "127.0.0.1"))
    parser.add_argument("--redis-port", type=int, default=int(os.environ.get("REDIS_PORT", "6379")))
    parser.add_argument("--redis-db", type=int, default=int(os.environ.get("REDIS_DB", "0")))
    parser.add_argument("--redis-password", default=os.environ.get("REDIS_PASSWORD", ""))
    parser.add_argument("--stream", default=os.environ.get("GUARDIAN_ALERT_STREAM", ""))
    parser.add_argument("--group", default=os.environ.get("GUARDIAN_ALERT_STREAM_GROUP", "guardian:web"))
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL", ""))
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--cleanup", action="store_true", help="Delete the drill stream at the end.")
    return parser.parse_args()


def _prepare_env(args: argparse.Namespace) -> tuple[str, str, Path]:
    drill_id = uuid.uuid4().hex[:10]
    stream = args.stream or f"guardian:alerts:drill:{drill_id}"
    db_path = Path(tempfile.gettempdir()) / f"guardian-staging-drill-{drill_id}.db"
    database_url = args.database_url or f"sqlite:///{db_path.as_posix()}"

    os.environ.update(
        {
            "FLASK_ENV": os.environ.get("FLASK_ENV", "testing"),
            "SECRET_KEY": os.environ.get("SECRET_KEY", "staging-drill-secret-key-32-bytes-min"),
            "ADMIN_USERNAME": os.environ.get("ADMIN_USERNAME", "admin"),
            "ADMIN_PASSWORD": os.environ.get("ADMIN_PASSWORD", "changeme"),
            "DATABASE_URL": database_url,
            "REDIS_HOST": args.redis_host,
            "REDIS_PORT": str(args.redis_port),
            "REDIS_DB": str(args.redis_db),
            "REDIS_PASSWORD": args.redis_password,
            "GUARDIAN_REDIS_DISABLE_CONNECT": "false",
            "ALERT_STREAM_CONSUMER_AUTOSTART": "false",
            "AUDIT_INTEGRITY_PATROL": "false",
            "ENABLE_PACKET_CAPTURE": "false",
            "ENABLE_WEB_LOG": "false",
        }
    )
    if args.redis_password:
        os.environ["REDIS_PASSWORD"] = args.redis_password
    return stream, args.group, db_path


def _wait_until(label: str, timeout: float, fn):
    deadline = time.time() + timeout
    last: Optional[Any] = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(0.1)
    raise RuntimeError(f"timeout waiting for {label}; last={last!r}")


def _auth_headers(app) -> Dict[str, str]:
    """Create an API token inside the drill process without depending on admin secrets."""
    from flask_jwt_extended import create_access_token

    with app.app_context():
        token = create_access_token(identity="staging-drill")
    return {"Authorization": f"Bearer {token}"}


def main() -> int:
    args = _parse_args()
    stream, group, db_path = _prepare_env(args)

    from flask_socketio import SocketIOTestClient

    from main import RuntimeConfig, SecurityGuardian
    from src.detectors.base import DetectionResult
    from src.utils.redis_client import RedisClient
    from web.alert_stream_consumer import GuardianAlertStreamConsumer
    from web.app import create_app
    from web.database import db
    from web.models import Alert

    rc = RedisClient(
        host=args.redis_host,
        port=args.redis_port,
        db=args.redis_db,
        password=args.redis_password,
    )
    if not rc.is_available:
        raise RuntimeError(f"Redis is not available at {args.redis_host}:{args.redis_port} db={args.redis_db}")

    # Keep the drill isolated by default while still exercising SecurityGuardian._on_threat.
    SecurityGuardian._ALERT_STREAM = stream
    SecurityGuardian._ALERT_STREAM_GROUP = group
    rc.stream_ensure_group(stream, group)

    app, socketio = create_app()
    app.config["TESTING"] = True
    sio_client: SocketIOTestClient = socketio.test_client(app, flask_test_client=app.test_client())
    if not sio_client.is_connected():
        raise RuntimeError("Socket.IO test client did not connect")

    consumer = GuardianAlertStreamConsumer(
        app=app,
        redis_client=rc,
        socketio=socketio,
        stream_key=stream,
        group_name=group,
        consumer_name=f"staging-drill-{uuid.uuid4().hex[:8]}",
        idle_block_ms=200,
        autoclaim_idle_ms=1_000,
        autoclaim_interval_sec=0.5,
    )
    consumer.start()

    token = f"staging-drill-{uuid.uuid4().hex}"
    guardian = SecurityGuardian(
        RuntimeConfig(
            dry_run=True,
            enable_packet_capture=False,
            enable_web_log=False,
            enable_flask=False,
            redis_host=args.redis_host,
            redis_port=args.redis_port,
            redis_db=args.redis_db,
            redis_password=args.redis_password,
            require_redis_available=True,
        )
    )

    try:
        before_len = rc.stream_len(stream)
        guardian._on_threat(
            DetectionResult(
                threat_type="staging_drill",
                threat_level="high",
                confidence=0.97,
                details=token,
                source_ip="198.51.100.200",
                raw_data={"drill": True, "token": token},
            )
        )
        after_len = _wait_until("Guardian XADD", args.timeout, lambda: rc.stream_len(stream) > before_len)
        print(f"[OK] Guardian wrote Redis Stream: stream={stream} before={before_len} after={rc.stream_len(stream)}")

        def _find_alert():
            with app.app_context():
                return db.session.query(Alert).filter(Alert.summary == token).one_or_none()

        row = _wait_until("Web consumer DB persistence", args.timeout, _find_alert)
        print(f"[OK] Web consumer persisted alert: id={row.id} external_id={row.external_id}")
        _wait_until("Redis Stream ack", args.timeout, lambda: rc.stream_pending(stream, group) == 0)
        print(f"[OK] Web consumer acked message: XPENDING={rc.stream_pending(stream, group)}")

        received = sio_client.get_received()
        if not any(e.get("name") == "alert" and e.get("args") and e["args"][0].get("id") == row.id for e in received):
            raise RuntimeError(f"Socket.IO alert event not observed; received={received!r}")
        print("[OK] Socket.IO alert event observed")

        duplicate_fields = {
            "alert_id": row.id,
            "timestamp": row.timestamp.isoformat(),
            "type": row.threat_type,
            "level": row.level,
            "confidence": row.confidence,
            "source_ip": row.source_ip,
            "details": token,
        }
        rc.stream_add(stream, duplicate_fields)
        _wait_until("duplicate ack", args.timeout, lambda: rc.stream_pending(stream, group) == 0)
        with app.app_context():
            count = db.session.query(Alert).filter(Alert.id == row.id).count()
        if count != 1:
            raise RuntimeError(f"duplicate consumption created {count} rows for {row.id}")
        print("[OK] Duplicate stream message remained idempotent")
    finally:
        consumer.stop()

    # Simulate Web restart: new Flask app, same DB, history still queryable.
    app2, _socketio2 = create_app()
    client = app2.test_client()
    headers = _auth_headers(app2)
    resp = client.get("/api/alerts?limit=50", headers=headers)
    if resp.status_code != 200:
        raise RuntimeError(f"history query failed: status={resp.status_code} body={resp.get_data(as_text=True)}")
    items = resp.get_json()
    if not any(item.get("summary") == token for item in items):
        raise RuntimeError("alert was not queryable after Web restart")
    print("[OK] Web restart history query returned the alert")

    if rc.stream_pending(stream, group) != 0:
        raise RuntimeError(f"stream still has pending messages: {rc.stream_pending(stream, group)}")
    print(f"[OK] No persistent Redis Stream backlog: XLEN={rc.stream_len(stream)} XPENDING=0")

    if args.cleanup:
        try:
            import redis

            raw = redis.Redis(
                host=args.redis_host,
                port=args.redis_port,
                db=args.redis_db,
                password=args.redis_password or None,
                decode_responses=True,
            )
            raw.delete(stream)
            print(f"[OK] Cleaned up drill stream: {stream}")
        except Exception as exc:  # noqa: BLE001
            print(f"[WARN] Cleanup failed: {exc}")

    print(f"[INFO] Database URL: {os.environ['DATABASE_URL']}")
    if not args.database_url:
        print(f"[INFO] Temporary DB file: {db_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
