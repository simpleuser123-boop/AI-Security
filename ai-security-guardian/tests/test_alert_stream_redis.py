"""Redis Stream ``guardian:alerts`` 消费链路与 Socket.IO 集成测试（需本机 Redis）。"""
from __future__ import annotations

import os
import time
import uuid
from pathlib import Path

import pytest

from tests.auth_helpers import auth_headers, configure_test_admin


def _redis_ping() -> bool:
    try:
        import redis

        r = redis.Redis(
            host=os.environ.get("REDIS_HOST", "localhost"),
            port=int(os.environ.get("REDIS_PORT", "6379")),
            db=int(os.environ.get("REDIS_TEST_DB", "15")),
            password=os.environ.get("REDIS_PASSWORD") or None,
            socket_connect_timeout=1.5,
            decode_responses=True,
        )
        return bool(r.ping())
    except Exception:
        return False


pytestmark = pytest.mark.integration


@pytest.fixture()
def stream_env(monkeypatch, tmp_path: Path) -> dict:
    """独立 stream + 文件库，避免污染默认 ``guardian:alerts``。"""
    if not _redis_ping():
        pytest.skip("Redis 不可用（跳过 Stream 集成测试）")
    suffix = uuid.uuid4().hex[:10]
    stream = f"guardian:alerts:test:{suffix}"
    group = f"guardian:web-test:{suffix}"
    db_file = tmp_path / "stream_test.db"
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b-long")
    configure_test_admin(monkeypatch)
    monkeypatch.setenv("GUARDIAN_REDIS_DISABLE_CONNECT", "false")
    monkeypatch.setenv("ALERT_STREAM_CONSUMER_AUTOSTART", "false")
    monkeypatch.setenv("GUARDIAN_ALERT_STREAM", stream)
    monkeypatch.setenv("GUARDIAN_ALERT_STREAM_GROUP", group)
    return {"stream": stream, "group": group, "db_file": db_file}


def _redis_client_for_tests():
    from src.utils.redis_client import RedisClient

    return RedisClient(
        host=os.environ.get("REDIS_HOST", "localhost"),
        port=int(os.environ.get("REDIS_PORT", "6379")),
        db=int(os.environ.get("REDIS_TEST_DB", "15")),
        password=os.environ.get("REDIS_PASSWORD") or "",
    )


def test_stream_consumer_persists_and_acks(stream_env, monkeypatch):
    from web.alert_stream_consumer import GuardianAlertStreamConsumer
    from web.app import create_app
    from web.database import db
    from web.models import Alert

    app, socketio = create_app()
    app.config["TESTING"] = True

    rc = _redis_client_for_tests()
    if not rc.is_available:
        pytest.skip("RedisClient 未连上 Redis")

    stream = stream_env["stream"]
    group = stream_env["group"]
    alert_id = str(uuid.uuid4())
    rc.stream_ensure_group(stream, group)
    rc.stream_add(
        stream,
        {
            "alert_id": alert_id,
            "timestamp": "2026-01-01T12:00:00+00:00",
            "type": "dos",
            "level": "high",
            "confidence": 0.91,
            "source_ip": "198.51.100.10",
            "details": "integration stream",
        },
    )

    consumer = GuardianAlertStreamConsumer(
        app=app,
        redis_client=rc,
        socketio=socketio,
        stream_key=stream,
        group_name=group,
        consumer_name="pytest-consumer",
        idle_block_ms=200,
    )
    consumer.start()
    try:
        deadline = time.time() + 15.0
        row = None
        while time.time() < deadline:
            with app.app_context():
                row = db.session.get(Alert, alert_id)
            if row is not None:
                break
            time.sleep(0.05)
        assert row is not None
        assert row.threat_type == "dos"
        assert row.external_id == alert_id
        assert int(rc.stream_pending(stream, group)) == 0
    finally:
        consumer.stop()


def test_stream_duplicate_messages_idempotent(stream_env):
    from web.alert_stream_consumer import GuardianAlertStreamConsumer
    from web.app import create_app
    from web.database import db
    from web.models import Alert

    app, socketio = create_app()
    rc = _redis_client_for_tests()
    if not rc.is_available:
        pytest.skip("RedisClient 未连上 Redis")

    stream = stream_env["stream"]
    group = stream_env["group"]
    alert_id = str(uuid.uuid4())
    rc.stream_ensure_group(stream, group)
    fields = {
        "alert_id": alert_id,
        "timestamp": "2026-01-02T08:00:00+00:00",
        "type": "xss",
        "level": "medium",
        "confidence": 0.7,
        "source_ip": "203.0.113.5",
        "details": "dup test",
    }
    rc.stream_add(stream, dict(fields))
    rc.stream_add(stream, dict(fields))

    consumer = GuardianAlertStreamConsumer(
        app=app,
        redis_client=rc,
        socketio=socketio,
        stream_key=stream,
        group_name=group,
        consumer_name="pytest-dup",
        idle_block_ms=200,
    )
    consumer.start()
    try:
        time.sleep(2.5)
        with app.app_context():
            cnt = db.session.query(Alert).filter(Alert.id == alert_id).count()
        assert cnt == 1
        assert int(rc.stream_pending(stream, group)) == 0
    finally:
        consumer.stop()


def test_api_survives_app_recreate_same_database(stream_env):
    """模拟 Web 重启：新进程/新 app 实例 + 同一 SQLite 文件仍能查历史。"""
    from web.alert_stream_consumer import GuardianAlertStreamConsumer
    from web.app import create_app
    from web.database import db
    from web.models import Alert

    alert_id = str(uuid.uuid4())

    def _make_pair():
        a, sio = create_app()
        a.config["TESTING"] = True
        return a, sio

    app1, socketio1 = _make_pair()
    rc = _redis_client_for_tests()
    if not rc.is_available:
        pytest.skip("RedisClient 未连上 Redis")

    stream = stream_env["stream"]
    group = stream_env["group"]
    rc.stream_ensure_group(stream, group)
    rc.stream_add(
        stream,
        {
            "alert_id": alert_id,
            "timestamp": "2026-03-01T10:00:00+00:00",
            "type": "port_scan",
            "level": "low",
            "confidence": 0.5,
            "source_ip": "192.0.2.1",
            "details": "restart test",
        },
    )
    c1 = GuardianAlertStreamConsumer(
        app=app1,
        redis_client=rc,
        socketio=socketio1,
        stream_key=stream,
        group_name=group,
        consumer_name="pytest-restart",
        idle_block_ms=200,
    )
    c1.start()
    try:
        deadline = time.time() + 15.0
        while time.time() < deadline:
            with app1.app_context():
                if db.session.get(Alert, alert_id):
                    break
            time.sleep(0.05)
        with app1.app_context():
            assert db.session.get(Alert, alert_id) is not None
    finally:
        c1.stop()

    # 新 Flask 应用实例，复用同一 DATABASE_URL
    app2, _ = _make_pair()
    client = app2.test_client()
    headers, _ = auth_headers(client)
    resp = client.get("/api/alerts", headers=headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert any(item["id"] == alert_id for item in data)


def test_socketio_receives_alert_after_stream_ingest(stream_env):
    from flask_socketio import SocketIOTestClient
    from web.alert_stream_consumer import GuardianAlertStreamConsumer
    from web.app import create_app
    from web.database import db
    from web.models import Alert

    app, socketio = create_app()
    app.config["TESTING"] = True
    sio_client: SocketIOTestClient = socketio.test_client(app, flask_test_client=app.test_client())
    assert sio_client.is_connected()
    rc = _redis_client_for_tests()
    if not rc.is_available:
        pytest.skip("RedisClient 未连上 Redis")

    stream = stream_env["stream"]
    group = stream_env["group"]
    alert_id = str(uuid.uuid4())
    rc.stream_ensure_group(stream, group)
    rc.stream_add(
        stream,
        {
            "alert_id": alert_id,
            "timestamp": "2026-04-01T15:30:00+00:00",
            "type": "malware_c2",
            "level": "critical",
            "confidence": 0.99,
            "source_ip": "198.51.100.77",
            "details": "socket test",
        },
    )

    consumer = GuardianAlertStreamConsumer(
        app=app,
        redis_client=rc,
        socketio=socketio,
        stream_key=stream,
        group_name=group,
        consumer_name="pytest-sio",
        idle_block_ms=200,
    )
    consumer.start()
    try:
        deadline = time.time() + 15.0
        while time.time() < deadline:
            with app.app_context():
                if db.session.get(Alert, alert_id):
                    break
            time.sleep(0.05)
        time.sleep(0.3)
        received = sio_client.get_received()
        names = [entry.get("name") for entry in received]
        assert "alert" in names
        payloads = [
            e["args"][0] for e in received if e.get("name") == "alert" and e.get("args")
        ]
        assert any(p.get("id") == alert_id for p in payloads)
    finally:
        consumer.stop()
