from __future__ import annotations

from flask import Flask
from flask_socketio import SocketIO

from src.utils.redis_client import RedisClient
from web.alert_stream_consumer import GuardianAlertStreamConsumer


def test_consumer_replays_own_pending_until_persisted(monkeypatch):
    """Default smoke: failed persistence must not ack; next pass replays and acks."""
    monkeypatch.setenv("GUARDIAN_REDIS_DISABLE_CONNECT", "true")
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret"
    socketio = SocketIO(app, async_mode="threading")
    rc = RedisClient()

    stream = "guardian:alerts:smoke"
    group = "guardian:web-smoke"
    consumer_name = "smoke-consumer"
    rc.stream_ensure_group(stream, group)
    msg_id = rc.stream_add(
        stream,
        {
            "alert_id": "smoke-alert-1",
            "timestamp": "2026-05-05T08:00:00+00:00",
            "type": "web_attack",
            "level": "high",
            "confidence": 0.88,
            "source_ip": "198.51.100.42",
            "details": "smoke retry",
        },
    )
    assert msg_id is not None

    attempts = {"count": 0}

    def flaky_upsert(payload):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RuntimeError("transient database outage")
        return dict(payload)

    consumer = GuardianAlertStreamConsumer(
        app=app,
        redis_client=rc,
        socketio=socketio,
        stream_key=stream,
        group_name=group,
        consumer_name=consumer_name,
        normalizer=lambda fields: dict(fields),
        upsert_alert=flaky_upsert,
        alert_to_api_dict=lambda row: dict(row),
    )

    first = rc.stream_read_group(stream, group, consumer_name, count=1)
    assert len(first) == 1
    consumer._process_one(first[0][0], first[0][1])
    assert rc.stream_pending(stream, group) == 1

    pending = rc.stream_read_own_pending(stream, group, consumer_name, count=1)
    assert len(pending) == 1
    consumer._process_one(pending[0][0], pending[0][1])
    assert attempts["count"] == 2
    assert rc.stream_pending(stream, group) == 0
