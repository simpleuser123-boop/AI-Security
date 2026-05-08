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


def test_blocking_empty_stream_timeout_does_not_degrade_shared_client(monkeypatch):
    """An empty Stream BLOCK timeout is a normal poll result, not Redis outage."""
    monkeypatch.setenv("GUARDIAN_REDIS_DISABLE_CONNECT", "true")
    rc = RedisClient()

    class TimeoutOnlyRedis:
        def xreadgroup(self, **_kwargs):
            raise TimeoutError("Timeout reading from socket")

    rc._client = TimeoutOnlyRedis()
    rc._mode = "redis"

    batch = rc.stream_read_group(
        "guardian:alerts",
        "guardian:web",
        "pytest-timeout",
        count=1,
        block_ms=1500,
    )

    assert batch == []
    assert rc.mode == "redis"
    assert rc.is_available


def test_empty_stream_read_returns_empty_without_degrade(monkeypatch):
    """Redis returning no stream entries is a normal empty poll."""
    monkeypatch.setenv("GUARDIAN_REDIS_DISABLE_CONNECT", "true")
    rc = RedisClient()

    class EmptyStreamRedis:
        def xreadgroup(self, **_kwargs):
            return []

    rc._client = EmptyStreamRedis()
    rc._mode = "redis"

    batch = rc.stream_read_group(
        "guardian:alerts",
        "guardian:web",
        "pytest-empty",
        count=1,
        block_ms=100,
    )

    assert batch == []
    assert rc.mode == "redis"
    assert rc.is_available


def test_pending_replay_uses_non_blocking_xreadgroup(monkeypatch):
    monkeypatch.setenv("GUARDIAN_REDIS_DISABLE_CONNECT", "true")
    rc = RedisClient()
    calls = []

    class EmptyRedis:
        def xreadgroup(self, **kwargs):
            calls.append(kwargs)
            return []

    rc._client = EmptyRedis()
    rc._mode = "redis"

    assert rc.stream_read_own_pending(
        "guardian:alerts",
        "guardian:web",
        "pytest-pending",
        count=1,
    ) == []
    assert calls
    assert calls[0]["block"] is None
    assert rc.mode == "redis"
