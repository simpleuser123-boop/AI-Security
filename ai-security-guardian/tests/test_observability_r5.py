"""R5 运维可观测：健康检查、Prometheus 指标、审计完整性巡检。"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import pytest


def _make_app(monkeypatch, tmp_path):
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("AUDIT_INTEGRITY_PATROL", "false")
    db_file = tmp_path / "r5.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "changeme")
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", "63999")

    from web.app import create_app

    app, _ = create_app()
    app.config["TESTING"] = True
    return app


def test_healthz_ok(monkeypatch, tmp_path):
    app = _make_app(monkeypatch, tmp_path)
    client = app.test_client()
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.get_json()
    assert body.get("status") == "live"


def test_readyz_ok_when_testing(monkeypatch, tmp_path):
    app = _make_app(monkeypatch, tmp_path)
    client = app.test_client()
    r = client.get("/readyz")
    assert r.status_code == 200
    data = r.get_json()
    assert data.get("status") in ("ready", "degraded")
    assert "checks" in data
    assert data["checks"]["database"]["ok"] is True


def test_readyz_unready_on_db_failure(monkeypatch, tmp_path):
    app = _make_app(monkeypatch, tmp_path)
    client = app.test_client()

    from web import observability_routes

    monkeypatch.setattr(
        observability_routes,
        "_checks_database",
        lambda: (False, "forced_failure"),
    )
    r = client.get("/readyz")
    assert r.status_code == 503
    assert r.get_json().get("status") == "unready"


def test_readyz_unready_on_model_missing(monkeypatch, tmp_path):
    app = _make_app(monkeypatch, tmp_path)
    client = app.test_client()

    from web import observability_routes

    monkeypatch.setattr(
        observability_routes,
        "_checks_models",
        lambda _app, _rds: (False, "no_guardian_metrics_and_empty_model_dir"),
    )
    r = client.get("/readyz")
    body = r.get_json()
    assert r.status_code == 503
    assert body["status"] == "unready"
    assert "models" in body["fatal"]
    assert body["checks"]["models"]["ok"] is False
    assert "empty_model_dir" in body["checks"]["models"]["detail"]


def test_readyz_redis_timeout_returns_fast(monkeypatch, tmp_path):
    monkeypatch.setenv("HEALTHCHECK_DEPENDENCY_TIMEOUT_SEC", "0.05")
    app = _make_app(monkeypatch, tmp_path)
    app.config["HEALTHCHECK_DEPENDENCY_TIMEOUT_SEC"] = 0.05

    from src.utils.redis_client import RedisClient

    rds = RedisClient(host="127.0.0.1", port=63999)
    rds._client = object()  # noqa: SLF001 - simulate a stuck redis-py client
    rds._mode = "redis"  # noqa: SLF001

    def _slow_ping():
        time.sleep(0.5)
        return False

    monkeypatch.setattr(rds, "ping", _slow_ping)
    app.extensions["guardian_redis_client"] = rds

    started = time.perf_counter()
    r = app.test_client().get("/readyz")
    elapsed = time.perf_counter() - started

    body = r.get_json()
    assert elapsed < 0.3
    assert r.status_code == 200
    assert body["status"] == "degraded"
    assert body["checks"]["redis"]["ok"] is False
    assert body["checks"]["redis"]["timed_out"] is True


def test_api_health_redis_timeout_returns_fast(monkeypatch, tmp_path):
    monkeypatch.setenv("HEALTHCHECK_DEPENDENCY_TIMEOUT_SEC", "0.05")
    app = _make_app(monkeypatch, tmp_path)
    app.config["HEALTHCHECK_DEPENDENCY_TIMEOUT_SEC"] = 0.05

    from src.utils.redis_client import RedisClient

    rds = RedisClient(host="127.0.0.1", port=63999)
    rds._client = object()  # noqa: SLF001 - simulate auth/network stall after startup
    rds._mode = "redis"  # noqa: SLF001

    def _slow_ping():
        time.sleep(0.5)
        return False

    monkeypatch.setattr(rds, "ping", _slow_ping)
    app.extensions["guardian_redis_client"] = rds

    started = time.perf_counter()
    r = app.test_client().get("/api/health")
    elapsed = time.perf_counter() - started

    body = r.get_json()
    assert elapsed < 0.3
    assert r.status_code == 200
    assert body["status"] == "degraded"
    assert body["frontend_safe"] is True
    assert body["checks"]["redis"]["timed_out"] is True


def test_readyz_redis_auth_failure_content(monkeypatch, tmp_path):
    app = _make_app(monkeypatch, tmp_path)

    from src.utils.redis_client import RedisClient

    rds = RedisClient(host="127.0.0.1", port=63999)
    rds._client = object()  # noqa: SLF001
    rds._mode = "redis"  # noqa: SLF001

    def _auth_failure():
        raise RuntimeError("invalid password")

    monkeypatch.setattr(rds, "ping", _auth_failure)
    app.extensions["guardian_redis_client"] = rds

    r = app.test_client().get("/readyz")
    body = r.get_json()
    assert r.status_code == 200
    assert body["status"] == "degraded"
    assert "redis" in body["degraded"]
    assert body["checks"]["redis"]["ok"] is False
    assert "RuntimeError" in body["checks"]["redis"]["detail"]


def test_alert_consumer_exception_does_not_pollute_readyz(monkeypatch, tmp_path):
    app = _make_app(monkeypatch, tmp_path)

    from flask_socketio import SocketIO

    from src.utils.redis_client import RedisClient
    from web.alert_stream_consumer import GuardianAlertStreamConsumer

    class HealthyRedis:
        def ping(self):
            return True

    class BrokenConsumerRedis:
        def xgroup_create(self, **_kwargs):
            raise RuntimeError("consumer stream socket failed")

    shared_rds = RedisClient(host="127.0.0.1", port=63999)
    shared_rds._client = HealthyRedis()  # noqa: SLF001
    shared_rds._mode = "redis"  # noqa: SLF001

    consumer_rds = RedisClient(host="127.0.0.1", port=63999)
    consumer_rds._client = BrokenConsumerRedis()  # noqa: SLF001
    consumer_rds._mode = "redis"  # noqa: SLF001

    monkeypatch.setattr(shared_rds, "fork_for_stream_consumer", lambda: consumer_rds)
    app.extensions["guardian_redis_client"] = shared_rds

    consumer = GuardianAlertStreamConsumer(
        app=app,
        redis_client=shared_rds,
        socketio=SocketIO(app, async_mode="threading"),
        stream_key="guardian:alerts",
        group_name="guardian:web",
        consumer_name="pytest-isolated-consumer",
        normalizer=lambda fields: dict(fields),
        upsert_alert=lambda payload: dict(payload),
        alert_to_api_dict=lambda row: dict(row),
    )

    assert consumer._redis is consumer_rds  # noqa: SLF001
    consumer._redis.stream_ensure_group("guardian:alerts", "guardian:web")  # noqa: SLF001

    r = app.test_client().get("/readyz")
    body = r.get_json()
    assert consumer_rds.mode == "memory"
    assert shared_rds.mode == "redis"
    assert r.status_code == 200
    assert body["checks"]["redis"]["ok"] is True
    assert "redis" not in body.get("degraded", [])


def test_metrics_contains_key_series(monkeypatch, tmp_path):
    app = _make_app(monkeypatch, tmp_path)
    client = app.test_client()
    r = client.get("/metrics")
    assert r.status_code == 200
    text = r.data.decode("utf-8")
    for name in (
        "guardian_packets_total",
        "guardian_packets_dropped_total",
        "guardian_detection_latency_ms_sum",
        "guardian_detection_latency_ms_count",
        "guardian_detection_latency_ms",
        "guardian_alerts_total",
        "guardian_model_ready",
        "guardian_model_expected",
        "guardian_model_loaded",
        "guardian_model_missing",
        "guardian_model_state",
        "guardian_model_status_updated_timestamp_seconds",
        "guardian_metrics_snapshot_updated_timestamp_seconds",
        "guardian_redis_stream_writes_total",
        "redis_stream_pending",
        "redis_stream_group_lag",
        "guardian_alert_stream_consumed_total",
        "guardian_alert_consume_latency_ms_count",
        "audit_integrity_valid",
        "audit_integrity_patrol_runs_total",
        "guardian_response_actions_total",
        "guardian_http_requests_total",
        "guardian_http_request_duration_seconds_bucket",
    ):
        assert name in text


def test_guardian_metrics_model_ready_is_binary():
    from src.observability.guardian_metrics import GuardianMetricsCollector

    c = GuardianMetricsCollector()
    c.set_model_load_state(expected=4, loaded=4)
    snap = c.snapshot()
    assert snap["model_ready"] == 1
    assert snap["model_expected_count"] == 4
    assert snap["model_loaded_count"] == 4
    assert snap["model_missing_count"] == 0
    assert snap["model_status_updated_ts"] > 0

    c.set_model_load_state(expected=4, loaded=2)
    snap = c.snapshot()
    assert snap["model_ready"] == 0
    assert snap["model_loaded_count"] == 2
    assert snap["model_missing_count"] == 2

    c.set_model_load_state(expected=4, loaded=0)
    snap = c.snapshot()
    assert snap["model_ready"] == 0
    assert snap["model_loaded_count"] == 0
    assert snap["model_missing_count"] == 4


@pytest.mark.parametrize(
    ("loaded", "ready", "active_state"),
    [(4, 1, "ready"), (2, 0, "partial"), (0, 0, "missing")],
)
def test_metrics_model_state_series(monkeypatch, tmp_path, loaded, ready, active_state):
    app = _make_app(monkeypatch, tmp_path)

    from web import observability_routes

    def _snapshot(_rds):
        return {
            "model_ready": float(ready),
            "model_expected_count": 4.0,
            "model_loaded_count": float(loaded),
            "model_missing_count": float(4 - loaded),
            "model_status_updated_ts": 123.0,
            "updated_ts": 124.0,
        }

    monkeypatch.setattr(observability_routes, "read_guardian_redis_snapshot", _snapshot)

    r = app.test_client().get("/metrics")
    assert r.status_code == 200
    text = r.data.decode("utf-8")
    assert f"guardian_model_ready {ready}" in text
    assert "guardian_model_expected 4" in text
    assert f"guardian_model_loaded {loaded}" in text
    assert f"guardian_model_missing {4 - loaded}" in text
    assert f'guardian_model_state{{state="{active_state}"}} 1' in text
    assert "guardian_model_status_updated_timestamp_seconds 123.0" in text
    assert "guardian_metrics_snapshot_updated_timestamp_seconds 124.0" in text


def test_audit_integrity_failure_creates_critical_trace(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("AUDIT_INTEGRITY_PATROL", "false")
    db_file = tmp_path / "r5_audit.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "changeme")

    logd = tmp_path / "logs"
    logd.mkdir(parents=True, exist_ok=True)

    from web.app import create_app

    app, _ = create_app()
    app.config["TESTING"] = True
    app.config["GUARDIAN_LOG_DIR"] = str(logd)
    app.config["LOG_INTEGRITY_ENABLED"] = True

    from src.audit.security_logger import SecurityLogger

    sec_logger = logging.getLogger("security")
    sec_logger.handlers.clear()

    sl = SecurityLogger(log_dir=str(logd), enable_integrity=True)
    sl.log_system("seed-a", "info")
    sl.log_system("seed-b", "info")

    sec_path = logd / "security.log"
    raw = sec_path.read_text(encoding="utf-8").strip().split("\n")
    first = json.loads(raw[0])
    first["event_type"] = "tampered"
    raw[0] = json.dumps(first, ensure_ascii=False)
    sec_path.write_text("\n".join(raw) + "\n", encoding="utf-8")

    from web.audit_integrity_patrol import (
        get_last_audit_integrity_valid,
        run_audit_integrity_patrol_once,
    )
    from web.database import db
    from web.models import Alert

    with app.app_context():
        before = db.session.query(Alert).count()
        run_audit_integrity_patrol_once(app)
        after = db.session.query(Alert).count()

    assert get_last_audit_integrity_valid() is False
    assert after >= before

    tail = sec_path.read_text(encoding="utf-8")
    assert "audit_integrity" in tail
    assert "critical" in tail

    with app.app_context():
        row = (
            db.session.query(Alert)
            .filter(Alert.threat_type == "audit_integrity")
            .order_by(Alert.created_at.desc())
            .first()
        )
        assert row is not None
        assert row.level == "critical"


def test_verify_integrity_missing_file_is_valid(monkeypatch, tmp_path):
    from src.audit.security_logger import SecurityLogger

    empty_dir = tmp_path / "empty_logs"
    empty_dir.mkdir()
    sl = SecurityLogger(log_dir=str(empty_dir), enable_integrity=True)
    r = sl.verify_integrity()
    assert r["valid"] is True


def test_security_logger_uses_environment_specific_log_dir(monkeypatch, tmp_path):
    from src.audit.security_logger import SecurityLogger

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FLASK_ENV", "testing")
    sl = SecurityLogger(log_dir=None, enable_integrity=True)
    assert Path(sl.log_dir).name == "test"
    assert sl.log_file.endswith("security.log")


def test_archive_security_log_rebuilds_clean_baseline(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("AUDIT_ENV", "test")
    from src.audit.security_logger import SecurityLogger
    from scripts.archive_security_audit_log import archive_security_log

    log_dir = tmp_path / "logs" / "test"
    sl = SecurityLogger(log_dir=str(log_dir), enable_integrity=True)
    sl.log_system("before-archive", level="info")
    before = sl.verify_integrity()
    assert before["valid"] is True

    result = archive_security_log(str(log_dir), reason="rotation")
    assert result["archived_log"]
    assert result["pre_archive_integrity"]["valid"] is True
    archive_file = Path(result["archived_log"])
    assert archive_file.exists()

    sec_path = log_dir / "security.log"
    assert sec_path.exists()
    after = SecurityLogger(log_dir=str(log_dir), enable_integrity=True).verify_integrity(
        str(sec_path)
    )
    assert after["valid"] is True
    body = sec_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(body) == 1
    event = json.loads(body[0])
    assert event["event_type"] == "system"
    assert event["integrity"]["prev_hash"] == "genesis"
