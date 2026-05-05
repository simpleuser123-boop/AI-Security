"""R5 运维可观测：健康检查、Prometheus 指标、审计完整性巡检。"""
from __future__ import annotations

import json
import logging
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
        "redis_stream_pending",
        "audit_integrity_valid",
    ):
        assert name in text


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
