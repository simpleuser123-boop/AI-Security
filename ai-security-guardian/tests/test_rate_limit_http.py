from __future__ import annotations

import pytest

from tests.auth_helpers import configure_test_admin


def test_protected_api_returns_429_under_low_rate_limit(monkeypatch, tmp_path):
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("AUDIT_INTEGRITY_PATROL", "false")
    monkeypatch.setenv("ALERT_STREAM_CONSUMER_AUTOSTART", "false")
    monkeypatch.setenv("REQUIRE_REDIS_AVAILABLE", "false")
    monkeypatch.setenv("REQUIRE_MODELS_READY", "false")
    monkeypatch.setenv("API_RATE_LIMIT", "2 per minute")
    db_file = tmp_path / "rate-limit.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    configure_test_admin(monkeypatch)

    from config.config import TestingConfig
    from flask_jwt_extended import create_access_token
    from web.app import create_app

    monkeypatch.setattr(TestingConfig, "API_RATE_LIMIT", "2 per minute")
    monkeypatch.setattr(TestingConfig, "REQUIRE_REDIS_AVAILABLE", False)
    monkeypatch.setattr(TestingConfig, "REQUIRE_MODELS_READY", False)

    app, _ = create_app()
    app.config["TESTING"] = True
    with app.app_context():
        token = create_access_token(identity="admin", additional_claims={"role": "admin"})

    client = app.test_client()
    statuses = [
        client.get("/api/stats", headers={"Authorization": f"Bearer {token}"}).status_code
        for _ in range(3)
    ]

    assert statuses[:2] == [200, 200]
    assert statuses[2] == 429


def test_benchmark_http_rejects_429_as_ok_status():
    from scripts.benchmark_http import _parse_ok_statuses

    with pytest.raises(ValueError, match="429"):
        _parse_ok_statuses("200,429")
