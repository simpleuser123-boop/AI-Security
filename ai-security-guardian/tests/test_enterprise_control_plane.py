from __future__ import annotations

import uuid
from datetime import datetime, timezone


def _build_test_app(monkeypatch, tmp_path, *, role: str = "admin"):
    db_file = tmp_path / f"guardian_{role}_{uuid.uuid4().hex}.db"
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "changeme")
    monkeypatch.setenv("ADMIN_ROLE", role)

    from web.app import create_app

    app, _ = create_app()
    app.config["TESTING"] = True
    return app


def _auth_headers(client):
    resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "changeme"},
    )
    assert resp.status_code == 200
    token = resp.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}, resp.get_json()


def test_rbac_role_claim_and_audit_query(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    client = app.test_client()
    headers, login_body = _auth_headers(client)

    assert login_body["role"] == "admin"
    me = client.get("/api/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.get_json()["role"] == "admin"

    events = client.get("/api/audit/events?event_type=auth.login_success", headers=headers)
    assert events.status_code == 200
    body = events.get_json()
    assert body["total"] >= 1
    assert body["items"][0]["actor"] == "admin"


def test_alert_status_update_writes_queryable_audit_event(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    client = app.test_client()
    headers, _ = _auth_headers(client)

    from web.app import push_alert

    alert_id = uuid.uuid4().hex
    with app.app_context():
        push_alert(
            app,
            {
                "id": alert_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": "2.2.2.2",
                "threat_type": "scan",
                "level": "medium",
                "status": "open",
                "summary": "端口扫描",
            },
        )

    resp = client.post(
        f"/api/alerts/{alert_id}/status",
        headers=headers,
        json={"status": "acknowledged", "note": "人工确认"},
    )
    assert resp.status_code == 200

    audit = client.get(
        f"/api/audit/events?resource_type=alert&resource_id={alert_id}",
        headers=headers,
    )
    assert audit.status_code == 200
    items = audit.get_json()["items"]
    assert any(item["event_type"] == "alert.status_updated" for item in items)


def test_analyst_can_triage_but_cannot_admin_mutate(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="analyst")
    client = app.test_client()
    headers, login_body = _auth_headers(client)
    assert login_body["role"] == "analyst"

    from web.app import push_alert

    alert_id = uuid.uuid4().hex
    with app.app_context():
        push_alert(
            app,
            {
                "id": alert_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": "3.3.3.3",
                "threat_type": "xss",
                "level": "low",
                "status": "open",
            },
        )

    triage = client.post(
        f"/api/alerts/{alert_id}/status",
        headers=headers,
        json={"status": "ignored", "note": "误报"},
    )
    assert triage.status_code == 200

    settings = client.put(
        "/api/settings",
        headers=headers,
        json={"alert_threshold": 0.7},
    )
    assert settings.status_code == 403

    audit = client.get("/api/audit/events", headers=headers)
    assert audit.status_code == 403
