from __future__ import annotations

import uuid
from datetime import datetime, timezone


def _build_test_app(monkeypatch, tmp_path):
    db_file = tmp_path / "guardian_test.db"
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "changeme")

    from web.app import create_app

    app, _ = create_app()
    app.config["TESTING"] = True
    return app


def _auth_headers(client):
    resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "changeme"},
    )
    token = resp.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_all_r2_tables_can_be_created(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)

    from sqlalchemy import inspect
    from web.database import db

    expected_tables = {
        "alerts",
        "alert_histories",
        "rules",
        "iocs",
        "settings",
        "banned_ips",
        "response_actions",
        "response_schedule_tasks",
        "audit_events",
        "model_versions",
    }
    with app.app_context():
        inspector = inspect(db.engine)
        existing = set(inspector.get_table_names())
    assert expected_tables.issubset(existing)


def test_alert_insert_and_query(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)

    from web.database import db
    from web.models import Alert

    alert_id = uuid.uuid4().hex
    with app.app_context():
        alert = Alert(
            id=alert_id,
            external_id="redis-1",
            timestamp=datetime.now(timezone.utc),
            source_ip="1.2.3.4",
            target_ip="10.0.0.2",
            threat_type="sql_injection",
            level="high",
            confidence=0.97,
            engine="fusion-v1",
            status="open",
            summary="SQL 注入告警",
            raw_payload="{\"sample\": true}",
            model_version="v1.0.0",
        )
        db.session.add(alert)
        db.session.commit()

        queried = db.session.get(Alert, alert_id)
        assert queried is not None
        assert queried.threat_type == "sql_injection"
        assert queried.status == "open"


def test_alert_history_status_transition(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)

    from web.database import db
    from web.models import Alert, AlertHistory

    alert_id = uuid.uuid4().hex
    with app.app_context():
        db.session.add(
            Alert(
                id=alert_id,
                timestamp=datetime.now(timezone.utc),
                source_ip="8.8.8.8",
                threat_type="dos",
                level="medium",
                status="open",
            )
        )
        db.session.commit()

        db.session.add(
            AlertHistory(
                alert_id=alert_id,
                from_status="open",
                to_status="acknowledged",
                operator="tester",
                note="已确认告警",
            )
        )
        db.session.commit()

        rows = (
            db.session.query(AlertHistory)
            .filter(AlertHistory.alert_id == alert_id)
            .order_by(AlertHistory.id.asc())
            .all()
        )
        assert len(rows) == 1
        assert rows[0].from_status == "open"
        assert rows[0].to_status == "acknowledged"


def test_alert_api_reads_and_updates_db(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)

    from web.app import push_alert

    with app.app_context():
        inserted = push_alert(
            app,
            {
                "id": uuid.uuid4().hex,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": "9.9.9.9",
                "dest_ip": "10.0.0.9",
                "threat_type": "xss",
                "level": "medium",
                "status": "open",
                "summary": "XSS 告警",
            },
        )

    list_resp = client.get("/api/alerts", headers=headers)
    assert list_resp.status_code == 200
    data = list_resp.get_json()
    assert any(item["id"] == inserted["id"] for item in data)

    detail_resp = client.get(f"/api/alerts/{inserted['id']}", headers=headers)
    assert detail_resp.status_code == 200
    assert detail_resp.get_json()["threat_type"] == "xss"

    update_resp = client.post(
        f"/api/alerts/{inserted['id']}/status",
        headers=headers,
        json={"status": "acknowledged", "note": "手动确认"},
    )
    assert update_resp.status_code == 200
    body = update_resp.get_json()
    assert body["status"] == "acknowledged"
    assert body["history"][-1]["status"] == "acknowledged"


def test_settings_persist_and_reload(monkeypatch, tmp_path):
    db_file = tmp_path / "settings_roundtrip.db"
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "changeme")

    from web.app import create_app

    app1, _ = create_app()
    app1.config["TESTING"] = True
    c1 = app1.test_client()
    h1 = _auth_headers(c1)
    r1 = c1.put(
        "/api/settings",
        headers=h1,
        json={
            "detection_sensitivity": 0.55,
            "alert_threshold": 0.5,
            "model_version": "v2.1",
        },
    )
    assert r1.status_code == 200
    assert r1.get_json()["editable"]["model_version"] == "v2.1"

    app2, _ = create_app()
    app2.config["TESTING"] = True
    c2 = app2.test_client()
    h2 = _auth_headers(c2)
    r2 = c2.get("/api/settings", headers=h2)
    assert r2.status_code == 200
    assert r2.get_json()["editable"]["model_version"] == "v2.1"
    assert abs(r2.get_json()["editable"]["detection_sensitivity"] - 0.55) < 1e-6


def test_rules_crud_db(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)

    create = client.post(
        "/api/rules",
        headers=headers,
        json={
            "name": "rule-db-test",
            "type": "signature",
            "pattern": "/evil/",
            "action": "alert",
            "level": "high",
            "priority": 10,
            "enabled": True,
            "description": "db test",
        },
    )
    assert create.status_code == 201
    rid = create.get_json()["id"]

    lst = client.get("/api/rules", headers=headers)
    assert lst.status_code == 200
    assert any(r["id"] == rid for r in lst.get_json())

    detail = client.get(f"/api/rules/{rid}", headers=headers)
    assert detail.status_code == 200
    assert detail.get_json()["name"] == "rule-db-test"

    from web.database import db
    from web.models import Rule

    with app.app_context():
        row = db.session.get(Rule, rid)
        assert row is not None
        assert row.rule_type == "signature"


def test_report_summary_from_db(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)

    from web.app import push_alert

    with app.app_context():
        push_alert(
            app,
            {
                "id": "rep-alert-1",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": "1.1.1.1",
                "threat_type": "scan",
                "level": "high",
                "status": "open",
                "summary": "测试",
                "confidence": 0.85,
            },
        )

    summ = client.get("/api/reports/summary?period=day", headers=headers)
    assert summ.status_code == 200
    body = summ.get_json()
    assert body["overview"]["total_alerts"] >= 1
    assert any(x["level"] == "high" for x in body["threats"]["by_level"])
    assert "model_performance" in body

    exp = client.get("/api/reports/export?period=day&format=html", headers=headers)
    assert exp.status_code == 200
    assert b"guardian-report-export" in exp.data
