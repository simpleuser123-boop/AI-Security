from __future__ import annotations

import json
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.auth_helpers import auth_headers, configure_test_admin


def _build_test_app(monkeypatch, tmp_path, *, role: str = "admin"):
    db_file = tmp_path / f"guardian_{role}_{uuid.uuid4().hex}.db"
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("REQUIRE_REDIS_AVAILABLE", "false")
    monkeypatch.setenv("REQUIRE_MODELS_READY", "false")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    configure_test_admin(monkeypatch, role=role)
    monkeypatch.setenv(
        "AUDIT_LOG_DIR",
        str(tmp_path / f"audit_{role}_{uuid.uuid4().hex}"),
    )

    from web.app import create_app
    from config.config import TestingConfig

    monkeypatch.setattr(TestingConfig, "REQUIRE_REDIS_AVAILABLE", False)
    monkeypatch.setattr(TestingConfig, "REQUIRE_MODELS_READY", False)

    app, _ = create_app()
    app.config["TESTING"] = True
    return app


def _auth_headers(client, *, tenant_id: str = "tenant_default"):
    if tenant_id == "tenant_default":
        resp = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "changeme"},
        )
        assert resp.status_code == 200
        token = resp.get_json()["access_token"]
        return {"Authorization": f"Bearer {token}"}, resp.get_json()

    from flask_jwt_extended import create_access_token

    with client.application.app_context():
        token = create_access_token(
            identity="admin",
            additional_claims={"role": "admin", "tenant_id": tenant_id},
        )
    return {"Authorization": f"Bearer {token}"}, {
        "username": "admin",
        "role": "admin",
        "tenant_id": tenant_id,
    }


def _seed_tenant_boundary_rows(app):
    from web.database import db
    from web.models import Alert, AuditEvent, BannedIp, IOC, Membership, Organization, Role, Rule, Tenant, User

    now = datetime.now(timezone.utc)
    with app.app_context():
        for tenant_id, slug in (("tenant_a", "tenant-a"), ("tenant_b", "tenant-b")):
            if db.session.get(Tenant, tenant_id) is None:
                db.session.add(
                    Tenant(
                        id=tenant_id,
                        name=tenant_id,
                        slug=slug,
                        status="active",
                    )
                )
            org_id = f"org_{tenant_id[-1]}"
            if db.session.get(Organization, org_id) is None:
                db.session.add(
                    Organization(
                        id=org_id,
                        tenant_id=tenant_id,
                        name=f"Org {tenant_id[-1].upper()}",
                        slug=f"org-{tenant_id[-1]}",
                        status="active",
                    )
                )
            role_id = f"role_{tenant_id}_admin"
            if db.session.get(Role, role_id) is None:
                db.session.add(
                    Role(
                        id=role_id,
                        tenant_id=tenant_id,
                        name="admin",
                        scope="tenant",
                        permissions=["admin"],
                    )
                )
        if db.session.get(User, "user_admin") is None:
            db.session.add(
                User(
                    id="user_admin",
                    email="admin@example.test",
                    username="admin",
                    display_name="Admin",
                    status="active",
                )
            )
        for tenant_id in ("tenant_a", "tenant_b"):
            mid = f"membership_admin_{tenant_id}"
            if db.session.get(Membership, mid) is None:
                db.session.add(
                    Membership(
                        id=mid,
                        tenant_id=tenant_id,
                        organization_id=f"org_{tenant_id[-1]}",
                        user_id="user_admin",
                        role_id=f"role_{tenant_id}_admin",
                        status="active",
                    )
                )
        db.session.add_all(
            [
                Alert(
                    id="alert-a",
                    tenant_id="tenant_a",
                    timestamp=now,
                    source_ip="10.1.1.1",
                    threat_type="scan",
                    level="high",
                    status="open",
                    summary="tenant a alert",
                ),
                Alert(
                    id="alert-b",
                    tenant_id="tenant_b",
                    timestamp=now,
                    source_ip="10.2.2.2",
                    threat_type="scan",
                    level="critical",
                    status="open",
                    summary="tenant b alert",
                ),
                Rule(
                    id="rule-a",
                    tenant_id="tenant_a",
                    name="tenant-a-rule",
                    rule_type="signature",
                    pattern="/a/",
                    action="alert",
                    level="medium",
                    priority=10,
                    enabled=True,
                ),
                Rule(
                    id="rule-b",
                    tenant_id="tenant_b",
                    name="tenant-b-rule",
                    rule_type="signature",
                    pattern="/b/",
                    action="alert",
                    level="high",
                    priority=10,
                    enabled=True,
                ),
                AuditEvent(
                    tenant_id="tenant_a",
                    event_type="tenant.audit",
                    actor="admin",
                    resource_type="alert",
                    resource_id="alert-a",
                    payload={"tenant": "a"},
                ),
                AuditEvent(
                    tenant_id="tenant_b",
                    event_type="tenant.audit",
                    actor="admin",
                    resource_type="alert",
                    resource_id="alert-b",
                    payload={"tenant": "b"},
                ),
                BannedIp(
                    tenant_id="tenant_a",
                    ip="203.0.113.10",
                    reason="tenant a ban",
                    operator="admin",
                ),
                BannedIp(
                    tenant_id="tenant_b",
                    ip="203.0.113.20",
                    reason="tenant b ban",
                    operator="admin",
                ),
                IOC(
                    id="ioc-a",
                    tenant_id="tenant_a",
                    ioc_type="ip",
                    value="198.51.100.10",
                    sources=["manual"],
                    reason="tenant a ioc",
                ),
                IOC(
                    id="ioc-b",
                    tenant_id="tenant_b",
                    ioc_type="ip",
                    value="198.51.100.20",
                    sources=["manual"],
                    reason="tenant b ioc",
                ),
            ]
        )
        db.session.commit()


def _seed_rbac_identity_rows(app):
    from web.database import db
    from web.models import (
        APIKey,
        Membership,
        Organization,
        Role,
        Tenant,
        User,
    )

    now = datetime.now(timezone.utc)
    raw_keys = {
        "tenant_a_viewer": "gk_tenant_a_viewer_secret",
        "tenant_a_analyst": "gk_tenant_a_analyst_secret",
        "tenant_a_admin": "gk_tenant_a_admin_secret",
        "tenant_b_admin": "gk_tenant_b_admin_secret",
    }
    with app.app_context():
        for tenant_id, slug in (("tenant_a", "tenant-a"), ("tenant_b", "tenant-b")):
            if db.session.get(Tenant, tenant_id) is None:
                db.session.add(Tenant(id=tenant_id, name=tenant_id, slug=slug, status="active"))
            org_id = f"org_{tenant_id[-1]}"
            if db.session.get(Organization, org_id) is None:
                db.session.add(
                    Organization(
                        id=org_id,
                        tenant_id=tenant_id,
                        name=f"Org {tenant_id[-1].upper()}",
                        slug=f"org-{tenant_id[-1]}",
                        status="active",
                    )
                )
            for role_name in ("viewer", "analyst", "admin"):
                role_id = f"role_{tenant_id}_{role_name}"
                if db.session.get(Role, role_id) is None:
                    db.session.add(
                        Role(
                            id=role_id,
                            tenant_id=tenant_id,
                            name=role_name,
                            scope="tenant",
                            permissions=[role_name],
                        )
                    )

        if db.session.get(User, "user_multi") is None:
            db.session.add(
                User(
                    id="user_multi",
                    email="multi@example.test",
                    username="multi",
                    display_name="Multi Tenant User",
                    status="active",
                )
            )
        memberships = [
            ("membership_multi_a_viewer", "tenant_a", "org_a", "role_tenant_a_viewer"),
            ("membership_multi_b_admin", "tenant_b", "org_b", "role_tenant_b_admin"),
        ]
        for mid, tenant_id, org_id, role_id in memberships:
            if db.session.get(Membership, mid) is None:
                db.session.add(
                    Membership(
                        id=mid,
                        tenant_id=tenant_id,
                        organization_id=org_id,
                        user_id="user_multi",
                        role_id=role_id,
                        status="active",
                    )
                )

        specs = [
            ("api_key_a_viewer", "tenant_a", "viewer", raw_keys["tenant_a_viewer"]),
            ("api_key_a_analyst", "tenant_a", "analyst", raw_keys["tenant_a_analyst"]),
            ("api_key_a_admin", "tenant_a", "admin", raw_keys["tenant_a_admin"]),
            ("api_key_b_admin", "tenant_b", "admin", raw_keys["tenant_b_admin"]),
        ]
        for key_id, tenant_id, role, raw in specs:
            if db.session.get(APIKey, key_id) is None:
                db.session.add(
                    APIKey(
                        id=key_id,
                        tenant_id=tenant_id,
                        name=key_id,
                        key_prefix=raw[:16],
                        key_hash=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                        role=role,
                        scopes=[role],
                        status="active",
                        expires_at=now + timedelta(days=1),
                    )
                )
        db.session.commit()
    return raw_keys


def _jwt_headers(app, *, username: str, tenant_id: str, role: str = "admin"):
    from flask_jwt_extended import create_access_token

    with app.app_context():
        token = create_access_token(
            identity=username,
            additional_claims={"role": role, "tenant_id": tenant_id},
        )
    return {"Authorization": f"Bearer {token}"}


def _api_key_headers(raw_key: str):
    return {"X-API-Key": raw_key}


def test_rbac_role_claim_and_audit_query(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    client = app.test_client()
    headers, login_body = _auth_headers(client)

    assert login_body["role"] == "admin"
    me = client.get("/api/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.get_json()["role"] == "admin"
    assert login_body["tenant_id"] == "tenant_default"

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


def test_login_ignores_client_supplied_tenant_id(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    client = app.test_client()

    resp = client.post(
        "/api/auth/login",
        json={
            "username": "admin",
            "password": "changeme",
            "tenant_id": "tenant_attacker",
        },
    )

    assert resp.status_code == 200
    assert resp.get_json()["tenant_id"] == "tenant_default"


def test_tenant_a_cannot_read_tenant_b_alerts(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    _seed_tenant_boundary_rows(app)
    client = app.test_client()
    headers, _ = _auth_headers(client, tenant_id="tenant_a")

    listed = client.get("/api/alerts", headers=headers)
    assert listed.status_code == 200
    ids = {item["id"] for item in listed.get_json()}
    assert "alert-a" in ids
    assert "alert-b" not in ids

    detail = client.get("/api/alerts/alert-b", headers=headers)
    assert detail.status_code == 404


def test_tenant_a_cannot_mutate_tenant_b_rule(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    _seed_tenant_boundary_rows(app)
    client = app.test_client()
    headers, _ = _auth_headers(client, tenant_id="tenant_a")

    update = client.put(
        "/api/rules/rule-b",
        headers=headers,
        json={"description": "cross tenant edit"},
    )
    assert update.status_code == 404

    own = client.put(
        "/api/rules/rule-a",
        headers=headers,
        json={"description": "own tenant edit"},
    )
    assert own.status_code == 200


def test_tenant_a_cannot_query_tenant_b_audit(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    _seed_tenant_boundary_rows(app)
    client = app.test_client()
    headers, _ = _auth_headers(client, tenant_id="tenant_a")

    audit = client.get("/api/audit/events?event_type=tenant.audit", headers=headers)
    assert audit.status_code == 200
    ids = {item["resource_id"] for item in audit.get_json()["items"]}
    assert "alert-a" in ids
    assert "alert-b" not in ids


def test_tenant_a_cannot_export_tenant_b_report(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    _seed_tenant_boundary_rows(app)
    client = app.test_client()
    headers, _ = _auth_headers(client, tenant_id="tenant_a")

    summary = client.get("/api/reports/summary?period=day", headers=headers)
    assert summary.status_code == 200
    body = summary.get_json()
    assert body["overview"]["total_alerts"] == 1
    assert body["overview"]["critical_alerts"] == 0

    exported = client.get("/api/reports/export?period=day&format=json", headers=headers)
    assert exported.status_code == 200
    assert exported.get_json()["overview"]["total_alerts"] == 1


def test_tenant_a_cannot_read_or_delete_tenant_b_banned_ip(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    _seed_tenant_boundary_rows(app)
    client = app.test_client()
    headers, _ = _auth_headers(client, tenant_id="tenant_a")

    listed = client.get("/api/banned_ips", headers=headers)
    assert listed.status_code == 200
    ips = {item["ip"] for item in listed.get_json()}
    assert "203.0.113.10" in ips
    assert "203.0.113.20" not in ips

    delete = client.delete("/api/banned_ips/203.0.113.20", headers=headers)
    assert delete.status_code == 404


def test_tenant_a_ioc_queries_do_not_see_tenant_b_iocs(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    _seed_tenant_boundary_rows(app)
    client = app.test_client()
    headers, _ = _auth_headers(client, tenant_id="tenant_a")

    listed = client.get("/api/threat_intel?type=ip", headers=headers)
    assert listed.status_code == 200
    values = {item["value"] for item in listed.get_json()["entries"]}
    assert "198.51.100.10" in values
    assert "198.51.100.20" not in values

    delete = client.delete(
        "/api/threat_intel/iocs/ip/198.51.100.20", headers=headers
    )
    assert delete.status_code == 404


def test_operation_audit_is_written_to_hash_chained_security_log(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    client = app.test_client()
    headers, _ = _auth_headers(client)

    resp = client.put(
        "/api/settings",
        headers=headers,
        json={"alert_threshold": 0.4},
    )
    assert resp.status_code == 200

    log_path = Path(app.config["GUARDIAN_LOG_DIR"]) / "security.log"
    events = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    operation_events = [
        event
        for event in events
        if event.get("event_type") == "operation_audit"
    ]
    assert any(
        event["details"]["event_type"] == "settings.updated"
        for event in operation_events
    )

    from src.audit.security_logger import SecurityLogger

    integrity = SecurityLogger(
        log_dir=app.config["GUARDIAN_LOG_DIR"], enable_integrity=True
    ).verify_integrity()
    assert integrity["valid"] is True


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


def test_jwt_user_cross_tenant_access_is_rejected(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    _seed_tenant_boundary_rows(app)
    _seed_rbac_identity_rows(app)
    client = app.test_client()

    tenant_a_headers = _jwt_headers(app, username="multi", tenant_id="tenant_a", role="admin")
    detail = client.get("/api/alerts/alert-b", headers=tenant_a_headers)
    assert detail.status_code == 404

    forged = _jwt_headers(app, username="multi", tenant_id="tenant_c", role="admin")
    denied = client.get("/api/alerts", headers=forged)
    assert denied.status_code == 403


def test_api_key_cross_tenant_access_is_rejected(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    _seed_tenant_boundary_rows(app)
    raw_keys = _seed_rbac_identity_rows(app)
    client = app.test_client()
    headers = _api_key_headers(raw_keys["tenant_a_admin"])

    listed = client.get("/api/alerts", headers=headers)
    assert listed.status_code == 200
    ids = {item["id"] for item in listed.get_json()}
    assert "alert-a" in ids
    assert "alert-b" not in ids

    cross = client.put(
        "/api/rules/rule-b",
        headers=headers,
        json={"description": "cross tenant edit via api key"},
    )
    assert cross.status_code == 404


def test_viewer_cannot_execute_write_operations(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    _seed_tenant_boundary_rows(app)
    raw_keys = _seed_rbac_identity_rows(app)
    client = app.test_client()
    headers = _api_key_headers(raw_keys["tenant_a_viewer"])

    triage = client.post(
        "/api/alerts/alert-a/status",
        headers=headers,
        json={"status": "ignored", "note": "viewer should not write"},
    )
    assert triage.status_code == 403

    rule = client.post(
        "/api/rules",
        headers=headers,
        json={
            "name": "viewer-write",
            "type": "signature",
            "pattern": "/viewer/",
            "action": "alert",
            "level": "low",
        },
    )
    assert rule.status_code == 403


def test_api_key_analyst_can_triage_but_cannot_update_settings(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    _seed_tenant_boundary_rows(app)
    raw_keys = _seed_rbac_identity_rows(app)
    client = app.test_client()
    headers = _api_key_headers(raw_keys["tenant_a_analyst"])

    triage = client.post(
        "/api/alerts/alert-a/status",
        headers=headers,
        json={"status": "acknowledged", "note": "analyst triage"},
    )
    assert triage.status_code == 200

    settings = client.put(
        "/api/settings",
        headers=headers,
        json={"alert_threshold": 0.6},
    )
    assert settings.status_code == 403


def test_admin_can_manage_rules_iocs_and_settings(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path, role="admin")
    _seed_tenant_boundary_rows(app)
    raw_keys = _seed_rbac_identity_rows(app)
    client = app.test_client()
    headers = _api_key_headers(raw_keys["tenant_a_admin"])

    rule = client.post(
        "/api/rules",
        headers=headers,
        json={
            "name": "admin-rule",
            "type": "signature",
            "pattern": "/admin/",
            "action": "alert",
            "level": "medium",
        },
    )
    assert rule.status_code == 201

    ioc = client.post(
        "/api/threat_intel/iocs",
        headers=headers,
        json={
            "type": "ip",
            "value": "198.51.100.99",
            "source": "manual",
            "reason": "admin test",
        },
    )
    assert ioc.status_code == 201

    settings = client.put(
        "/api/settings",
        headers=headers,
        json={"alert_threshold": 0.65},
    )
    assert settings.status_code == 200
