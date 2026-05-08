from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone


def _build_test_app(monkeypatch, tmp_path, *, role: str = "admin"):
    db_file = tmp_path / f"saas_{role}_{uuid.uuid4().hex}.db"
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "changeme")
    monkeypatch.setenv("ADMIN_ROLE", role)
    monkeypatch.setenv("AUDIT_LOG_DIR", str(tmp_path / f"audit_{uuid.uuid4().hex}"))

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
    return {"Authorization": f"Bearer {resp.get_json()['access_token']}"}


def _jwt_headers(app, *, username: str, tenant_id: str, role: str = "admin"):
    from flask_jwt_extended import create_access_token

    with app.app_context():
        token = create_access_token(
            identity=username,
            additional_claims={"role": role, "tenant_id": tenant_id},
        )
    return {"Authorization": f"Bearer {token}"}


def _seed_tenant_admin(app, tenant_id: str = "tenant_customer"):
    from web.database import db
    from web.models import Membership, Organization, Role, Tenant, User

    with app.app_context():
        db.session.add(
            Tenant(id=tenant_id, name="Customer", slug="customer", status="active")
        )
        db.session.add(
            Organization(
                id="org_customer",
                tenant_id=tenant_id,
                name="Customer Org",
                slug="default",
                status="active",
            )
        )
        db.session.add(
            Role(
                id="role_customer_admin",
                tenant_id=tenant_id,
                name="admin",
                scope="tenant",
                permissions=["admin"],
            )
        )
        db.session.add(
            User(
                id="user_customer_admin",
                email="customer@example.test",
                username="customer-admin",
                status="active",
            )
        )
        db.session.add(
            Membership(
                id="membership_customer_admin",
                tenant_id=tenant_id,
                organization_id="org_customer",
                user_id="user_customer_admin",
                role_id="role_customer_admin",
                status="active",
            )
        )
        db.session.commit()


def test_platform_admin_can_manage_saas_tenant_and_audit_operations(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)

    created = client.post(
        "/api/admin/saas/tenants",
        headers=headers,
        json={
            "id": "tenant_acme",
            "name": "Acme",
            "slug": "acme",
            "plan_code": "mvp-default",
        },
    )
    assert created.status_code == 201
    assert created.get_json()["status"] == "active"

    suspended = client.patch(
        "/api/admin/saas/tenants/tenant_acme",
        headers=headers,
        json={"status": "suspended"},
    )
    assert suspended.status_code == 200
    assert suspended.get_json()["status"] == "suspended"

    quota = client.put(
        "/api/admin/saas/tenants/tenant_acme/quotas/rules",
        headers=headers,
        json={"limit": 7},
    )
    assert quota.status_code == 200
    assert quota.get_json()["limit"] == 7
    assert quota.get_json()["source"] == "manual"

    license_resp = client.post(
        "/api/admin/saas/tenants/tenant_acme/licenses",
        headers=headers,
        json={"issued_to": "Acme SOC", "limits": {"rules": 9}},
    )
    assert license_resp.status_code == 201
    license_body = license_resp.get_json()
    assert license_body["license_key"].startswith("lic_")

    disabled = client.patch(
        f"/api/admin/saas/tenants/tenant_acme/licenses/{license_body['id']}/status",
        headers=headers,
        json={"status": "disabled"},
    )
    assert disabled.status_code == 200
    assert disabled.get_json()["status"] == "disabled"

    renewed_until = (datetime.now(timezone.utc) + timedelta(days=45)).isoformat()
    renewed = client.patch(
        f"/api/admin/saas/tenants/tenant_acme/licenses/{license_body['id']}",
        headers=headers,
        json={"status": "active", "expires_at": renewed_until},
    )
    assert renewed.status_code == 200
    assert renewed.get_json()["status"] == "active"
    assert renewed.get_json()["expires_at"] is not None

    usage = client.get(
        "/api/admin/saas/tenants/tenant_acme/usage",
        headers=headers,
    )
    assert usage.status_code == 200
    usage_items = usage.get_json()["items"]
    assert {item["metric"] for item in usage_items} >= {"rules", "alerts"}

    from web.database import db
    from web.models import AuditEvent

    with app.app_context():
        events = {
            row.event_type
            for row in db.session.query(AuditEvent)
            .filter(AuditEvent.resource_id.in_(("tenant_acme", license_body["id"], "tenant_acme:rules")))
            .all()
        }
    assert "saas.tenant.created" in events
    assert "saas.tenant.updated" in events
    assert "saas.license.created" in events
    assert "saas.license.status_updated" in events
    assert "saas.license.updated" in events
    assert "saas.quota.updated" in events


def test_tenant_admin_cannot_use_platform_saas_control_plane(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    _seed_tenant_admin(app)
    client = app.test_client()
    headers = _jwt_headers(
        app,
        username="customer-admin",
        tenant_id="tenant_customer",
        role="admin",
    )

    resp = client.get("/api/admin/saas/tenants", headers=headers)

    assert resp.status_code == 403


def test_suspended_tenant_access_is_restricted_for_jwt_and_api_key(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    _seed_tenant_admin(app)

    from web.database import db
    from web.models import APIKey, Tenant

    raw_key = "gk_customer_admin_secret"
    with app.app_context():
        tenant = db.session.get(Tenant, "tenant_customer")
        tenant.status = "suspended"
        db.session.add(
            APIKey(
                id="api_key_customer",
                tenant_id="tenant_customer",
                name="customer",
                key_prefix=raw_key[:16],
                key_hash=hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
                role="admin",
                scopes=["admin"],
                status="active",
                expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            )
        )
        db.session.commit()

    client = app.test_client()
    jwt_headers = _jwt_headers(
        app,
        username="customer-admin",
        tenant_id="tenant_customer",
        role="admin",
    )
    jwt_resp = client.get("/api/stats", headers=jwt_headers)
    assert jwt_resp.status_code == 403
    assert jwt_resp.get_json()["code"] == "tenant_inactive"

    key_resp = client.get("/api/stats", headers={"X-API-Key": raw_key})
    assert key_resp.status_code == 403
    assert key_resp.get_json()["code"] == "tenant_inactive"

    with app.app_context():
        from web.models import AuditEvent

        denied_count = (
            db.session.query(AuditEvent)
            .filter(
                AuditEvent.tenant_id == "tenant_customer",
                AuditEvent.event_type == "tenant.access_denied",
            )
            .count()
        )
    assert denied_count >= 2


def test_tenant_admin_can_view_commercial_status_and_overages(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    _seed_tenant_admin(app)

    from web.database import db
    from web.models import Alert, LicenseKey, Plan, Quota, Subscription, Tenant

    raw_license = "lic_customer_secret"
    with app.app_context():
        plan = db.session.query(Plan).filter(Plan.code == "mvp-default").one()
        tenant = db.session.get(Tenant, "tenant_customer")
        tenant.plan = plan.code
        db.session.add(
            Subscription(
                id="sub_customer",
                tenant_id="tenant_customer",
                plan_id=plan.id,
                status="active",
            )
        )
        db.session.add(
            LicenseKey(
                id="lic_customer",
                tenant_id="tenant_customer",
                key_prefix=raw_license[:16],
                key_hash=hashlib.sha256(raw_license.encode("utf-8")).hexdigest(),
                status="active",
                issued_to="Customer SOC",
                expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            )
        )
        db.session.add(
            Quota(
                tenant_id="tenant_customer",
                metric="alerts",
                limit=0,
                source="manual",
            )
        )
        db.session.add(
            Alert(
                id="alert_customer_1",
                tenant_id="tenant_customer",
                timestamp=datetime.now(timezone.utc),
                source_ip="10.0.0.1",
                threat_type="scan",
                level="high",
                status="open",
            )
        )
        db.session.commit()

    client = app.test_client()
    headers = _jwt_headers(
        app,
        username="customer-admin",
        tenant_id="tenant_customer",
        role="admin",
    )

    resp = client.get("/api/tenant/commercial/status", headers=headers)

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["tenant"]["id"] == "tenant_customer"
    assert body["current_plan"]["code"] == "mvp-default"
    assert body["licenses"][0]["status"] == "active"
    assert body["has_overage"] is True
    assert body["overages"][0]["metric"] == "alerts"


def test_suspended_tenant_can_still_view_commercial_status(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    _seed_tenant_admin(app)

    from web.database import db
    from web.models import Tenant

    with app.app_context():
        tenant = db.session.get(Tenant, "tenant_customer")
        tenant.status = "suspended"
        db.session.commit()

    client = app.test_client()
    headers = _jwt_headers(
        app,
        username="customer-admin",
        tenant_id="tenant_customer",
        role="admin",
    )

    status_resp = client.get("/api/tenant/commercial/status", headers=headers)
    stats_resp = client.get("/api/stats", headers=headers)

    assert status_resp.status_code == 200
    assert status_resp.get_json()["tenant"]["status"] == "suspended"
    assert stats_resp.status_code == 403
