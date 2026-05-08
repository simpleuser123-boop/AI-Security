from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone


def _build_test_app(monkeypatch, tmp_path):
    db_file = tmp_path / f"metering_{uuid.uuid4().hex}.db"
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "changeme")
    monkeypatch.setenv("ADMIN_ROLE", "admin")
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


def _set_quota(
    app,
    metric: str,
    limit: int | None,
    *,
    warning_thresholds: list[float] | None = None,
    overage_policy: str = "reject",
):
    from web.database import db
    from web.models import DEFAULT_TENANT_ID, Quota

    with app.app_context():
        row = (
            db.session.query(Quota)
            .filter(Quota.tenant_id == DEFAULT_TENANT_ID, Quota.metric == metric)
            .one_or_none()
        )
        if row is None:
            row = Quota(
                tenant_id=DEFAULT_TENANT_ID,
                metric=metric,
                limit=limit,
                source="test",
                warning_thresholds=warning_thresholds,
                overage_policy=overage_policy,
            )
            db.session.add(row)
        else:
            row.limit = limit
            row.source = "test"
            row.warning_thresholds = warning_thresholds
            row.overage_policy = overage_policy
        db.session.commit()


def test_rule_quota_allows_normal_and_boundary_then_rejects_overage(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)
    _set_quota(app, "api_calls", 100)
    _set_quota(app, "rules", 2)

    def create_rule(name: str):
        return client.post(
            "/api/rules",
            headers=headers,
            json={
                "name": name,
                "type": "signature",
                "pattern": f"/{name}/",
                "action": "alert",
                "level": "medium",
            },
        )

    assert create_rule("normal-rule").status_code == 201
    assert create_rule("boundary-rule").status_code == 201

    over = create_rule("over-rule")
    assert over.status_code == 402
    body = over.get_json()
    assert body["code"] == "quota_exceeded"
    assert body["quota"]["metric"] == "rules"
    assert body["quota"]["limit"] == 2
    assert body["quota"]["used"] == 3

    from web.database import db
    from web.models import AuditEvent, UsageMeter

    with app.app_context():
        usage = (
            db.session.query(UsageMeter)
            .filter_by(tenant_id="tenant_default", metric="rules", period="current")
            .one()
        )
        assert usage.used == 2
        audits = (
            db.session.query(AuditEvent)
            .filter(
                AuditEvent.tenant_id == "tenant_default",
                AuditEvent.event_type == "usage_meter.changed",
                AuditEvent.resource_type == "rule",
            )
            .count()
        )
        assert audits == 2


def test_usage_is_queryable_by_tenant_period_and_metric(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)
    _set_quota(app, "api_calls", 100)
    _set_quota(app, "rules", 10)

    resp = client.post(
        "/api/rules",
        headers=headers,
        json={
            "name": "bucket-rule",
            "type": "signature",
            "pattern": "/bucket/",
            "action": "alert",
            "level": "medium",
        },
    )
    assert resp.status_code == 201

    period = datetime.now(timezone.utc).strftime("%Y-%m")
    usage = client.get(
        f"/api/admin/saas/tenants/tenant_default/usage?metric=rules&period={period}",
        headers=headers,
    )
    assert usage.status_code == 200
    body = usage.get_json()
    assert body["tenant_id"] == "tenant_default"
    assert body["period"] == period
    assert body["items"][0]["metric"] == "rules"
    assert body["items"][0]["used"] == 1
    bucket = next(item for item in body["buckets"] if item["metric"] == "rules")
    assert bucket["period"] == period
    assert bucket["used"] == 1


def test_quota_warning_event_is_emitted_when_threshold_is_crossed(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)
    _set_quota(app, "api_calls", 100)
    _set_quota(app, "rules", 2, warning_thresholds=[0.5])

    resp = client.post(
        "/api/rules",
        headers=headers,
        json={
            "name": "warning-rule",
            "type": "signature",
            "pattern": "/warning/",
            "action": "alert",
            "level": "medium",
        },
    )
    assert resp.status_code == 201

    from web.database import db
    from web.models import AuditEvent

    period = datetime.now(timezone.utc).strftime("%Y-%m")
    with app.app_context():
        event = (
            db.session.query(AuditEvent)
            .filter(
                AuditEvent.tenant_id == "tenant_default",
                AuditEvent.event_type == "usage_quota.warning",
                AuditEvent.resource_id == f"rules:{period}:0.5000",
            )
            .one()
        )
        assert event.payload["metric"] == "rules"
        assert event.payload["threshold"] == 0.5
        assert event.payload["used"] == 1


def test_overage_alert_policy_allows_and_audits_overage(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)
    _set_quota(app, "api_calls", 1, overage_policy="alert")

    assert client.get("/api/stats", headers=headers).status_code == 200
    assert client.get("/api/stats", headers=headers).status_code == 200

    from web.database import db
    from web.models import AuditEvent, UsageMeter

    with app.app_context():
        usage = (
            db.session.query(UsageMeter)
            .filter_by(tenant_id="tenant_default", metric="api_calls", period="current")
            .one()
        )
        assert usage.used == 2
        event = (
            db.session.query(AuditEvent)
            .filter(
                AuditEvent.tenant_id == "tenant_default",
                AuditEvent.event_type == "usage_quota.overage",
                AuditEvent.resource_id == "api_calls:current",
            )
            .first()
        )
        assert event is not None
        assert event.payload["policy"] == "alert"
        assert event.payload["action"] == "alert"


def test_overage_read_only_policy_allows_reads_but_blocks_writes(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)
    _set_quota(app, "api_calls", 1, overage_policy="read_only")
    _set_quota(app, "rules", 100)

    assert client.get("/api/stats", headers=headers).status_code == 200
    assert client.get("/api/stats", headers=headers).status_code == 200
    blocked = client.post(
        "/api/rules",
        headers=headers,
        json={
            "name": "blocked-by-read-only",
            "type": "signature",
            "pattern": "/blocked/",
            "action": "alert",
            "level": "medium",
        },
    )
    assert blocked.status_code == 403
    assert blocked.get_json()["quota"]["overage_policy"] == "read_only"


def test_overage_degrade_policy_returns_degrade_decision_without_rejecting(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    _set_quota(app, "notifications", 0, overage_policy="degrade")

    from web.billing import ensure_quota
    from web.database import db
    from web.models import AuditEvent

    with app.app_context():
        snapshot = ensure_quota(
            db.session,
            "tenant_default",
            "notifications",
            requested=1,
            actor="test",
        )
        db.session.commit()
        assert snapshot.exceeded is True
        assert snapshot.action == "degrade"
        event = (
            db.session.query(AuditEvent)
            .filter(
                AuditEvent.tenant_id == "tenant_default",
                AuditEvent.event_type == "usage_quota.overage",
                AuditEvent.resource_id == "notifications:current",
            )
            .one()
        )
        assert event.payload["policy"] == "degrade"
        assert event.payload["action"] == "degrade"


def test_ioc_quota_counts_new_iocs_but_allows_merge_at_boundary(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)
    _set_quota(app, "api_calls", 100)
    _set_quota(app, "iocs", 1)

    first = client.post(
        "/api/threat_intel/iocs",
        headers=headers,
        json={"type": "ip", "value": "198.51.100.10", "source": "manual"},
    )
    assert first.status_code == 201

    merge = client.post(
        "/api/threat_intel/iocs",
        headers=headers,
        json={"type": "ip", "value": "198.51.100.10", "source": "feed"},
    )
    assert merge.status_code == 201

    over = client.post(
        "/api/threat_intel/iocs",
        headers=headers,
        json={"type": "ip", "value": "198.51.100.11", "source": "manual"},
    )
    assert over.status_code == 402
    assert over.get_json()["quota"]["metric"] == "iocs"


def test_api_call_quota_blocks_second_authenticated_request(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)
    _set_quota(app, "api_calls", 1)

    first = client.get("/api/stats", headers=headers)
    assert first.status_code == 200

    second = client.get("/api/stats", headers=headers)
    assert second.status_code == 402
    body = second.get_json()
    assert body["quota"]["metric"] == "api_calls"
    assert body["quota"]["limit"] == 1
    assert body["quota"]["used"] == 2


def test_license_key_can_override_plan_quota_and_retention_limit(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)

    from web.billing import quota_snapshot
    from web.database import db
    from web.models import DEFAULT_TENANT_ID, LicenseKey, Subscription

    with app.app_context():
        license_row = LicenseKey(
            id="lic_test",
            tenant_id=DEFAULT_TENANT_ID,
            key_prefix="lic_test",
            key_hash="hash_test",
            status="active",
            limits={"rules": 3, "retention_days": 90},
            issued_to="test",
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
        db.session.add(license_row)
        sub = (
            db.session.query(Subscription)
            .filter(Subscription.tenant_id == DEFAULT_TENANT_ID, Subscription.status == "active")
            .one()
        )
        sub.license_key_id = license_row.id
        db.session.commit()

        assert quota_snapshot(db.session, DEFAULT_TENANT_ID, "rules").limit == 3
        assert quota_snapshot(db.session, DEFAULT_TENANT_ID, "retention_days").limit == 90
