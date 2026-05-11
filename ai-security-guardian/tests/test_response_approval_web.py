from __future__ import annotations

from datetime import datetime, timezone

from src.response.firewall import FirewallResult
from tests.auth_helpers import auth_headers, configure_test_admin


def _build_test_app(monkeypatch, tmp_path):
    db_file = tmp_path / "approval_web.db"
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("REQUIRE_REDIS_AVAILABLE", "false")
    monkeypatch.setenv("REQUIRE_MODELS_READY", "false")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    configure_test_admin(monkeypatch)

    from web.app import create_app
    from config.config import TestingConfig

    monkeypatch.setattr(TestingConfig, "REQUIRE_REDIS_AVAILABLE", False)
    monkeypatch.setattr(TestingConfig, "REQUIRE_MODELS_READY", False)

    app, _ = create_app()
    app.config["TESTING"] = True
    return app


def _set_real_enforcement_env(monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("REAL_ENFORCEMENT_GATE", "real-enforcement")
    monkeypatch.setenv("REAL_ENFORCEMENT_APPROVAL_REQUIRED", "true")
    monkeypatch.setenv("REAL_ENFORCEMENT_AUDIT_VERIFIED", "true")
    monkeypatch.setenv("REAL_ENFORCEMENT_ROLLBACK_READY", "true")
    monkeypatch.setenv("REAL_ENFORCEMENT_UNBLOCK_READY", "true")
    monkeypatch.setenv("REAL_ENFORCEMENT_REVIEW_REQUIRED", "true")


def _seed_real_gate_db_evidence(app, *, provider_validated=True):
    with app.app_context():
        from web.database import db
        from web.models import (
            DEFAULT_TENANT_ID,
            ResponseDrill,
            ResponseProviderConfig,
            ResponseWhitelistEntry,
        )

        db.session.add(
            ResponseWhitelistEntry(
                tenant_id=DEFAULT_TENANT_ID,
                scope="business",
                value_type="cidr",
                value="198.51.100.0/24",
                status="active",
                reason="customer business range",
                owner="customer",
                created_by="admin",
            )
        )
        provider = ResponseProviderConfig(
            tenant_id=DEFAULT_TENANT_ID,
            provider_type="iptables",
            provider_name="iptables",
            environment="production",
            status="active",
            config_ref="config://response/iptables",
            credential_ref="local-root-approved-change-window",
            created_by="admin",
            last_validated_at=datetime.now(timezone.utc) if provider_validated else None,
            last_validation_result={"ok": True, "reason": "provider_available"}
            if provider_validated
            else None,
        )
        db.session.add(provider)
        db.session.add(
            ResponseDrill(
                tenant_id=DEFAULT_TENANT_ID,
                provider_config=provider,
                environment="production",
                drill_type="misblock_recovery",
                target_type="ip",
                target="203.0.113.250",
                status="passed",
                started_at=datetime.now(timezone.utc),
                ended_at=datetime.now(timezone.utc),
                rto_seconds=120,
                result="rollback verified",
                participants=["soc", "ops"],
                evidence={"ticket": "DRILL-1"},
                created_by="admin",
                approved_by="lead",
            )
        )
        db.session.commit()
        return provider.id


def _auth_headers(client):
    headers, _ = auth_headers(client)
    return headers


def test_banned_ips_post_creates_approval_not_ban(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)

    resp = client.post(
        "/api/banned_ips",
        headers=headers,
        json={"ip": "192.0.2.201", "reason": "manual"},
    )

    assert resp.status_code == 202
    assert resp.get_json()["status"] == "pending_approval"
    assert resp.get_json()["dry_run"] is True
    assert "gate" in resp.get_json()

    with app.app_context():
        from web.database import db
        from web.models import BannedIp, ResponseAction

        assert db.session.get(BannedIp, ("192.0.2.201", "tenant_default")) is None
        action = (
            db.session.query(ResponseAction)
            .filter(ResponseAction.target == "192.0.2.201")
            .order_by(ResponseAction.id.desc())
            .first()
        )
        assert action is not None
        assert action.status == "pending_approval"


def _create_and_approve_response_action(
    client,
    headers,
    *,
    ip="192.0.2.210",
    provider_config_id=None,
):
    payload = {
        "action_type": "ban_ip",
        "target_type": "ip",
        "target": ip,
        "ttl_seconds": 3600,
        "reason": "confirmed critical alert",
    }
    if provider_config_id is not None:
        payload["provider_config_id"] = provider_config_id
    create = client.post(
        "/api/response/actions",
        headers=headers,
        json=payload,
    )
    assert create.status_code == 202
    action_id = create.get_json()["response_action_id"]
    approve = client.post(
        f"/api/response/actions/{action_id}/approve",
        headers=headers,
        json={"reason": "human approval granted"},
    )
    assert approve.status_code == 200
    return action_id


def test_response_execute_dry_run_does_not_require_or_call_provider(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)
    action_id = _create_and_approve_response_action(client, headers)

    def _boom():
        raise AssertionError("provider must not be loaded during dry-run execute")

    monkeypatch.setattr("src.response.firewall.firewall_manager_from_env", _boom)
    resp = client.post(
        f"/api/response/actions/{action_id}/execute",
        headers=headers,
        json={"reason": "dry-run execution drill"},
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "dry_run_simulated"
    assert body["dry_run"] is True
    assert body["provider_called"] is False


def test_response_execute_real_without_gate_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.delenv("REAL_ENFORCEMENT_GATE", raising=False)
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)
    action_id = _create_and_approve_response_action(client, headers, ip="198.51.100.210")

    resp = client.post(
        f"/api/response/actions/{action_id}/execute",
        headers=headers,
        json={"reason": "confirmed critical abuse"},
    )

    assert resp.status_code == 403
    body = resp.get_json()
    assert body["status"] == "rejected"
    assert body["reason"] == "real_enforcement_gate_required"
    assert body["dry_run"] is False


def test_response_execute_whitelist_hit_never_calls_provider(monkeypatch, tmp_path):
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("REAL_ENFORCEMENT_GATE", "real-enforcement")
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)
    action_id = _create_and_approve_response_action(client, headers, ip="198.51.100.211")
    wl = client.post(
        "/api/response/whitelist",
        headers=headers,
        json={
            "scope": "business",
            "value_type": "ip",
            "value": "198.51.100.211",
            "reason": "core customer endpoint",
        },
    )
    assert wl.status_code == 201

    def _boom():
        raise AssertionError("provider must not be called when whitelist matches")

    monkeypatch.setattr("src.response.firewall.firewall_manager_from_env", _boom)
    resp = client.post(
        f"/api/response/actions/{action_id}/execute",
        headers=headers,
        json={"reason": "confirmed critical abuse"},
    )

    assert resp.status_code == 409
    body = resp.get_json()
    assert body["status"] == "skipped"
    assert body["reason"] == "whitelist_matched"


def test_response_execute_cidr_whitelist_hit_never_calls_provider(monkeypatch, tmp_path):
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("REAL_ENFORCEMENT_GATE", "real-enforcement")
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)
    action_id = _create_and_approve_response_action(client, headers, ip="198.51.100.42")
    wl = client.post(
        "/api/response/whitelists",
        headers=headers,
        json={
            "scope": "monitoring",
            "value_type": "cidr",
            "value": "198.51.100.0/24",
            "owner": "soc",
            "reason": "monitoring range",
        },
    )
    assert wl.status_code == 201

    def _boom():
        raise AssertionError("provider must not be called when CIDR whitelist matches")

    monkeypatch.setattr("src.response.firewall.firewall_manager_from_env", _boom)
    resp = client.post(
        f"/api/response/actions/{action_id}/execute",
        headers=headers,
        json={"reason": "confirmed critical abuse"},
    )

    assert resp.status_code == 409
    body = resp.get_json()
    assert body["status"] == "skipped"
    assert body["reason"] == "whitelist_matched"


def test_response_whitelist_expired_entry_is_historical_not_effective(monkeypatch, tmp_path):
    _set_real_enforcement_env(monkeypatch)
    monkeypatch.setenv("RESPONSE_BUSINESS_IP_WHITELIST", "203.0.113.250")
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)
    action_id = _create_and_approve_response_action(client, headers, ip="198.51.100.43")
    wl = client.post(
        "/api/response/whitelists",
        headers=headers,
        json={
            "scope": "office",
            "value_type": "cidr",
            "value": "198.51.100.0/24",
            "reason": "old office range",
            "expires_at": "2020-01-01T00:00:00Z",
        },
    )
    assert wl.status_code == 201
    entry_id = wl.get_json()["entry"]["id"]

    resp = client.post(
        f"/api/response/actions/{action_id}/execute",
        headers=headers,
        json={"reason": "confirmed critical abuse"},
    )

    assert resp.status_code == 409
    assert resp.get_json()["reason"] == "provider_required"
    get_entry = client.get(f"/api/response/whitelists/{entry_id}", headers=headers)
    assert get_entry.status_code == 200
    assert get_entry.get_json()["entry"]["expires_at"] is not None


def test_response_whitelist_crud_and_audit(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)

    create = client.post(
        "/api/response/whitelists",
        headers=headers,
        json={
            "scope": "control_plane",
            "value_type": "ip",
            "value": "198.51.100.44",
            "owner": "platform",
            "reason": "control plane endpoint",
        },
    )
    assert create.status_code == 201
    entry_id = create.get_json()["entry"]["id"]
    patch = client.patch(
        f"/api/response/whitelists/{entry_id}",
        headers=headers,
        json={"reason": "control plane endpoint updated", "status": "active"},
    )
    assert patch.status_code == 200
    check = client.post(
        "/api/response/whitelists/check",
        headers=headers,
        json={"target": "198.51.100.44"},
    )
    assert check.status_code == 200
    assert check.get_json()["reason"] == "control_plane_whitelist"
    delete = client.delete(f"/api/response/whitelists/{entry_id}", headers=headers)
    assert delete.status_code == 200

    with app.app_context():
        from web.database import db
        from web.models import AuditEvent, ResponseWhitelistEntry

        row = db.session.get(ResponseWhitelistEntry, entry_id)
        assert row.status == "disabled"
        event_types = [
            r.event_type
            for r in db.session.query(AuditEvent)
            .filter(AuditEvent.resource_id == str(entry_id))
            .order_by(AuditEvent.id.asc())
            .all()
        ]
        assert "response.whitelist.created" in event_types
        assert "response.whitelist.updated" in event_types
        assert "response.whitelist.disabled" in event_types


def test_responder_db_whitelist_hit_never_calls_provider(monkeypatch, tmp_path):
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("REAL_ENFORCEMENT_GATE", "real-enforcement")
    app = _build_test_app(monkeypatch, tmp_path)
    with app.app_context():
        from datetime import timedelta
        from unittest.mock import patch

        from src.response.responder import SecurityResponder
        from web.database import db
        from web.models import DEFAULT_TENANT_ID, ResponseWhitelistEntry

        db.session.add(
            ResponseWhitelistEntry(
                tenant_id=DEFAULT_TENANT_ID,
                scope="business",
                value_type="cidr",
                value="198.51.100.0/24",
                status="active",
                reason="customer business range",
                owner="customer",
                created_by="admin",
            )
        )
        db.session.commit()

        responder = SecurityResponder(dry_run=False, real_enforcement_gate="real-enforcement")
        responder.approve_ban_ip("198.51.100.45", operator="analyst-a", reason="confirmed")
        with patch("src.response.firewall.subprocess.run") as mock_run:
            responder.execute_approved_ban_ip(
                "198.51.100.45",
                operator="analyst-a",
                reason="execute confirmed",
                duration=timedelta(hours=1),
            )
            mock_run.assert_not_called()
        rows = [a for a in responder.response_actions if a.get("action") == "ban_ip"]
        assert rows[-1]["status"] == "skipped"
        assert "business_whitelist" in rows[-1]["reason"]


def test_response_execute_real_requires_provider(monkeypatch, tmp_path):
    _set_real_enforcement_env(monkeypatch)
    app = _build_test_app(monkeypatch, tmp_path)
    _seed_real_gate_db_evidence(app)
    client = app.test_client()
    headers = _auth_headers(client)
    action_id = _create_and_approve_response_action(client, headers, ip="203.0.113.212")

    resp = client.post(
        f"/api/response/actions/{action_id}/execute",
        headers=headers,
        json={"reason": "confirmed critical abuse"},
    )

    assert resp.status_code == 409
    body = resp.get_json()
    assert body["status"] == "rejected"
    assert body["reason"] == "provider_required"
    assert body["missing_prerequisites"][0]["code"] == "provider_required"


def test_response_execute_real_gate_requires_env_prerequisites(monkeypatch, tmp_path):
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("REAL_ENFORCEMENT_GATE", "real-enforcement")
    app = _build_test_app(monkeypatch, tmp_path)
    provider_id = _seed_real_gate_db_evidence(app)
    client = app.test_client()
    headers = _auth_headers(client)
    action_id = _create_and_approve_response_action(
        client,
        headers,
        ip="203.0.113.42",
        provider_config_id=provider_id,
    )

    def _boom():
        raise AssertionError("provider must not be loaded when env prerequisites are missing")

    monkeypatch.setattr("src.response.firewall.firewall_manager_from_env", _boom)
    resp = client.post(
        f"/api/response/actions/{action_id}/execute",
        headers=headers,
        json={"reason": "confirmed critical abuse"},
    )

    assert resp.status_code == 409
    body = resp.get_json()
    assert body["status"] == "rejected"
    assert body["reason"] == "real_enforcement_approval_required"
    assert any(
        item["name"] == "REAL_ENFORCEMENT_APPROVAL_REQUIRED"
        for item in body["missing_prerequisites"]
    )


def test_response_execute_real_requires_validated_provider(monkeypatch, tmp_path):
    _set_real_enforcement_env(monkeypatch)
    app = _build_test_app(monkeypatch, tmp_path)
    provider_id = _seed_real_gate_db_evidence(app, provider_validated=False)
    client = app.test_client()
    headers = _auth_headers(client)
    action_id = _create_and_approve_response_action(
        client,
        headers,
        ip="203.0.113.43",
        provider_config_id=provider_id,
    )

    def _boom():
        raise AssertionError("provider must not be loaded before provider validation evidence")

    monkeypatch.setattr("src.response.firewall.firewall_manager_from_env", _boom)
    resp = client.post(
        f"/api/response/actions/{action_id}/execute",
        headers=headers,
        json={"reason": "confirmed critical abuse"},
    )

    assert resp.status_code == 409
    body = resp.get_json()
    assert body["status"] == "rejected"
    assert body["reason"] == "provider_validation_required"


def test_response_execute_real_all_gate_evidence_uses_mock_provider(monkeypatch, tmp_path):
    _set_real_enforcement_env(monkeypatch)
    app = _build_test_app(monkeypatch, tmp_path)
    provider_id = _seed_real_gate_db_evidence(app)
    client = app.test_client()
    headers = _auth_headers(client)
    action_id = _create_and_approve_response_action(
        client,
        headers,
        ip="203.0.113.44",
        provider_config_id=provider_id,
    )
    calls = []

    class FakeFirewall:
        def ban_input_drop(self, ip: str, *, dry_run: bool):
            calls.append((ip, dry_run))
            return FirewallResult(True, dry_run, "mock_applied", command=["mock", "ban", ip])

        def unban_input_drop(self, ip: str, *, dry_run: bool):
            return FirewallResult(True, dry_run, "mock_removed", command=["mock", "unban", ip])

    monkeypatch.setattr("src.response.firewall.firewall_manager_from_env", lambda: FakeFirewall())
    resp = client.post(
        f"/api/response/actions/{action_id}/execute",
        headers=headers,
        json={"reason": "confirmed critical abuse"},
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "executed"
    assert calls == [("203.0.113.44", False)]


def test_response_execute_without_approval_keeps_pending_action(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)
    create = client.post(
        "/api/response/actions",
        headers=headers,
        json={
            "action_type": "ban_ip",
            "target_type": "ip",
            "target": "192.0.2.213",
            "ttl_seconds": 3600,
            "reason": "confirmed critical alert",
        },
    )
    assert create.status_code == 202
    action_id = create.get_json()["response_action_id"]

    resp = client.post(
        f"/api/response/actions/{action_id}/execute",
        headers=headers,
        json={"reason": "operator requested execution"},
    )

    assert resp.status_code == 409
    assert resp.get_json()["reason"] == "approval_not_approved"
    with app.app_context():
        from web.database import db
        from web.models import ResponseAction

        action = db.session.get(ResponseAction, action_id)
        assert action.status == "pending_approval"


def test_response_execute_real_requires_reason(monkeypatch, tmp_path):
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("REAL_ENFORCEMENT_GATE", "real-enforcement")
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)
    action_id = _create_and_approve_response_action(client, headers, ip="198.51.100.214")

    resp = client.post(f"/api/response/actions/{action_id}/execute", headers=headers, json={})

    assert resp.status_code == 400
    assert resp.get_json()["reason"] == "execution_reason_required"


def test_command_block_creates_approval_not_ban(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)

    resp = client.post(
        "/api/command",
        headers=headers,
        json={"command": "block 192.0.2.202"},
    )

    assert resp.status_code == 200
    assert resp.get_json()["status"] == "pending_approval"

    with app.app_context():
        from web.database import db
        from web.models import BannedIp, ResponseAction

        assert db.session.get(BannedIp, ("192.0.2.202", "tenant_default")) is None
        action = (
            db.session.query(ResponseAction)
            .filter(ResponseAction.target == "192.0.2.202")
            .order_by(ResponseAction.id.desc())
            .first()
        )
        assert action is not None
        assert action.status == "pending_approval"
