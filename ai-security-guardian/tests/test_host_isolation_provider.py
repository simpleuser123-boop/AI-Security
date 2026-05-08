from __future__ import annotations

from src.response.firewall import approved_response_execution
from src.response.host_isolation import (
    CustomWebhookHostIsolationProvider,
    DefenderHostIsolationProvider,
    HostIsolationConfig,
    IsolationResult,
    NullHostIsolationProvider,
    host_isolation_from_env,
)
from src.response.responder import STATUS_EXECUTED, STATUS_REJECTED, SecurityResponder


def _edr_config(provider: str = "edr_custom_webhook") -> HostIsolationConfig:
    return HostIsolationConfig(
        provider=provider,
        tenant_id="tenant-a",
        credential_ref="secret://customer-vault/edr/tenant-a",
        endpoint="https://edr.example.test/isolate",
        provider_test_passed=True,
        recovery_drill_passed=True,
    )


def _set_real_enforcement_env(monkeypatch):
    monkeypatch.setenv("REAL_ENFORCEMENT_APPROVAL_REQUIRED", "true")
    monkeypatch.setenv("REAL_ENFORCEMENT_AUDIT_VERIFIED", "true")
    monkeypatch.setenv("REAL_ENFORCEMENT_ROLLBACK_READY", "true")
    monkeypatch.setenv("REAL_ENFORCEMENT_UNBLOCK_READY", "true")
    monkeypatch.setenv("REAL_ENFORCEMENT_REVIEW_REQUIRED", "true")


def test_default_host_isolation_provider_is_none(monkeypatch):
    monkeypatch.delenv("RESPONSE_HOST_ISOLATION", raising=False)
    assert isinstance(host_isolation_from_env(), NullHostIsolationProvider)


def test_edr_provider_from_env_is_explicit(monkeypatch):
    monkeypatch.setenv("RESPONSE_HOST_ISOLATION", "edr_defender")
    monkeypatch.setenv("RESPONSE_HOST_ISOLATION_CREDENTIAL_REF", "secret://edr/defender")
    monkeypatch.setenv("RESPONSE_HOST_ISOLATION_PROVIDER_TEST_PASSED", "true")
    provider = host_isolation_from_env()
    assert isinstance(provider, DefenderHostIsolationProvider)
    assert provider.config.provider == "edr_defender"


def test_edr_dry_run_returns_plan_without_client_call():
    calls = []
    provider = CustomWebhookHostIsolationProvider(
        config=_edr_config(),
        client=lambda op, ip, plan, cfg: calls.append((op, ip, plan, cfg))
        or IsolationResult(True, True, "called", provider=cfg.provider),
    )
    result = provider.isolate(
        "198.51.100.10",
        dry_run=True,
        context={"alert_id": "alert-1", "requested_by": "analyst-a"},
    )
    assert result.success is True
    assert result.message == "dry_run_plan"
    assert calls == []
    assert result.meta["plan"]["alert_id"] == "alert-1"


def test_edr_real_call_requires_approved_execution_context():
    calls = []
    provider = CustomWebhookHostIsolationProvider(
        config=_edr_config(),
        client=lambda op, ip, plan, cfg: calls.append((op, ip, plan, cfg))
        or IsolationResult(True, True, "called", provider=cfg.provider),
    )
    result = provider.isolate("198.51.100.11", dry_run=False)
    assert result.success is False
    assert result.message == "approval_required"
    assert calls == []


def test_edr_real_call_uses_client_after_provider_approval():
    calls = []

    def client(op, ip, plan, cfg):
        calls.append((op, ip, plan, cfg))
        return IsolationResult(
            True,
            True,
            "isolated",
            provider=cfg.provider,
            recovery_hint="recover with edr_custom_webhook",
            meta={"provider_action_id": "pa-1"},
        )

    provider = CustomWebhookHostIsolationProvider(config=_edr_config(), client=client)
    with approved_response_execution():
        result = provider.isolate("198.51.100.12", dry_run=False)
    assert result.success is True
    assert calls[0][0] == "isolate_host"
    assert calls[0][2]["target_ip"] == "198.51.100.12"


def test_responder_rejects_real_host_isolation_without_c6_gate():
    calls = []
    provider = CustomWebhookHostIsolationProvider(
        config=_edr_config(),
        client=lambda op, ip, plan, cfg: calls.append((op, ip, plan, cfg))
        or IsolationResult(True, True, "isolated", provider=cfg.provider),
    )
    responder = SecurityResponder(dry_run=False, isolation=provider)
    responder.execute_approved_host_isolation(
        "198.51.100.13",
        requested_by="analyst-a",
        approved_by="lead-b",
        reason="confirmed critical compromise",
        recovery_drill_passed=True,
        provider_test_passed=True,
    )
    assert calls == []
    rows = [x for x in responder.response_actions if x.get("action") == "isolate_host"]
    assert rows[-1]["status"] == STATUS_REJECTED
    assert "real_enforcement_gate_required" in rows[-1]["reason"]


def test_responder_executes_real_host_isolation_only_after_strict_gate(monkeypatch):
    _set_real_enforcement_env(monkeypatch)
    calls = []

    def client(op, ip, plan, cfg):
        calls.append((op, ip, plan, cfg))
        return IsolationResult(
            True,
            True,
            "isolated",
            provider=cfg.provider,
            recovery_hint="use edr_custom_webhook unisolate/recover workflow",
            meta={"provider_action_id": "pa-2"},
        )

    provider = CustomWebhookHostIsolationProvider(config=_edr_config(), client=client)
    responder = SecurityResponder(
        dry_run=False,
        isolation=provider,
        real_enforcement_gate="real-enforcement",
    )
    responder.execute_approved_host_isolation(
        "198.51.100.14",
        requested_by="analyst-a",
        approved_by="lead-b",
        reason="confirmed critical compromise",
        recovery_drill_passed=True,
        provider_test_passed=True,
        alert_id="alert-2",
    )
    rows = [x for x in responder.response_actions if x.get("action") == "isolate_host"]
    assert rows[-1]["status"] == STATUS_EXECUTED
    assert rows[-1]["provider"] == "edr_custom_webhook"
    assert "unisolate/recover" in rows[-1]["recovery_hint"]
    assert calls[0][2]["approved_by"] == "lead-b"
