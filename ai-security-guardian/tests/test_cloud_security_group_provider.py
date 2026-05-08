from __future__ import annotations

from datetime import timedelta

from src.response.cloud_security_group import (
    CloudSecurityGroupApiResult,
    CloudSecurityGroupConfig,
)
from src.response.firewall import (
    CloudSecurityGroupFirewallManager,
    IptablesFirewallManager,
    approved_response_execution,
    firewall_manager_from_env,
)
from src.response.responder import SecurityResponder


def _configured(provider: str = "aws_security_group") -> CloudSecurityGroupConfig:
    return CloudSecurityGroupConfig(
        provider=provider,
        tenant_id="tenant-a",
        allowed_security_group_ids=["sg-authorized"],
        target_security_group_ids=["sg-authorized"],
        region="ap-southeast-1",
        credential_ref="secret://customer-vault/cloud-sg/tenant-a",
        response_action_id="ra-123",
    )


def test_default_firewall_backend_remains_iptables(monkeypatch):
    monkeypatch.delenv("RESPONSE_FIREWALL_BACKEND", raising=False)
    assert isinstance(firewall_manager_from_env(), IptablesFirewallManager)


def test_cloud_provider_unconfigured_returns_provider_not_configured():
    fw = CloudSecurityGroupFirewallManager(
        "aliyun_security_group",
        config=CloudSecurityGroupConfig(provider="aliyun_security_group"),
    )
    res = fw.ban_input_drop("198.51.100.10", dry_run=True)
    assert res.ok is False
    assert res.message == "provider_not_configured"


def test_cloud_provider_dry_run_returns_plan_without_api_call():
    calls = []

    def api_client(plan, config):
        calls.append((plan, config))
        return CloudSecurityGroupApiResult(True, "applied")

    fw = CloudSecurityGroupFirewallManager(
        "tencent_security_group",
        config=_configured("tencent_security_group"),
        api_client=api_client,
    )
    res = fw.ban_input_drop("198.51.100.11", dry_run=True)
    assert res.ok is True
    assert res.message == "dry_run_plan"
    assert calls == []
    assert res.meta["plan"]["marker"] == "guardian:tenant-a:ra-123"
    assert res.meta["plan"]["security_group_ids"] == ["sg-authorized"]


def test_cloud_provider_rejects_unapproved_real_call():
    calls = []

    def api_client(plan, config):
        calls.append((plan, config))
        return CloudSecurityGroupApiResult(True, "applied")

    fw = CloudSecurityGroupFirewallManager(
        "aws_security_group",
        config=_configured("aws_security_group"),
        api_client=api_client,
    )
    res = fw.ban_input_drop("198.51.100.12", dry_run=False)
    assert res.ok is False
    assert res.message == "approval_required"
    assert calls == []


def test_cloud_provider_real_call_requires_authorized_security_group():
    calls = []
    config = CloudSecurityGroupConfig(
        provider="huawei_security_group",
        tenant_id="tenant-a",
        allowed_security_group_ids=["sg-allowed"],
        target_security_group_ids=["sg-denied"],
        region="cn-north-4",
        credential_ref="secret://customer-vault/cloud-sg/tenant-a",
        response_action_id="ra-456",
    )

    fw = CloudSecurityGroupFirewallManager(
        "huawei_security_group",
        config=config,
        api_client=lambda plan, cfg: calls.append((plan, cfg)) or CloudSecurityGroupApiResult(True, "applied"),
    )
    with approved_response_execution():
        res = fw.ban_input_drop("198.51.100.13", dry_run=False)
    assert res.ok is False
    assert res.message == "security_group_not_authorized"
    assert calls == []


def test_cloud_provider_real_call_uses_injected_client_after_approval():
    calls = []

    def api_client(plan, config):
        calls.append((plan, config))
        return CloudSecurityGroupApiResult(
            True,
            "applied",
            provider_rule_ids=["rule-1"],
            raw={"request_id": "req-1"},
        )

    fw = CloudSecurityGroupFirewallManager(
        "aws_security_group",
        config=_configured("aws_security_group"),
        api_client=api_client,
    )
    with approved_response_execution():
        res = fw.ban_input_drop("198.51.100.14", dry_run=False)
    assert res.ok is True
    assert calls
    assert res.meta["provider_rule_ids"] == ["rule-1"]
    assert res.meta["plan"]["description"] == "guardian:tenant-a:ra-123"


def test_responder_gate_still_blocks_cloud_provider_before_real_call(monkeypatch):
    monkeypatch.delenv("REAL_ENFORCEMENT_GATE", raising=False)
    calls = []
    fw = CloudSecurityGroupFirewallManager(
        "aws_security_group",
        config=_configured("aws_security_group"),
        api_client=lambda plan, cfg: calls.append((plan, cfg)) or CloudSecurityGroupApiResult(True, "applied"),
    )
    responder = SecurityResponder(dry_run=False, firewall=fw)
    responder.approve_ban_ip(
        "198.51.100.15",
        operator="analyst-a",
        reason="confirmed_abuse",
        duration=timedelta(minutes=5),
    )
    responder.execute_approved_ban_ip(
        "198.51.100.15",
        operator="analyst-a",
        reason="execute confirmed_abuse",
        duration=timedelta(minutes=5),
    )
    assert calls == []
    assert responder.response_actions[-1]["reason"] == "real_enforcement_gate_required"
