"""Cloud security-group FirewallManager providers for controlled C6 response."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from src.response.ip_validate import validate_ip

logger = logging.getLogger(__name__)

SUPPORTED_CLOUD_SG_PROVIDERS = {
    "aliyun_security_group",
    "tencent_security_group",
    "aws_security_group",
    "huawei_security_group",
}

_DEFAULT_TENANT_ID = "default"
_DEFAULT_RESPONSE_ACTION_ID = "unbound"


@dataclass(frozen=True)
class CloudSecurityGroupConfig:
    """Non-secret cloud security-group configuration.

    Credentials are intentionally represented only by a reference. The actual
    secret must come from the customer's secret manager or runtime environment.
    """

    provider: str
    tenant_id: str = _DEFAULT_TENANT_ID
    allowed_security_group_ids: List[str] = field(default_factory=list)
    target_security_group_ids: List[str] = field(default_factory=list)
    region: Optional[str] = None
    credential_ref: Optional[str] = None
    response_action_id: str = _DEFAULT_RESPONSE_ACTION_ID

    @property
    def configured(self) -> bool:
        return (
            self.provider in SUPPORTED_CLOUD_SG_PROVIDERS
            and bool(self.tenant_id.strip())
            and bool(self.credential_ref and self.credential_ref.strip())
            and bool(self.allowed_security_group_ids)
            and bool(self.target_security_group_ids)
        )

    @property
    def guardian_marker(self) -> str:
        tenant = self.tenant_id.strip() or _DEFAULT_TENANT_ID
        rid = str(self.response_action_id or _DEFAULT_RESPONSE_ACTION_ID).strip()
        return f"guardian:{tenant}:{rid or _DEFAULT_RESPONSE_ACTION_ID}"

    def safe_meta(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "tenant_id": self.tenant_id,
            "region": self.region,
            "credential_ref": self.credential_ref,
            "allowed_security_group_ids": list(self.allowed_security_group_ids),
            "target_security_group_ids": list(self.target_security_group_ids),
            "guardian_marker": self.guardian_marker,
        }


def _split_csv(raw: str) -> List[str]:
    return [x.strip() for x in (raw or "").split(",") if x.strip()]


def cloud_sg_config_from_env(provider: str) -> CloudSecurityGroupConfig:
    """Build provider config from env without reading or persisting secrets."""

    target_sgs = _split_csv(os.environ.get("RESPONSE_CLOUD_SG_TARGET_IDS", ""))
    allowed_sgs = _split_csv(os.environ.get("RESPONSE_CLOUD_SG_ALLOWED_IDS", ""))
    if not allowed_sgs:
        # A target group is still not enough for real calls unless explicitly
        # authorized; keeping this empty makes misconfiguration fail closed.
        allowed_sgs = _split_csv(os.environ.get("RESPONSE_CLOUD_SG_AUTHORIZED_IDS", ""))
    return CloudSecurityGroupConfig(
        provider=provider,
        tenant_id=(
            os.environ.get("RESPONSE_CLOUD_SG_TENANT_ID")
            or os.environ.get("RESPONSE_WORKER_TENANT_ID")
            or _DEFAULT_TENANT_ID
        ).strip(),
        allowed_security_group_ids=allowed_sgs,
        target_security_group_ids=target_sgs,
        region=(os.environ.get("RESPONSE_CLOUD_SG_REGION") or "").strip() or None,
        credential_ref=(os.environ.get("RESPONSE_CLOUD_SG_CREDENTIAL_REF") or "").strip() or None,
        response_action_id=(
            os.environ.get("RESPONSE_CLOUD_SG_RESPONSE_ACTION_ID")
            or _DEFAULT_RESPONSE_ACTION_ID
        ).strip(),
    )


def make_cloud_sg_plan(
    *,
    operation: str,
    ip: str,
    config: CloudSecurityGroupConfig,
) -> Dict[str, Any]:
    cidr = f"{ip.strip()}/32"
    return {
        "operation": operation,
        "provider": config.provider,
        "region": config.region,
        "security_group_ids": list(config.target_security_group_ids),
        "cidr": cidr,
        "direction": "ingress",
        "action": "drop",
        "protocol": "all",
        "marker": config.guardian_marker,
        "description": config.guardian_marker,
        "credential_ref": config.credential_ref,
    }


@dataclass
class CloudSecurityGroupApiResult:
    ok: bool
    message: str
    provider_rule_ids: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


CloudSecurityGroupClient = Callable[[Dict[str, Any], CloudSecurityGroupConfig], CloudSecurityGroupApiResult]


class CloudSecurityGroupProviderMixin:
    """Shared cloud SG provider behavior used by FirewallManager adapters."""

    provider_name: str

    def __init__(
        self,
        config: Optional[CloudSecurityGroupConfig] = None,
        *,
        api_client: Optional[CloudSecurityGroupClient] = None,
    ) -> None:
        self.config = config or cloud_sg_config_from_env(self.provider_name)
        self._api_client = api_client

    def _validate_common(self, ip: str, *, dry_run: bool) -> Optional[Dict[str, Any]]:
        if not validate_ip(ip):
            return {"ok": False, "message": "invalid_ip"}
        if not self.config.configured:
            return {
                "ok": False,
                "message": "provider_not_configured",
                "meta": {"provider_config": self.config.safe_meta()},
            }
        unauthorized = [
            sg
            for sg in self.config.target_security_group_ids
            if sg not in self.config.allowed_security_group_ids
        ]
        if unauthorized:
            return {
                "ok": False,
                "message": "security_group_not_authorized",
                "meta": {"unauthorized_security_group_ids": unauthorized},
            }
        return None

    def _execute_cloud_plan(self, plan: Dict[str, Any]) -> CloudSecurityGroupApiResult:
        if self._api_client is None:
            return CloudSecurityGroupApiResult(False, "provider_sdk_not_configured")
        return self._api_client(plan, self.config)

    @staticmethod
    def command_from_plan(plan: Dict[str, Any]) -> List[str]:
        return ["cloud-security-group", json.dumps(plan, sort_keys=True, separators=(",", ":"))]
