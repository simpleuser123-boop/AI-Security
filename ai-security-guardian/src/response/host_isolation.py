"""
主机隔离 Provider：未配置时由上层降级为人工待办。

C6 keeps EDR isolation as a controlled capability. The provider layer is
deliberately plan-first: dry-run never calls EDR, and real calls require the
responder gate plus the approved execution context.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import logging
from typing import Any, Callable, Dict, Optional

from src.response.firewall import is_approved_response_execution
from src.response.ip_validate import validate_ip

logger = logging.getLogger(__name__)

SUPPORTED_HOST_ISOLATION_PROVIDERS = {
    "edr_custom_webhook",
    "edr_crowdstrike",
    "edr_defender",
    "edr_sentinelone",
}


@dataclass
class IsolationResult:
    attempted: bool
    success: bool
    message: str
    provider: str = "none"
    recovery_hint: str = "manual EDR recovery required"
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HostIsolationConfig:
    provider: str
    tenant_id: str = "default"
    credential_ref: Optional[str] = None
    endpoint: Optional[str] = None
    provider_test_passed: bool = False
    recovery_drill_passed: bool = False

    @property
    def configured(self) -> bool:
        if self.provider not in SUPPORTED_HOST_ISOLATION_PROVIDERS:
            return False
        if not (self.credential_ref and self.credential_ref.strip()):
            return False
        if self.provider == "edr_custom_webhook" and not (self.endpoint and self.endpoint.strip()):
            return False
        return True

    def safe_meta(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "tenant_id": self.tenant_id,
            "credential_ref": self.credential_ref,
            "endpoint_configured": bool(self.endpoint and self.endpoint.strip()),
            "provider_test_passed": self.provider_test_passed,
            "recovery_drill_passed": self.recovery_drill_passed,
        }


EdrClient = Callable[[str, str, Dict[str, Any], HostIsolationConfig], IsolationResult]


class HostIsolationProvider(ABC):
    provider_name = "none"

    @abstractmethod
    def isolate(
        self, ip: str, *, dry_run: bool, context: Optional[Dict[str, Any]] = None
    ) -> IsolationResult:
        ...

    @abstractmethod
    def unisolate(
        self, ip: str, *, dry_run: bool, context: Optional[Dict[str, Any]] = None
    ) -> IsolationResult:
        ...


class NullHostIsolationProvider(HostIsolationProvider):
    """未配置：不执行隔离，由响应层写入人工待办。"""

    provider_name = "none"

    def isolate(
        self, ip: str, *, dry_run: bool, context: Optional[Dict[str, Any]] = None
    ) -> IsolationResult:
        return IsolationResult(False, False, "provider_not_configured", provider=self.provider_name)

    def unisolate(
        self, ip: str, *, dry_run: bool, context: Optional[Dict[str, Any]] = None
    ) -> IsolationResult:
        return IsolationResult(False, False, "provider_not_configured", provider=self.provider_name)


class LoggingHostIsolationProvider(HostIsolationProvider):
    """联调占位：只记录计划，不调用真实 EDR。"""

    provider_name = "logging"

    def isolate(
        self, ip: str, *, dry_run: bool, context: Optional[Dict[str, Any]] = None
    ) -> IsolationResult:
        if not validate_ip(ip):
            return IsolationResult(True, False, "invalid_ip", provider=self.provider_name)
        ip = ip.strip()
        if dry_run:
            logger.critical("[DRY RUN][隔离] 将请求隔离主机: %s", ip)
            return IsolationResult(
                True,
                True,
                "dry_run_logged",
                provider=self.provider_name,
                recovery_hint="placeholder only; no EDR recovery needed",
                meta={"plan_only": True},
            )
        if not is_approved_response_execution():
            logger.error("[审批] 拒绝未审批的真实主机隔离调用: %s", ip)
            return IsolationResult(True, False, "approval_required", provider=self.provider_name)
        logger.critical("[隔离] 已请求隔离主机（占位实现）: %s", ip)
        return IsolationResult(
            True,
            True,
            "logged_placeholder",
            provider=self.provider_name,
            recovery_hint="placeholder only; no EDR recovery needed",
            meta={"plan_only": True},
        )

    def unisolate(
        self, ip: str, *, dry_run: bool, context: Optional[Dict[str, Any]] = None
    ) -> IsolationResult:
        if not validate_ip(ip):
            return IsolationResult(True, False, "invalid_ip", provider=self.provider_name)
        if not dry_run and not is_approved_response_execution():
            return IsolationResult(True, False, "approval_required", provider=self.provider_name)
        msg = "dry_run_recovery_logged" if dry_run else "logged_recovery_placeholder"
        logger.critical("[恢复][%s] 将恢复主机隔离: %s", self.provider_name, ip.strip())
        return IsolationResult(
            True,
            True,
            msg,
            provider=self.provider_name,
            recovery_hint="placeholder only; confirm host network state manually",
            meta={"plan_only": True},
        )


class EdrHostIsolationProvider(HostIsolationProvider):
    """C6 EDR adapter shell.

    Real SDK/webhook clients are injected per customer project. Without an
    injected client, non-dry-run returns provider_sdk_not_configured and never
    pretends isolation succeeded.
    """

    def __init__(
        self,
        provider_name: str,
        config: Optional[HostIsolationConfig] = None,
        *,
        client: Optional[EdrClient] = None,
    ) -> None:
        if provider_name not in SUPPORTED_HOST_ISOLATION_PROVIDERS:
            raise ValueError(f"unsupported host isolation provider: {provider_name}")
        self.provider_name = provider_name
        self.config = config or host_isolation_config_from_env(provider_name)
        self._client = client

    def _validate(self, ip: str) -> Optional[IsolationResult]:
        if not validate_ip(ip):
            return IsolationResult(True, False, "invalid_ip", provider=self.provider_name)
        if not self.config.configured:
            return IsolationResult(
                False,
                False,
                "provider_not_configured",
                provider=self.provider_name,
                recovery_hint="create manual EDR ticket; provider config is incomplete",
                meta={"provider_config": self.config.safe_meta()},
            )
        if not self.config.provider_test_passed:
            return IsolationResult(
                True,
                False,
                "provider_test_required",
                provider=self.provider_name,
                recovery_hint="run provider validate/test before enabling isolation",
                meta={"provider_config": self.config.safe_meta()},
            )
        return None

    def _plan(self, operation: str, ip: str, context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        ctx = dict(context or {})
        return {
            "operation": operation,
            "provider": self.provider_name,
            "tenant_id": self.config.tenant_id,
            "target_ip": ip.strip(),
            "target_host_id": ctx.get("host_id"),
            "alert_id": ctx.get("alert_id"),
            "approval_id": ctx.get("approval_id"),
            "requested_by": ctx.get("requested_by"),
            "approved_by": ctx.get("approved_by"),
            "second_approver": ctx.get("second_approver"),
            "recovery_hint": self.recovery_hint(operation),
        }

    def recovery_hint(self, operation: str = "isolate_host") -> str:
        if operation == "unisolate_host":
            return f"verify {self.provider_name} host is released and endpoint telemetry resumes"
        return f"use {self.provider_name} unisolate/recover workflow before closing incident"

    def isolate(
        self, ip: str, *, dry_run: bool, context: Optional[Dict[str, Any]] = None
    ) -> IsolationResult:
        validation = self._validate(ip)
        if validation is not None:
            return validation
        ip = ip.strip()
        plan = self._plan("isolate_host", ip, context)
        if dry_run:
            logger.info("[DRY RUN][%s] EDR 隔离计划: %s", self.provider_name, plan)
            return IsolationResult(
                True,
                True,
                "dry_run_plan",
                provider=self.provider_name,
                recovery_hint=self.recovery_hint("isolate_host"),
                meta={"plan": plan, "provider_config": self.config.safe_meta()},
            )
        if not is_approved_response_execution():
            return IsolationResult(True, False, "approval_required", provider=self.provider_name)
        if self._client is None:
            return IsolationResult(
                True,
                False,
                "provider_sdk_not_configured",
                provider=self.provider_name,
                recovery_hint=self.recovery_hint("isolate_host"),
                meta={"plan": plan},
            )
        return self._client("isolate_host", ip, plan, self.config)

    def unisolate(
        self, ip: str, *, dry_run: bool, context: Optional[Dict[str, Any]] = None
    ) -> IsolationResult:
        validation = self._validate(ip)
        if validation is not None:
            return validation
        ip = ip.strip()
        plan = self._plan("unisolate_host", ip, context)
        if dry_run:
            return IsolationResult(
                True,
                True,
                "dry_run_recovery_plan",
                provider=self.provider_name,
                recovery_hint=self.recovery_hint("unisolate_host"),
                meta={"plan": plan, "provider_config": self.config.safe_meta()},
            )
        if not is_approved_response_execution():
            return IsolationResult(True, False, "approval_required", provider=self.provider_name)
        if self._client is None:
            return IsolationResult(
                True,
                False,
                "provider_sdk_not_configured",
                provider=self.provider_name,
                recovery_hint=self.recovery_hint("unisolate_host"),
                meta={"plan": plan},
            )
        return self._client("unisolate_host", ip, plan, self.config)


class CustomWebhookHostIsolationProvider(EdrHostIsolationProvider):
    def __init__(
        self,
        config: Optional[HostIsolationConfig] = None,
        *,
        client: Optional[EdrClient] = None,
    ) -> None:
        super().__init__("edr_custom_webhook", config=config, client=client)


class CrowdStrikeHostIsolationProvider(EdrHostIsolationProvider):
    def __init__(
        self,
        config: Optional[HostIsolationConfig] = None,
        *,
        client: Optional[EdrClient] = None,
    ) -> None:
        super().__init__("edr_crowdstrike", config=config, client=client)


class DefenderHostIsolationProvider(EdrHostIsolationProvider):
    def __init__(
        self,
        config: Optional[HostIsolationConfig] = None,
        *,
        client: Optional[EdrClient] = None,
    ) -> None:
        super().__init__("edr_defender", config=config, client=client)


class SentinelOneHostIsolationProvider(EdrHostIsolationProvider):
    def __init__(
        self,
        config: Optional[HostIsolationConfig] = None,
        *,
        client: Optional[EdrClient] = None,
    ) -> None:
        super().__init__("edr_sentinelone", config=config, client=client)


def _env_bool(raw: Optional[str]) -> bool:
    return str(raw or "").strip().lower() in {"1", "true", "yes", "y", "on", "passed"}


def host_isolation_config_from_env(provider: str) -> HostIsolationConfig:
    import os

    return HostIsolationConfig(
        provider=provider,
        tenant_id=(
            os.environ.get("RESPONSE_HOST_ISOLATION_TENANT_ID")
            or os.environ.get("RESPONSE_WORKER_TENANT_ID")
            or "default"
        ).strip(),
        credential_ref=(os.environ.get("RESPONSE_HOST_ISOLATION_CREDENTIAL_REF") or "").strip()
        or None,
        endpoint=(os.environ.get("RESPONSE_HOST_ISOLATION_ENDPOINT") or "").strip() or None,
        provider_test_passed=_env_bool(
            os.environ.get("RESPONSE_HOST_ISOLATION_PROVIDER_TEST_PASSED")
        ),
        recovery_drill_passed=_env_bool(
            os.environ.get("RESPONSE_HOST_ISOLATION_RECOVERY_DRILL_PASSED")
        ),
    )


def host_isolation_from_env() -> HostIsolationProvider:
    """
    RESPONSE_HOST_ISOLATION=none|logging|placeholder|edr_custom_webhook|edr_crowdstrike|edr_defender|edr_sentinelone

    需显式配置，默认 none。
    """
    import os

    mode = os.environ.get("RESPONSE_HOST_ISOLATION", "none").strip().lower()
    if mode in ("logging", "placeholder", "log"):
        return LoggingHostIsolationProvider()
    if mode == "edr_custom_webhook":
        return CustomWebhookHostIsolationProvider()
    if mode == "edr_crowdstrike":
        return CrowdStrikeHostIsolationProvider()
    if mode == "edr_defender":
        return DefenderHostIsolationProvider()
    if mode == "edr_sentinelone":
        return SentinelOneHostIsolationProvider()
    return NullHostIsolationProvider()
