"""
FirewallManager 抽象：iptables 实现 + Windows / 云安全组占位。
"""
from __future__ import annotations

import logging
import subprocess
from contextlib import contextmanager
from contextvars import ContextVar
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional

from src.response.ip_validate import validate_ip
from src.response.cloud_security_group import (
    CloudSecurityGroupConfig,
    CloudSecurityGroupProviderMixin,
    SUPPORTED_CLOUD_SG_PROVIDERS,
    make_cloud_sg_plan,
)

logger = logging.getLogger(__name__)

_SUBPROCESS_TIMEOUT = 5
_APPROVED_EXECUTION_CONTEXT: ContextVar[bool] = ContextVar(
    "response_approved_execution_context", default=False
)


@dataclass
class FirewallResult:
    ok: bool
    dry_run: bool
    message: str
    command: Optional[List[str]] = None
    meta: Optional[Dict[str, Any]] = None


class FirewallManager(ABC):
    """统一封禁 / 解封接口。"""

    @abstractmethod
    def ban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        ...

    @abstractmethod
    def unban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        ...


@contextmanager
def approved_response_execution() -> Iterator[None]:
    """Allow one approved high-risk response operation to reach the provider."""
    token = _APPROVED_EXECUTION_CONTEXT.set(True)
    try:
        yield
    finally:
        _APPROVED_EXECUTION_CONTEXT.reset(token)


def _require_approved_execution(dry_run: bool, command: List[str]) -> Optional[FirewallResult]:
    if dry_run or _APPROVED_EXECUTION_CONTEXT.get():
        return None
    return FirewallResult(
        False,
        False,
        "approval_required",
        command=list(command),
    )


def is_approved_response_execution() -> bool:
    return _APPROVED_EXECUTION_CONTEXT.get()


class IptablesFirewallManager(FirewallManager):
    """Linux iptables（列表参数，禁止 shell=True）。"""

    def ban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        if not validate_ip(ip):
            return FirewallResult(False, dry_run, "invalid_ip")
        ip = ip.strip()
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        approval_error = _require_approved_execution(dry_run, cmd)
        if approval_error is not None:
            logger.error("[审批] 拒绝未审批的真实封禁调用: %s", " ".join(cmd))
            return approval_error
        if dry_run:
            logger.info("[DRY RUN][iptables] 将执行封禁（未真实调用）: %s", " ".join(cmd))
            return FirewallResult(True, True, "dry_run_no_subprocess", command=list(cmd))
        try:
            subprocess.run(
                cmd,
                check=True,
                timeout=_SUBPROCESS_TIMEOUT,
                capture_output=True,
            )
            return FirewallResult(True, False, "applied", command=list(cmd))
        except subprocess.CalledProcessError as exc:
            return FirewallResult(
                False, False, f"called_process_error:{exc.returncode}", command=list(cmd)
            )
        except subprocess.TimeoutExpired:
            return FirewallResult(False, False, "timeout", command=list(cmd))
        except FileNotFoundError:
            return FirewallResult(False, False, "iptables_not_found", command=list(cmd))

    def unban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        if not validate_ip(ip):
            return FirewallResult(False, dry_run, "invalid_ip")
        ip = ip.strip()
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        approval_error = _require_approved_execution(dry_run, cmd)
        if approval_error is not None:
            logger.error("[审批] 拒绝未审批的真实解封调用: %s", " ".join(cmd))
            return approval_error
        if dry_run:
            logger.info("[DRY RUN][iptables] 将执行解封（未真实调用）: %s", " ".join(cmd))
            return FirewallResult(True, True, "dry_run_no_subprocess", command=list(cmd))
        try:
            subprocess.run(
                cmd,
                check=True,
                timeout=_SUBPROCESS_TIMEOUT,
                capture_output=True,
            )
            return FirewallResult(True, False, "applied", command=list(cmd))
        except subprocess.CalledProcessError as exc:
            return FirewallResult(
                False, False, f"called_process_error:{exc.returncode}", command=list(cmd)
            )
        except subprocess.TimeoutExpired:
            return FirewallResult(False, False, "timeout", command=list(cmd))
        except FileNotFoundError:
            return FirewallResult(False, False, "iptables_not_found", command=list(cmd))


class WindowsFirewallPlaceholderManager(FirewallManager):
    """Windows 防火墙占位：仅记录审计意图，不执行 netsh。"""

    def ban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        if not validate_ip(ip):
            return FirewallResult(False, dry_run, "invalid_ip")
        if not dry_run and not _APPROVED_EXECUTION_CONTEXT.get():
            return FirewallResult(False, False, "approval_required")
        msg = "windows_firewall_placeholder_noop"
        logger.warning("[防火墙占位][Windows] ban %s (%s)", ip.strip(), msg)
        return FirewallResult(True, dry_run, msg)

    def unban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        if not validate_ip(ip):
            return FirewallResult(False, dry_run, "invalid_ip")
        if not dry_run and not _APPROVED_EXECUTION_CONTEXT.get():
            return FirewallResult(False, False, "approval_required")
        msg = "windows_firewall_placeholder_noop"
        logger.warning("[防火墙占位][Windows] unban %s (%s)", ip.strip(), msg)
        return FirewallResult(True, dry_run, msg)


class CloudSecurityGroupPlaceholderManager(FirewallManager):
    """云安全组 API 占位：不落真实规则。"""

    def ban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        if not validate_ip(ip):
            return FirewallResult(False, dry_run, "invalid_ip")
        if not dry_run and not _APPROVED_EXECUTION_CONTEXT.get():
            return FirewallResult(False, False, "approval_required")
        msg = "cloud_security_group_placeholder_noop"
        logger.warning("[防火墙占位][CloudSG] ban %s (%s)", ip.strip(), msg)
        return FirewallResult(
            True,
            dry_run,
            msg,
            command=["cloud-security-group-placeholder", "ban", ip.strip()],
            meta={"provider": "cloud_sg_placeholder", "plan_only": True},
        )

    def unban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        if not validate_ip(ip):
            return FirewallResult(False, dry_run, "invalid_ip")
        if not dry_run and not _APPROVED_EXECUTION_CONTEXT.get():
            return FirewallResult(False, False, "approval_required")
        msg = "cloud_security_group_placeholder_noop"
        logger.warning("[防火墙占位][CloudSG] unban %s (%s)", ip.strip(), msg)
        return FirewallResult(
            True,
            dry_run,
            msg,
            command=["cloud-security-group-placeholder", "unban", ip.strip()],
            meta={"provider": "cloud_sg_placeholder", "plan_only": True},
        )


class CloudSecurityGroupFirewallManager(CloudSecurityGroupProviderMixin, FirewallManager):
    """Cloud security-group provider adapter.

    The C6 implementation intentionally ships without real SDK calls by
    default. A production integration must inject a provider-specific client
    that enforces least privilege for the configured security groups.
    """

    provider_name = "cloud_security_group"

    def __init__(
        self,
        provider_name: str,
        config: Optional[CloudSecurityGroupConfig] = None,
        *,
        api_client=None,
    ) -> None:
        if provider_name not in SUPPORTED_CLOUD_SG_PROVIDERS:
            raise ValueError(f"unsupported cloud security group provider: {provider_name}")
        self.provider_name = provider_name
        super().__init__(config=config, api_client=api_client)

    def ban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        error = self._validate_common(ip, dry_run=dry_run)
        if error is not None:
            return FirewallResult(
                bool(error["ok"]),
                dry_run,
                str(error["message"]),
                meta=error.get("meta"),
            )
        ip = ip.strip()
        plan = make_cloud_sg_plan(operation="ban_input_drop", ip=ip, config=self.config)
        cmd = self.command_from_plan(plan)
        approval_error = _require_approved_execution(dry_run, cmd)
        if approval_error is not None:
            logger.error("[审批] 拒绝未审批的真实云安全组封禁调用: %s", plan)
            return FirewallResult(False, False, "approval_required", command=cmd, meta={"plan": plan})
        if dry_run:
            logger.info("[DRY RUN][%s] 云安全组封禁计划: %s", self.provider_name, plan)
            return FirewallResult(True, True, "dry_run_plan", command=cmd, meta={"plan": plan})
        api_result = self._execute_cloud_plan(plan)
        return FirewallResult(
            api_result.ok,
            False,
            api_result.message,
            command=cmd,
            meta={
                "plan": plan,
                "provider_rule_ids": list(api_result.provider_rule_ids),
                "provider_result": api_result.raw,
            },
        )

    def unban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        error = self._validate_common(ip, dry_run=dry_run)
        if error is not None:
            return FirewallResult(
                bool(error["ok"]),
                dry_run,
                str(error["message"]),
                meta=error.get("meta"),
            )
        ip = ip.strip()
        plan = make_cloud_sg_plan(operation="unban_input_drop", ip=ip, config=self.config)
        cmd = self.command_from_plan(plan)
        approval_error = _require_approved_execution(dry_run, cmd)
        if approval_error is not None:
            logger.error("[审批] 拒绝未审批的真实云安全组解封调用: %s", plan)
            return FirewallResult(False, False, "approval_required", command=cmd, meta={"plan": plan})
        if dry_run:
            logger.info("[DRY RUN][%s] 云安全组解封计划: %s", self.provider_name, plan)
            return FirewallResult(True, True, "dry_run_plan", command=cmd, meta={"plan": plan})
        api_result = self._execute_cloud_plan(plan)
        return FirewallResult(
            api_result.ok,
            False,
            api_result.message,
            command=cmd,
            meta={
                "plan": plan,
                "provider_rule_ids": list(api_result.provider_rule_ids),
                "provider_result": api_result.raw,
            },
        )


def firewall_manager_from_env() -> FirewallManager:
    """RESPONSE_FIREWALL_BACKEND=iptables|windows_placeholder|cloud_sg_placeholder|cloud providers"""
    import os

    kind = os.environ.get("RESPONSE_FIREWALL_BACKEND", "iptables").strip().lower()
    if kind == "windows_placeholder":
        return WindowsFirewallPlaceholderManager()
    if kind in ("cloud_sg_placeholder", "cloud_placeholder"):
        return CloudSecurityGroupPlaceholderManager()
    if kind in SUPPORTED_CLOUD_SG_PROVIDERS:
        return CloudSecurityGroupFirewallManager(kind)
    return IptablesFirewallManager()
