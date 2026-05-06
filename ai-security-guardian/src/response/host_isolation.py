"""
主机隔离 Provider：未配置时由上层降级为人工待办。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import logging
from typing import Optional

from src.response.firewall import is_approved_response_execution
from src.response.ip_validate import validate_ip

logger = logging.getLogger(__name__)


@dataclass
class IsolationResult:
    attempted: bool
    success: bool
    message: str


class HostIsolationProvider(ABC):
    @abstractmethod
    def isolate(self, ip: str, *, dry_run: bool) -> IsolationResult:
        ...


class NullHostIsolationProvider(HostIsolationProvider):
    """未配置：不执行隔离，由响应层写入人工待办。"""

    def isolate(self, ip: str, *, dry_run: bool) -> IsolationResult:
        return IsolationResult(False, False, "provider_not_configured")


class LoggingHostIsolationProvider(HostIsolationProvider):
    """联调占位：仅打 critical 日志，表示“将调用外部隔离 API”。"""

    def isolate(self, ip: str, *, dry_run: bool) -> IsolationResult:
        if not validate_ip(ip):
            return IsolationResult(True, False, "invalid_ip")
        ip = ip.strip()
        if dry_run:
            logger.critical("[DRY RUN][隔离] 将请求隔离主机: %s", ip)
            return IsolationResult(True, True, "dry_run_logged")
        if not is_approved_response_execution():
            logger.error("[审批] 拒绝未审批的真实主机隔离调用: %s", ip)
            return IsolationResult(True, False, "approval_required")
        logger.critical("[隔离] 已请求隔离主机（占位实现）: %s", ip)
        return IsolationResult(True, True, "logged_placeholder")


def host_isolation_from_env() -> HostIsolationProvider:
    """
    RESPONSE_HOST_ISOLATION=none|logging

    未来可扩展为 edr | aws_ssm 等，需显式配置，默认 none。
    """
    import os

    mode = os.environ.get("RESPONSE_HOST_ISOLATION", "none").strip().lower()
    if mode in ("logging", "placeholder", "log"):
        return LoggingHostIsolationProvider()
    return NullHostIsolationProvider()
