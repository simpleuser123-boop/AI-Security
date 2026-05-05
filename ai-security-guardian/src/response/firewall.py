"""
FirewallManager 抽象：iptables 实现 + Windows / 云安全组占位。
"""
from __future__ import annotations

import logging
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

from src.response.ip_validate import validate_ip

logger = logging.getLogger(__name__)

_SUBPROCESS_TIMEOUT = 5


@dataclass
class FirewallResult:
    ok: bool
    dry_run: bool
    message: str
    command: Optional[List[str]] = None


class FirewallManager(ABC):
    """统一封禁 / 解封接口。"""

    @abstractmethod
    def ban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        ...

    @abstractmethod
    def unban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        ...


class IptablesFirewallManager(FirewallManager):
    """Linux iptables（列表参数，禁止 shell=True）。"""

    def ban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        if not validate_ip(ip):
            return FirewallResult(False, dry_run, "invalid_ip")
        ip = ip.strip()
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
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
        msg = "windows_firewall_placeholder_noop"
        logger.warning("[防火墙占位][Windows] ban %s (%s)", ip.strip(), msg)
        return FirewallResult(True, dry_run, msg)

    def unban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        if not validate_ip(ip):
            return FirewallResult(False, dry_run, "invalid_ip")
        msg = "windows_firewall_placeholder_noop"
        logger.warning("[防火墙占位][Windows] unban %s (%s)", ip.strip(), msg)
        return FirewallResult(True, dry_run, msg)


class CloudSecurityGroupPlaceholderManager(FirewallManager):
    """云安全组 API 占位：不落真实规则。"""

    def ban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        if not validate_ip(ip):
            return FirewallResult(False, dry_run, "invalid_ip")
        msg = "cloud_security_group_placeholder_noop"
        logger.warning("[防火墙占位][CloudSG] ban %s (%s)", ip.strip(), msg)
        return FirewallResult(True, dry_run, msg)

    def unban_input_drop(self, ip: str, *, dry_run: bool) -> FirewallResult:
        if not validate_ip(ip):
            return FirewallResult(False, dry_run, "invalid_ip")
        msg = "cloud_security_group_placeholder_noop"
        logger.warning("[防火墙占位][CloudSG] unban %s (%s)", ip.strip(), msg)
        return FirewallResult(True, dry_run, msg)


def firewall_manager_from_env() -> FirewallManager:
    """RESPONSE_FIREWALL_BACKEND=iptables|windows_placeholder|cloud_sg_placeholder"""
    import os

    kind = os.environ.get("RESPONSE_FIREWALL_BACKEND", "iptables").strip().lower()
    if kind == "windows_placeholder":
        return WindowsFirewallPlaceholderManager()
    if kind in ("cloud_sg_placeholder", "cloud_placeholder"):
        return CloudSecurityGroupPlaceholderManager()
    return IptablesFirewallManager()
