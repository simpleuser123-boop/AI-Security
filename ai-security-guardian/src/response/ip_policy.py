"""
生产封禁 IP 策略：非法、保留、白名单与本地地址一律不得触发真实防火墙动作。
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from typing import FrozenSet, Optional, Set

from src.response.ip_validate import validate_ip

# 复用 responder 的 IPv4 严格格式校验；本模块在其之上叠加路由/业务语义。


def _parse_csv_ips(raw: str) -> FrozenSet[str]:
    out: Set[str] = set()
    for part in (raw or "").split(","):
        s = part.strip()
        if s and validate_ip(s):
            out.add(s)
    return frozenset(out)


def _reserved_or_special(addr: ipaddress.IPv4Address) -> bool:
    if addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return True
    if int(addr) == 0:
        return True
    # 文档网段（RFC 5737）允许演练封禁，不作为“非法”，但也不建议生产当真实攻击源
    return False


def _is_rfc1918_or_carrier(addr: ipaddress.IPv4Address) -> bool:
    nets = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    )
    return any(addr in n for n in nets)


@dataclass(frozen=True)
class BanEligibility:
    """是否允许执行真实封禁（iptables 等）。"""

    allowed: bool
    reason: str = ""

    @property
    def rejection_reason(self) -> str:
        return self.reason if not self.allowed else ""


def load_business_whitelist_from_env() -> FrozenSet[str]:
    return _parse_csv_ips(os.environ.get("RESPONSE_BUSINESS_IP_WHITELIST", ""))


def load_private_whitelist_from_env() -> FrozenSet[str]:
    """显式私网/内网资产白名单：命中则禁止自动封禁（防误伤）。"""
    return _parse_csv_ips(os.environ.get("RESPONSE_PRIVATE_IP_WHITELIST", ""))


def check_real_ban_eligibility(
    ip: str,
    *,
    business_whitelist: Optional[FrozenSet[str]] = None,
    private_whitelist: Optional[FrozenSet[str]] = None,
    allow_private_ban: Optional[bool] = None,
) -> BanEligibility:
    """
    生产真实封禁前校验。

    - 非法 IPv4 -> 拒绝
    - 回环、链路本地 -> 拒绝
    - 业务白名单命中 -> 拒绝
    - 私网白名单命中 -> 拒绝
    - RFC1918/CGNAT 等私网地址：默认拒绝（可通过 RESPONSE_ALLOW_PRIVATE_BAN=true 放开，仅限实验）
    """
    if not isinstance(ip, str) or not ip.strip():
        return BanEligibility(False, "missing_source_ip")
    s = ip.strip()
    if not validate_ip(s):
        return BanEligibility(False, "invalid_ipv4_format")

    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return BanEligibility(False, "invalid_ipv4_format")

    if not isinstance(addr, ipaddress.IPv4Address):
        return BanEligibility(False, "not_ipv4")

    if _reserved_or_special(addr):
        return BanEligibility(False, "reserved_or_localhost")

    biz = business_whitelist if business_whitelist is not None else load_business_whitelist_from_env()
    if s in biz:
        return BanEligibility(False, "business_whitelist")

    priv = private_whitelist if private_whitelist is not None else load_private_whitelist_from_env()
    if s in priv:
        return BanEligibility(False, "private_ip_whitelist")

    allow_priv = (
        allow_private_ban
        if allow_private_ban is not None
        else os.environ.get("RESPONSE_ALLOW_PRIVATE_BAN", "").lower() == "true"
    )
    if _is_rfc1918_or_carrier(addr) and not allow_priv:
        return BanEligibility(False, "private_or_cgnat_range")

    return BanEligibility(True, "")
