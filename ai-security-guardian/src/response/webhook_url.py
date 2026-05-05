"""
Webhook URL 防 SSRF：禁止本地、链路本地与云元数据常见地址。
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlparse


@dataclass(frozen=True)
class WebhookUrlCheck:
    ok: bool
    reason: str = ""


def _is_blocked_ip(addr: ipaddress._BaseAddress) -> bool:
    if isinstance(addr, ipaddress.IPv4Address):
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
            return True
        if addr == ipaddress.IPv4Address("0.0.0.0"):
            return True
        # 云元数据（常见 IPv4）
        if addr in ipaddress.ip_network("169.254.169.254/32"):
            return True
        # 典型内网（Webhook 不应指向内网服务）
        blocked_nets = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
            ipaddress.ip_network("100.64.0.0/10"),
            ipaddress.ip_network("0.0.0.0/8"),
        )
        return any(addr in n for n in blocked_nets)
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.is_loopback or addr.is_link_local or addr.is_multicast:
            return True
        if addr == ipaddress.IPv6Address("::1"):
            return True
        if addr in ipaddress.ip_network("fe80::/10"):
            return True
        # AWS/GCP 等 IPv6 元数据（占位，保守拒绝 ULA 与未指定）
        if addr in ipaddress.ip_network("fd00::/8"):
            return True
    return False


def check_webhook_url_safe(url: str) -> WebhookUrlCheck:
    """
    解析 URL，校验 scheme/host，并对解析后的 IP 做 SSRF 防护。

    禁止：非 http(s)、localhost、127.0.0.0/8、169.254.169.254、内网网段、裸 IP字面量中的阻断段。
    """
    if not isinstance(url, str) or not url.strip():
        return WebhookUrlCheck(False, "empty_url")
    raw = url.strip()
    try:
        parsed = urlparse(raw)
    except Exception:  # noqa: BLE001
        return WebhookUrlCheck(False, "parse_error")

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return WebhookUrlCheck(False, "scheme_not_http")

    host = parsed.hostname
    if not host:
        return WebhookUrlCheck(False, "missing_host")

    host_lower = host.lower()
    if host_lower == "localhost" or host_lower.endswith(".localhost"):
        return WebhookUrlCheck(False, "localhost_forbidden")

    # 常见云元数据 / 内网解析名（不依赖 DNS 即可拒绝）
    _blocked_hostnames = frozenset(
        {
            "metadata.google.internal",
            "metadata.goog",
            "metadata",
            "kubernetes.default",
            "kubernetes.default.svc",
            "kubernetes.default.svc.cluster.local",
            "instance-data.ec2.internal",
        }
    )
    if host_lower in _blocked_hostnames:
        return WebhookUrlCheck(False, "blocked_hostname")

    # 直接 IPv4 / IPv6 字面量
    try:
        addr = ipaddress.ip_address(host)
        if _is_blocked_ip(addr):
            return WebhookUrlCheck(False, "blocked_ip_literal")
        return WebhookUrlCheck(True, "")
    except ValueError:
        pass

    # DNS 解析（仅校验首轮 A/AAAA；解析失败不视为“安全”，拒绝）
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return WebhookUrlCheck(False, "dns_resolution_failed")

    for _fam, _type, _proto, _canon, sockaddr in infos:
        ip_str: Optional[str] = None
        if len(sockaddr) >= 1 and isinstance(sockaddr[0], str):
            ip_str = sockaddr[0]
        if not ip_str:
            continue
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_blocked_ip(addr):
            return WebhookUrlCheck(False, f"resolved_to_blocked:{ip_str}")

    return WebhookUrlCheck(True, "")
