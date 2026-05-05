"""IPv4 严格格式校验（供响应层与 Web API 复用）。"""
from __future__ import annotations

import re

_IPV4_PATTERN: re.Pattern[str] = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def validate_ip(ip: str) -> bool:
    if not isinstance(ip, str):
        return False
    stripped = ip.strip()
    if not stripped:
        return False
    return bool(_IPV4_PATTERN.match(stripped))
