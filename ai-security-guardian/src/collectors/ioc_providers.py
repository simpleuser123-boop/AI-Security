"""
外部威胁情报 Provider 接口与实现。

- 已接入：AbuseIPDB（IP）、VirusTotal（IP / 域名 / URL / 文件哈希）
- 占位：Spamhaus、PhishTank、OpenPhish、NVD、CNVD（未配置时 ``not_configured`` 降级）
"""
from __future__ import annotations

import base64
import logging
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

#: 与 threat_intel 中域名校验保持一致风格（子集）
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_HASH_RE = re.compile(r"^[a-f0-9]{32,128}$", re.IGNORECASE)


def not_configured(provider: str) -> Dict[str, Any]:
    return {
        "ok": False,
        "provider": provider,
        "reason": "not_configured",
        "is_malicious": False,
    }


class IOCProvider(ABC):
    """统一查询接口：按 ioc_type + value 返回结构化结果（不得包含密钥）。"""

    name: str

    @abstractmethod
    def query(self, ioc_type: str, value: str, *, timeout: float) -> Dict[str, Any]:
        raise NotImplementedError


class PlaceholderIOCProvider(IOCProvider):
    """预留第三方：仅配置占位与降级。"""

    def __init__(self, name: str) -> None:
        self.name = name

    def query(self, ioc_type: str, value: str, *, timeout: float) -> Dict[str, Any]:
        return not_configured(self.name)


class AbuseIPDBProvider(IOCProvider):
    name = "abuseipdb"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key or ""

    def query(self, ioc_type: str, value: str, *, timeout: float) -> Dict[str, Any]:
        if ioc_type != "ip":
            return {
                "ok": False,
                "provider": self.name,
                "reason": "unsupported_type",
                "is_malicious": False,
            }
        if not self._api_key:
            return {**not_configured(self.name), "reason": "api_key_missing"}
        ip = value.strip()
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self._api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30, "verbose": ""},
                timeout=timeout,
            )
            resp.raise_for_status()
            data = (resp.json() or {}).get("data", {})
        except requests.exceptions.Timeout:
            logger.error("[IOC] AbuseIPDB 查询超时")
            return {
                "ok": False,
                "provider": self.name,
                "reason": "timeout",
                "is_malicious": False,
            }
        except requests.exceptions.RequestException as exc:
            logger.error("[IOC] AbuseIPDB 查询失败: %s", exc)
            return {
                "ok": False,
                "provider": self.name,
                "reason": "request_error",
                "is_malicious": False,
            }
        except ValueError as exc:
            logger.error("[IOC] AbuseIPDB 响应解析失败: %s", exc)
            return {
                "ok": False,
                "provider": self.name,
                "reason": "parse_error",
                "is_malicious": False,
            }

        score = int(data.get("abuseConfidenceScore", 0) or 0)
        malicious = score >= 50
        return {
            "ok": True,
            "provider": self.name,
            "is_malicious": malicious,
            "score": score,
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
        }


class VirusTotalProvider(IOCProvider):
    name = "virustotal"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key or ""

    @staticmethod
    def _url_to_vt_id(url: str) -> str:
        """VirusTotal v3 ``/urls/{id}`` 使用 URL 的 urlsafe base64（无 padding）。"""
        return base64.urlsafe_b64encode(url.strip().encode("utf-8")).decode("ascii").rstrip("=")

    @classmethod
    def _vt_url(cls, ioc_type: str, value: str) -> Optional[str]:
        v = value.strip()
        t = ioc_type.lower()
        if t == "ip":
            return f"https://www.virustotal.com/api/v3/ip_addresses/{v}"
        if t == "domain":
            return f"https://www.virustotal.com/api/v3/domains/{v.lower()}"
        if t == "url":
            return f"https://www.virustotal.com/api/v3/urls/{cls._url_to_vt_id(v)}"
        if t == "file_hash":
            return f"https://www.virustotal.com/api/v3/files/{v.lower()}"
        if t == "cve":
            return f"https://www.virustotal.com/api/v3/cve/{v.upper()}"
        return None

    @staticmethod
    def _validate(ioc_type: str, value: str) -> Tuple[bool, str]:
        t = ioc_type.lower()
        v = value.strip()
        if t == "ip":
            parts = v.split(".")
            if len(parts) != 4:
                return False, "invalid_ip_format"
            try:
                ok = all(0 <= int(p) <= 255 and p == str(int(p)) for p in parts)
            except ValueError:
                ok = False
            return ok, "invalid_ip_format"
        if t == "domain":
            return bool(_DOMAIN_RE.match(v)), "invalid_domain_format"
        if t == "url":
            return v.startswith(("http://", "https://")), "invalid_url_format"
        if t == "file_hash":
            return bool(_HASH_RE.match(v)), "invalid_hash_format"
        if t == "cve":
            return bool(_CVE_RE.match(v)), "invalid_cve_format"
        return False, "unsupported_type"

    def query(self, ioc_type: str, value: str, *, timeout: float) -> Dict[str, Any]:
        if not self._api_key:
            return {**not_configured(self.name), "reason": "api_key_missing"}
        ok, reason = self._validate(ioc_type, value)
        if not ok:
            return {"ok": False, "provider": self.name, "reason": reason, "is_malicious": False}
        url = self._vt_url(ioc_type, value)
        if not url:
            return {"ok": False, "provider": self.name, "reason": "unsupported_type", "is_malicious": False}
        try:
            resp = requests.get(
                url,
                headers={"x-apikey": self._api_key, "Accept": "application/json"},
                timeout=timeout,
            )
            resp.raise_for_status()
            attrs = (resp.json() or {}).get("data", {}).get("attributes", {}) or {}
        except requests.exceptions.Timeout:
            logger.error("[IOC] VirusTotal 查询超时")
            return {
                "ok": False,
                "provider": self.name,
                "reason": "timeout",
                "is_malicious": False,
            }
        except requests.exceptions.RequestException as exc:
            logger.error("[IOC] VirusTotal 查询失败: %s", exc)
            return {
                "ok": False,
                "provider": self.name,
                "reason": "request_error",
                "is_malicious": False,
            }
        except ValueError as exc:
            logger.error("[IOC] VirusTotal 响应解析失败: %s", exc)
            return {
                "ok": False,
                "provider": self.name,
                "reason": "parse_error",
                "is_malicious": False,
            }

        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0) or 0)
        reputation = int(attrs.get("reputation", 0) or 0)
        is_malicious = malicious >= 3
        out: Dict[str, Any] = {
            "ok": True,
            "provider": self.name,
            "is_malicious": is_malicious,
            "malicious": malicious,
            "suspicious": int(stats.get("suspicious", 0) or 0),
            "harmless": int(stats.get("harmless", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
            "reputation": reputation,
        }
        if ioc_type == "ip":
            out.update(
                {
                    "score": min(100, malicious * 10) if malicious else malicious,
                    "country": attrs.get("country"),
                    "as_owner": attrs.get("as_owner"),
                    "network": attrs.get("network"),
                }
            )
        elif ioc_type == "domain":
            out.update(
                {
                    "score": min(100, malicious * 10) if malicious else malicious,
                    "categories": attrs.get("categories") or {},
                    "registrar": attrs.get("registrar"),
                }
            )
        else:
            out["score"] = min(100, malicious * 10) if malicious else malicious
        return out


def build_default_provider_registry(
    *,
    abuseipdb_key: str,
    virustotal_key: str,
) -> Dict[str, IOCProvider]:
    """name -> provider，含占位实现。"""
    return {
        "abuseipdb": AbuseIPDBProvider(abuseipdb_key),
        "virustotal": VirusTotalProvider(virustotal_key),
        "spamhaus": PlaceholderIOCProvider("spamhaus"),
        "phishtank": PlaceholderIOCProvider("phishtank"),
        "openphish": PlaceholderIOCProvider("openphish"),
        "nvd": PlaceholderIOCProvider("nvd"),
        "cnvd": PlaceholderIOCProvider("cnvd"),
    }
