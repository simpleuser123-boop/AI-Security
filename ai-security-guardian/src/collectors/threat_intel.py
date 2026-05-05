"""
威胁情报采集器：本地/DB IOC 优先，外部 Provider 兜底（有界等待、不抛异常）。

- API Key 不得进入日志或返回值
- 外部查询在独立线程中执行，主调用 ``wait`` 超时则降级，后台线程仍可能更新缓存
- ``THREAT_INTEL_MOCK=true`` 时外部走确定性 mock（便于离线演示）
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set

from src.collectors.ioc_providers import (
    IOCProvider,
    build_default_provider_registry,
    not_configured,
)

logger = logging.getLogger(__name__)

_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

_IOC_TYPES = frozenset({"ip", "domain", "url", "file_hash", "cve"})


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _mock_hash_int(seed: str, mod: int, offset: int = 0) -> int:
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    num = int.from_bytes(digest[:8], "big")
    return (num % mod) + offset


def _mock_abuseipdb(ip: str) -> Dict[str, Any]:
    score = _mock_hash_int(f"abuseipdb:{ip}", 101)
    countries = ("US", "CN", "RU", "BR", "DE", "NL", "GB", "SG", "JP")
    isps = (
        "Mock Cloud Provider",
        "Fake Data Center, Inc.",
        "Demo Hosting LLC",
        "Sample ISP Holdings",
    )
    return {
        "ok": True,
        "provider": "abuseipdb",
        "mocked": True,
        "is_malicious": score >= 50,
        "score": score,
        "country_code": countries[_mock_hash_int(f"cc:{ip}", len(countries))],
        "usage_type": "Data Center/Web Hosting/Transit",
        "isp": isps[_mock_hash_int(f"isp:{ip}", len(isps))],
        "domain": None,
        "total_reports": _mock_hash_int(f"reports:{ip}", 500),
        "last_reported_at": _utc_now().isoformat(),
    }


def _mock_virustotal(ioc_type: str, value: str) -> Dict[str, Any]:
    seed = f"vt:{ioc_type}:{value.lower()}"
    malicious = _mock_hash_int(seed + ":mal", 20)
    suspicious = _mock_hash_int(seed + ":sus", 10)
    harmless = _mock_hash_int(seed + ":har", 50, offset=30)
    undetected = _mock_hash_int(seed + ":und", 20, offset=5)
    reputation = _mock_hash_int(seed + ":rep", 101, offset=-50)
    base: Dict[str, Any] = {
        "ok": True,
        "provider": "virustotal",
        "mocked": True,
        "is_malicious": malicious >= 3,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "reputation": reputation,
        "score": min(100, malicious * 10) if malicious else malicious,
    }
    if ioc_type == "ip":
        base.update(
            {
                "country": _mock_abuseipdb(value)["country_code"],
                "as_owner": "AS65535 Mock Networks",
                "network": ".".join(value.split(".")[:3]) + ".0/24",
            }
        )
    elif ioc_type == "domain":
        base.update(
            {
                "categories": {
                    "Mock Vendor": "malware" if malicious >= 3 else "business",
                },
                "registrar": "Mock Registrar Ltd.",
            }
        )
    return base


class ThreatIntelCollector:
    """威胁情报：内存缓存 + 可选 DB 会话工厂 + Provider 注册表。"""

    def __init__(
        self,
        abuseipdb_key: str = "",
        virustotal_key: str = "",
        *,
        external_http_timeout: Optional[float] = None,
        external_wait_sec: Optional[float] = None,
        db_session_factory: Optional[Callable[[], Any]] = None,
        mock_external: Optional[bool] = None,
    ) -> None:
        self.abuseipdb_key = abuseipdb_key
        self.virustotal_key = virustotal_key
        self.external_http_timeout = float(
            external_http_timeout
            if external_http_timeout is not None
            else os.environ.get("THREAT_INTEL_HTTP_TIMEOUT", "5")
        )
        self.external_wait_sec = float(
            external_wait_sec
            if external_wait_sec is not None
            else os.environ.get("THREAT_INTEL_EXTERNAL_WAIT_SEC", "0.45")
        )
        self._mock_external_override = mock_external
        self._db_session_factory = db_session_factory
        self._ti_flask_app: Any = None

        self._ip_blacklist: Set[str] = set()
        self._domain_blacklist: Set[str] = set()
        self._url_blacklist: Set[str] = set()
        self._hash_blacklist: Set[str] = set()
        self._cve_blacklist: Set[str] = set()

        self._last_update: Optional[datetime] = None
        self._cache_ttl: timedelta = timedelta(hours=1)

        self._lock = threading.Lock()
        self._request_interval: float = 1.0
        self._last_request_time: Optional[datetime] = None

        self._providers: Dict[str, IOCProvider] = build_default_provider_registry(
            abuseipdb_key=abuseipdb_key,
            virustotal_key=virustotal_key,
        )
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ti-ext")

    def set_db_session_factory(self, factory: Optional[Callable[[], Any]]) -> None:
        self._db_session_factory = factory

    def bind_flask_app(self, app: Any) -> None:
        """绑定 Flask 应用以便在 app_context 下访问 ``db.session``。"""
        self._ti_flask_app = app

    @contextmanager
    def _db_session_scope(self):
        if self._ti_flask_app is not None:
            with self._ti_flask_app.app_context():
                from web.database import db

                yield db.session
            return
        if self._db_session_factory:
            yield self._db_session_factory()
            return
        yield None

    def _use_mock_external(self) -> bool:
        if self._mock_external_override is not None:
            return bool(self._mock_external_override)
        return os.environ.get("THREAT_INTEL_MOCK", "").lower() == "true"

    # ------------------------------------------------------------------
    @staticmethod
    def _validate_ip(ip: str) -> bool:
        if not isinstance(ip, str) or not ip:
            return False
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 and p == str(int(p)) for p in parts)
        except ValueError:
            return False

    def _local_db_lookup(self, ioc_type: str, value: str) -> Optional[Dict[str, Any]]:
        try:
            from src.collectors.ioc_repository import IOCRepository

            with self._db_session_scope() as session:
                if session is None:
                    return None
                return IOCRepository(session).find_active_dict(ioc_type, value)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[ThreatIntel] DB 查询失败（降级）: %s", exc)
            return None

    def _memory_hit(self, ioc_type: str, value: str) -> bool:
        t = ioc_type.lower()
        v = value.strip()
        with self._lock:
            if t == "ip":
                return v in self._ip_blacklist
            if t == "domain":
                return v.lower() in self._domain_blacklist
            if t == "url":
                return v in self._url_blacklist
            if t == "file_hash":
                return v.lower() in self._hash_blacklist
            if t == "cve":
                return v.upper() in self._cve_blacklist
        return False

    def _add_memory(self, ioc_type: str, value: str) -> None:
        t = ioc_type.lower()
        v = value.strip()
        with self._lock:
            if t == "ip" and self._validate_ip(v):
                self._ip_blacklist.add(v)
            elif t == "domain":
                self._domain_blacklist.add(v.lower())
            elif t == "url":
                self._url_blacklist.add(v)
            elif t == "file_hash":
                self._hash_blacklist.add(v.lower())
            elif t == "cve":
                self._cve_blacklist.add(v.upper())

    def refresh_local_from_db(self, session: Optional[Any] = None) -> int:
        """从数据库加载未过期 IOC 到内存；传入 session 或已配置 factory。"""
        from src.collectors.ioc_repository import IOCRepository

        sess = session
        if sess is None:
            with self._db_session_scope() as s:
                sess = s
        if sess is None:
            return 0
        rows = IOCRepository(sess).list_active_dicts()
        with self._lock:
            self._ip_blacklist.clear()
            self._domain_blacklist.clear()
            self._url_blacklist.clear()
            self._hash_blacklist.clear()
            self._cve_blacklist.clear()
            for r in rows:
                self._add_memory(str(r["ioc_type"]), str(r["value"]))
        self._last_update = _utc_now()
        return len(rows)

    @staticmethod
    def _fuse_provider_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
        malicious = False
        max_score: Optional[int] = None
        sources: List[str] = []
        for r in results:
            if not r.get("ok"):
                continue
            if r.get("is_malicious") or r.get("hit"):
                malicious = True
                prov = str(r.get("provider", "unknown"))
                if prov not in sources:
                    sources.append(prov)
            sc = r.get("score")
            if isinstance(sc, (int, float)):
                si = int(sc)
                if max_score is None or si > max_score:
                    max_score = si
        return {
            "is_malicious": malicious,
            "score": max_score,
            "providers": sources,
        }

    def _query_external_parallel(
        self, ioc_type: str, value: str, provider_names: List[str]
    ) -> Dict[str, Any]:
        """线程池并行查询；在 ``external_wait_sec`` 内尽量收齐结果，超时则降级。"""
        if self._use_mock_external():
            out: List[Dict[str, Any]] = []
            if "abuseipdb" in provider_names and ioc_type == "ip":
                if self.abuseipdb_key:
                    out.append(
                        self._providers["abuseipdb"].query(
                            ioc_type, value, timeout=self.external_http_timeout
                        )
                    )
                else:
                    out.append(_mock_abuseipdb(value))
            if "virustotal" in provider_names:
                if self.virustotal_key:
                    out.append(
                        self._providers["virustotal"].query(
                            ioc_type, value, timeout=self.external_http_timeout
                        )
                    )
                else:
                    out.append(_mock_virustotal(ioc_type, value))
            for name in provider_names:
                if name in ("spamhaus", "phishtank", "openphish", "nvd", "cnvd"):
                    out.append(self._providers[name].query(ioc_type, value, timeout=0.1))
            fused = self._fuse_provider_results(out)
            return {
                "is_malicious": fused["is_malicious"],
                "source": ",".join(fused["providers"]) if fused["providers"] else "none",
                "score": fused["score"],
                "degraded": False,
                "raw": out,
            }

        futures: List[Any] = []
        for name in provider_names:
            prov = self._providers.get(name)
            if not prov:
                continue
            if name == "abuseipdb" and ioc_type != "ip":
                continue
            futures.append(
                self._executor.submit(
                    prov.query, ioc_type, value, timeout=self.external_http_timeout
                )
            )

        if not futures:
            return {
                "is_malicious": False,
                "source": "none",
                "score": None,
                "degraded": False,
            }

        done, not_done = wait(futures, timeout=self.external_wait_sec)
        collected: List[Dict[str, Any]] = []
        for fut in done:
            try:
                collected.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                logger.debug("[ThreatIntel] provider future 异常: %s", exc)
        degraded = bool(not_done)
        if degraded:
            logger.warning(
                "[ThreatIntel] 外部情报等待超时（%.2fs），已降级；未完成查询仍在后台执行",
                self.external_wait_sec,
            )

        fused = self._fuse_provider_results(collected)
        if fused["is_malicious"]:
            self._add_memory(ioc_type, value)
            return {
                "is_malicious": True,
                "source": ",".join(fused["providers"]) if fused["providers"] else "external",
                "score": fused["score"],
                "degraded": degraded,
                "raw": collected,
            }

        if degraded:
            return {
                "is_malicious": False,
                "source": "none",
                "score": fused.get("score"),
                "degraded": True,
                "reason": "external_timeout",
                "raw": collected,
            }

        return {
            "is_malicious": False,
            "source": "none",
            "score": fused.get("score"),
            "degraded": False,
            "raw": collected,
        }

    def _check_ioc_core(self, ioc_type: str, value: str) -> Dict[str, Any]:
        t = ioc_type.lower()
        if t not in _IOC_TYPES:
            return {
                "is_malicious": False,
                "source": "none",
                "reason": "invalid_ioc_type",
            }

        row = self._local_db_lookup(t, value)
        if row:
            sc = row.get("score")
            return {
                "is_malicious": True,
                "source": "local_db",
                "score": int(sc) if isinstance(sc, (int, float)) else sc,
                "sources": row.get("sources") or [],
                "ioc_value": row.get("value"),
                "metadata": row.get("metadata"),
                "reason": row.get("reason") or "local_ioc_hit",
            }

        if self._memory_hit(t, value):
            return {
                "is_malicious": True,
                "source": "local",
                "ioc_value": value.strip() if t != "domain" else value.strip().lower(),
                "reason": "memory_blacklist",
            }

        if self._use_mock_external():
            ext_names = ["abuseipdb", "virustotal"] if t == "ip" else ["virustotal"]
        else:
            ext_names = []
            if t == "ip" and self.abuseipdb_key:
                ext_names.append("abuseipdb")
            if self.virustotal_key:
                ext_names.append("virustotal")

        if not ext_names:
            return {"is_malicious": False, "source": "none"}

        ext = self._query_external_parallel(t, value, ext_names)
        return {
            "is_malicious": bool(ext.get("is_malicious")),
            "source": ext.get("source", "none"),
            "score": ext.get("score"),
            "degraded": ext.get("degraded", False),
            "reason": ext.get("reason"),
            "ioc_value": value.strip(),
        }

    def check_ip(self, ip: str) -> dict:
        if not self._validate_ip(ip):
            logger.warning("[ThreatIntel] 无效的 IP 地址格式: %r", ip)
            return {
                "is_malicious": False,
                "source": "none",
                "reason": "invalid_ip_format",
            }
        r = self._check_ioc_core("ip", ip)
        r["ioc_value"] = r.get("ioc_value") or ip
        return r

    def check_domain(self, domain: str) -> dict:
        if not domain or not isinstance(domain, str):
            return {"is_malicious": False, "source": "none"}
        r = self._check_ioc_core("domain", domain.strip())
        r["ioc_value"] = r.get("ioc_value") or domain.strip().lower()
        return r

    def check_ioc(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """通用 IOC 前置查询（含 url / file_hash / cve）。"""
        return self._check_ioc_core(ioc_type.strip().lower(), value)

    def query_abuseipdb_detailed(self, ip: str) -> dict:
        if not self._validate_ip(ip):
            return {"ok": False, "reason": "invalid_ip_format"}
        if self._use_mock_external() and not self.abuseipdb_key:
            return _mock_abuseipdb(ip)
        return self._providers["abuseipdb"].query(
            "ip", ip, timeout=self.external_http_timeout
        )

    def query_virustotal_ip(self, ip: str) -> dict:
        if not self._validate_ip(ip):
            return {"ok": False, "reason": "invalid_ip_format"}
        if self._use_mock_external() and not self.virustotal_key:
            return _mock_virustotal("ip", ip)
        r = self._providers["virustotal"].query(
            "ip", ip, timeout=self.external_http_timeout
        )
        if r.get("ok") and r.get("is_malicious"):
            self._add_memory("ip", ip)
        return r

    def query_virustotal_domain(self, domain: str) -> dict:
        if not isinstance(domain, str) or not _DOMAIN_PATTERN.match(domain.strip()):
            return {"ok": False, "reason": "invalid_domain_format"}
        if self._use_mock_external() and not self.virustotal_key:
            return _mock_virustotal("domain", domain)
        r = self._providers["virustotal"].query(
            "domain", domain, timeout=self.external_http_timeout
        )
        if r.get("ok") and r.get("is_malicious"):
            self._add_memory("domain", domain)
        return r

    def update_blacklist(self) -> None:
        with self._lock:
            count = len(self._ip_blacklist)
        self._last_update = _utc_now()
        logger.info("[ThreatIntel] 黑名单已更新，当前 %d 条 IP", count)

    def get_blacklist_stats(self) -> dict:
        with self._lock:
            return {
                "ip_count": len(self._ip_blacklist),
                "domain_count": len(self._domain_blacklist),
                "url_count": len(self._url_blacklist),
                "file_hash_count": len(self._hash_blacklist),
                "cve_count": len(self._cve_blacklist),
                "last_update": (
                    self._last_update.isoformat() if self._last_update else None
                ),
            }

    def add_ip_to_blacklist(self, ip: str) -> bool:
        if not self._validate_ip(ip):
            logger.warning("[ThreatIntel] 拒绝将无效 IP 加入黑名单: %r", ip)
            return False
        self._add_memory("ip", ip)
        return True

    def add_domain_to_blacklist(self, domain: str) -> bool:
        if not domain or not isinstance(domain, str):
            return False
        self._add_memory("domain", domain)
        return True

    def add_ioc_to_blacklist(self, ioc_type: str, value: str) -> bool:
        """将任意支持的 IOC 写入内存黑名单（值需已通过上层校验）。"""
        t = (ioc_type or "").strip().lower()
        if t not in _IOC_TYPES:
            return False
        if t == "ip" and not self._validate_ip(value.strip()):
            return False
        self._add_memory(t, value)
        return True

    def remove_ip_from_blacklist(self, ip: str) -> bool:
        with self._lock:
            if ip in self._ip_blacklist:
                self._ip_blacklist.discard(ip)
                return True
        return False

    def remove_domain_from_blacklist(self, domain: str) -> bool:
        if not isinstance(domain, str):
            return False
        lower = domain.lower()
        with self._lock:
            if lower in self._domain_blacklist:
                self._domain_blacklist.discard(lower)
                return True
        return False

    def snapshot_local_entries(self) -> Dict[str, List[str]]:
        with self._lock:
            return {
                "ip": sorted(self._ip_blacklist),
                "domain": sorted(self._domain_blacklist),
                "url": sorted(self._url_blacklist),
                "file_hash": sorted(self._hash_blacklist),
                "cve": sorted(self._cve_blacklist),
            }

    def query_provider(
        self, provider: str, ioc_type: str, value: str
    ) -> Dict[str, Any]:
        """单 provider 查询（供 Web API）；不抛异常。"""
        prov = self._providers.get(provider)
        if not prov:
            return {"ok": False, "provider": provider, "reason": "unknown_provider"}
        if self._use_mock_external():
            if provider == "abuseipdb":
                r = (
                    _mock_abuseipdb(value)
                    if ioc_type == "ip"
                    else {**not_configured(provider), "reason": "unsupported_type"}
                )
            elif provider == "virustotal":
                r = _mock_virustotal(ioc_type, value)
            else:
                r = prov.query(ioc_type, value, timeout=0.1)
        else:
            r = prov.query(ioc_type, value, timeout=self.external_http_timeout)
        if r.get("ok") and r.get("is_malicious") and provider in ("abuseipdb", "virustotal"):
            self._add_memory(ioc_type, value)
        return r
