"""Flask Web 应用入口（Phase 7 可视化与交互层）。

对应架构文档 §8（可视化与交互层）、§9（数据流与通信机制）、§10（技术选型）。
遵循：
    - AI-Security-Guardian-DESIGN.md：视觉与交互规范
    - AI-Security-Guardian-Cursor-Phase7-Frontend-Prompt.md：实施约束
    - 开发实操指南修复版 Phase 7：**仅保留**安全与通信基线，UI 由 DESIGN 覆盖

安全与通信基线（硬要求）：
    1. SECRET_KEY / JWT_SECRET_KEY 从 `config.get_config()` 读取（环境变量驱动）
    2. 所有 `/api/*` 默认加 `@_auth_required()`；仅 `/api/auth/login`、`/api/health`、
       `/healthz`、`/readyz`、`/metrics` 匿名
    3. CORS 仅允许 `config.ALLOWED_ORIGINS` 白名单，禁止 `*`
    4. Flask-Limiter：默认 `config.API_RATE_LIMIT`，登录接口额外 `5 per minute`
    5. Flask-SocketIO：`cors_allowed_origins` 与 REST 使用同一白名单
    6. IP 入参复用 `src.response.responder.validate_ip`，非法一律拒绝
    7. 401 / 403 / 429 返回 JSON 错误体，前端统一拦截
"""
from __future__ import annotations

import atexit
import copy
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import secrets
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

from flask import Flask, current_app, jsonify, redirect, render_template, request, url_for, has_request_context
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity,
    verify_jwt_in_request,
    jwt_required,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, disconnect
from sqlalchemy import func, or_, text
from sqlalchemy.exc import IntegrityError

# Ensure project root is importable for script-style startup (`python web/app.py`).
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from config.config import get_config
from src.collectors.threat_intel import ThreatIntelCollector
from src.response.responder import (
    STATUS_APPROVED,
    STATUS_EXECUTED,
    STATUS_MANUAL_UNBLOCKED,
    STATUS_PENDING_APPROVAL,
    STATUS_REVIEWED,
    STATUS_SCHEDULED_UNBLOCKED,
    validate_ip,
)
from src.response.ip_policy import WHITELIST_SCOPES, check_real_ban_eligibility
from src.response.real_enforcement_gate import (
    REAL_ENFORCEMENT_GATE_VALUE,
    real_enforcement_env_failures,
    first_failure_code,
)
from src.response.webhook_url import check_webhook_url_safe
from src.utils.auth import verify_admin_credentials
from web.database import db, init_db_tables
from web.billing import (
    METRIC_ALERTS,
    METRIC_API_CALLS,
    METRIC_IOCS,
    METRIC_NOTIFICATIONS,
    METRIC_RESPONSE_ACTIONS,
    METRIC_RULES,
    METRIC_USERS,
    METERED_METRICS,
    OVERAGE_POLICIES,
    QuotaExceededError,
    ensure_quota,
    quota_snapshot,
    quota_error_response,
    record_usage,
    sync_quota_rows,
    usage_buckets,
    usage_period,
)
from web import models as _db_models  # noqa: F401
from web.models import (
    Alert,
    AlertHistory,
    APIKey,
    AuditEvent,
    BannedIp,
    DEFAULT_TENANT_ID,
    IOC,
    LicenseKey,
    ModelVersion,
    Organization,
    Plan,
    Quota,
    ResponseAction,
    ResponseApproval,
    ResponseDrill,
    ResponseProviderConfig,
    ResponseScheduleTask,
    ResponseWhitelistEntry,
    Rule,
    Setting,
    Subscription,
    Tenant,
    UsageMeter,
)
from web.tenant import (
    assign_tenant,
    configured_default_tenant_id,
    current_tenant_id,
    login_tenant_id,
    tenant_get,
    tenant_query,
)

logger = logging.getLogger(__name__)

_REQUIRED_MODEL_FILES: Tuple[str, ...] = (
    "intrusion_rf_v1.pkl",
    "ddos_rf_v1.pkl",
    "web_attack_nb_v1.pkl",
    "anomaly_if_v1.pkl",
)


def _resolve_model_dir(app: Flask) -> str:
    model_dir = str(app.config.get("MODEL_DIR", "models/saved"))
    if os.path.isabs(model_dir):
        return model_dir
    return os.path.abspath(os.path.join(app.root_path, "..", model_dir))


def _missing_model_artifacts(app: Flask) -> List[str]:
    md = _resolve_model_dir(app)
    return [f for f in _REQUIRED_MODEL_FILES if not os.path.exists(os.path.join(md, f))]


def _redis_client_for_app(app: Flask, cfg: Any):
    """Return the process-wide Redis client so health probes do not reconnect."""
    client = app.extensions.get("guardian_redis_client")
    if client is not None:
        return client

    from src.utils.redis_client import RedisClient

    client = RedisClient(
        host=cfg.REDIS_HOST,
        port=cfg.REDIS_PORT,
        db=cfg.REDIS_DB,
        password=getattr(cfg, "REDIS_PASSWORD", "") or "",
    )
    app.extensions["guardian_redis_client"] = client
    return client


def _runtime_dependency_checks(app: Flask, cfg: Any) -> Dict[str, Any]:
    require_redis = bool(getattr(cfg, "REQUIRE_REDIS_AVAILABLE", False))
    require_models = bool(getattr(cfg, "REQUIRE_MODELS_READY", False))

    from web.observability_routes import collect_health_checks

    checks, _fatal, _degraded = collect_health_checks(app, include_config=False)
    checks.setdefault("redis", {})["required"] = require_redis
    checks.setdefault("models", {})["required"] = require_models
    return checks


def _ensure_core_api_indexes(app: Flask) -> None:
    """Idempotently add indexes used by high-read dashboard API paths."""
    statements = (
        "CREATE INDEX IF NOT EXISTS ix_alerts_tenant_timestamp ON alerts (tenant_id, timestamp)",
        "CREATE INDEX IF NOT EXISTS ix_alerts_tenant_threat_type ON alerts (tenant_id, threat_type)",
        "CREATE INDEX IF NOT EXISTS ix_alerts_tenant_level ON alerts (tenant_id, level)",
        "CREATE INDEX IF NOT EXISTS ix_rules_tenant_priority_updated ON rules (tenant_id, priority, updated_at)",
        "CREATE INDEX IF NOT EXISTS ix_rules_tenant_type_enabled_priority ON rules (tenant_id, type, enabled, priority)",
    )
    with app.app_context():
        try:
            with db.engine.begin() as conn:
                for stmt in statements:
                    conn.execute(text(stmt))
        except Exception:  # noqa: BLE001
            logger.warning("[Perf] core API index bootstrap skipped", exc_info=True)


def _enforce_startup_guards(app: Flask, cfg: Any) -> Dict[str, Any]:
    checks = _runtime_dependency_checks(app, cfg)
    if checks["redis"]["required"] and not checks["redis"]["ok"]:
        raise RuntimeError(
            "启动失败：REQUIRE_REDIS_AVAILABLE=true 且 Redis 不可用。"
            "请先修复 Redis 连接/鉴权后再启动。"
        )
    if checks["models"]["required"] and not checks["models"]["ok"]:
        raise RuntimeError(
            "启动失败：REQUIRE_MODELS_READY=true 且模型文件缺失。"
            f"missing={checks['models']['missing']}"
        )
    return checks


# =====================================================================
# 应用工厂
# =====================================================================
def create_app() -> tuple[Flask, SocketIO]:
    """构建并返回 (Flask, SocketIO) 实例对。

    使用工厂模式便于测试注入不同配置。
    """
    cfg = get_config()

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path="/static",
    )

    # ---- 核心配置 ----------------------------------------------------
    app.config["SECRET_KEY"] = cfg.SECRET_KEY
    app.config["JWT_SECRET_KEY"] = cfg.SECRET_KEY
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = cfg.JWT_TOKEN_EXPIRES
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = cfg.JWT_REFRESH_TOKEN_EXPIRES
    app.config["SQLALCHEMY_DATABASE_URI"] = cfg.SQLALCHEMY_DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = cfg.SQLALCHEMY_TRACK_MODIFICATIONS
    # 生产环境关闭 debug（由 config 控制）
    app.config["DEBUG"] = getattr(cfg, "DEBUG", False)
    app.config["MODEL_DIR"] = getattr(cfg, "MODEL_DIR", "models/saved")
    app.config["HEALTHCHECK_DEPENDENCY_TIMEOUT_SEC"] = getattr(
        cfg, "HEALTHCHECK_DEPENDENCY_TIMEOUT_SEC", 0.3
    )
    app.config["GUARDIAN_LOG_DIR"] = getattr(cfg, "LOG_DIR", "logs")
    app.config["LOG_INTEGRITY_ENABLED"] = getattr(
        cfg, "LOG_INTEGRITY_ENABLED", True
    )
    app.extensions["guardian_os_config"] = cfg
    db.init_app(app)
    init_db_tables(app)
    _ensure_core_api_indexes(app)

    # ---- JWT ---------------------------------------------------------
    jwt = JWTManager(app)
    _register_jwt_error_handlers(jwt)
    _register_api_auth_gate(app)

    # ---- CORS（严格白名单）-------------------------------------------
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": cfg.ALLOWED_ORIGINS,
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"],
                "supports_credentials": False,
            }
        },
    )

    # ---- 速率限制 ----------------------------------------------------
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[cfg.API_RATE_LIMIT],
        storage_uri="memory://",
        strategy="fixed-window",
    )

    # ---- WebSocket ---------------------------------------------------
    socketio = SocketIO(
        app,
        cors_allowed_origins=cfg.ALLOWED_ORIGINS,
        async_mode="threading",
        ping_interval=25,
        ping_timeout=20,
    )

    # ---- 业务状态 ----------------------------------------------------
    state = _ServerState()
    state.init_settings(_default_editable_settings())
    with app.app_context():
        _hydrate_settings_from_db(state)
        _sync_banned_cache_from_db(state)
    app.extensions["guardian_state"] = state
    app.extensions["guardian_socketio"] = socketio

    # ---- 威胁情报采集器 ---------------------------------------------
    # 从环境变量读 Key；缺失不影响应用启动，仅影响对应 provider 的查询。
    threat_intel = ThreatIntelCollector(
        abuseipdb_key=os.environ.get("ABUSEIPDB_API_KEY", ""),
        virustotal_key=os.environ.get("VIRUSTOTAL_API_KEY", ""),
        external_http_timeout=float(os.environ.get("THREAT_INTEL_HTTP_TIMEOUT", "5")),
        external_wait_sec=float(os.environ.get("THREAT_INTEL_EXTERNAL_WAIT_SEC", "0.45")),
    )
    threat_intel.bind_flask_app(app)
    with app.app_context():
        try:
            _n = threat_intel.refresh_local_from_db()
            logger.info("[Phase7] 威胁情报 IOC 已从 DB 加载 %d 条", _n)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[Phase7] 威胁情报 DB 初始加载跳过: %s", exc)
    app.extensions["guardian_threat_intel"] = threat_intel

    # ---- 路由注册 ----------------------------------------------------
    _register_page_routes(app)
    _register_api_routes(app, limiter, state)
    from web.observability_routes import register_observability_routes

    register_observability_routes(app, limiter)
    _register_socket_handlers(socketio, state)
    _register_common_error_handlers(app)
    _register_access_log_writer(app)

    app.extensions["guardian_alert_consumer"] = None
    if getattr(cfg, "ALERT_STREAM_CONSUMER_AUTOSTART", True):
        try:
            from web.alert_stream_consumer import GuardianAlertStreamConsumer

            _redis_client = _redis_client_for_app(app, cfg)
            _consumer = GuardianAlertStreamConsumer(
                app=app,
                redis_client=_redis_client,
                socketio=socketio,
                stream_key=getattr(cfg, "GUARDIAN_ALERT_STREAM", "guardian:alerts"),
                group_name=getattr(cfg, "GUARDIAN_ALERT_STREAM_GROUP", "guardian:web"),
                tenant_id=configured_default_tenant_id(),
                per_tenant_stream=bool(
                    getattr(cfg, "GUARDIAN_ALERT_STREAM_PER_TENANT", True)
                ),
                normalizer=normalize_guardian_stream_fields,
                upsert_alert=_upsert_alert_to_db,
                alert_to_api_dict=_alert_to_api_dict,
            )
            _consumer.start()
            app.extensions["guardian_alert_consumer"] = _consumer

            def _stop_alert_consumer() -> None:
                c = app.extensions.get("guardian_alert_consumer")
                if c is not None:
                    c.stop()

            atexit.register(_stop_alert_consumer)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[Phase7] Redis Stream 告警 consumer 未启动: %s", exc)

    logger.info(
        "[Phase7] Flask app 就绪: ALLOWED_ORIGINS=%s, rate_limit=%s",
        cfg.ALLOWED_ORIGINS,
        cfg.API_RATE_LIMIT,
    )

    try:
        from web.audit_integrity_patrol import (
            run_audit_integrity_patrol_once,
            start_audit_integrity_patrol,
            stop_audit_integrity_patrol,
        )

        audit_patrol_enabled = (
            os.environ.get("AUDIT_INTEGRITY_PATROL", "true").lower() == "true"
        )
        if audit_patrol_enabled:
            with app.app_context():
                run_audit_integrity_patrol_once(app)
            start_audit_integrity_patrol(app)
            atexit.register(lambda: stop_audit_integrity_patrol(app))
    except Exception as exc:  # noqa: BLE001
        logger.warning("[Phase7] 审计完整性巡检未启动: %s", exc)

    checks = _enforce_startup_guards(app, cfg)
    app.extensions["guardian_startup_dependency_checks"] = checks

    return app, socketio


# =====================================================================
# 内存业务状态（开发缓存/兼容层；生产真源为 DB）
# =====================================================================
#: 合法等级（DESIGN §2.3 威胁等级色）
ALERT_LEVELS: Tuple[str, ...] = ("low", "medium", "high", "critical")
#: 合法状态流：open → acknowledged → resolved；任何状态可 → ignored
ALERT_STATUSES: Tuple[str, ...] = ("open", "acknowledged", "resolved", "ignored")
#: 检测规则类型
RULE_TYPES: Tuple[str, ...] = ("signature", "anomaly", "threshold")
#: 规则命中后的处置动作
RULE_ACTIONS: Tuple[str, ...] = ("alert", "block", "monitor")
#: 最小企业 RBAC 角色。当前为单管理员账号的角色化基础，不引入多用户/多租户。
RBAC_ROLES: Tuple[str, ...] = ("viewer", "analyst", "admin")
RBAC_ROLE_LEVEL: Dict[str, int] = {"viewer": 0, "analyst": 1, "admin": 2}
TENANT_STATUSES: Tuple[str, ...] = ("active", "suspended", "expired")
#: 规则 pattern 的最大长度，防止滥用
_RULE_PATTERN_MAX: int = 1024
_RULE_NAME_MAX: int = 80
_RULE_DESC_MAX: int = 400

#: 审计报告的周期枚举（DESIGN §8.6 支持日/周/月）
REPORT_PERIODS: Tuple[str, ...] = ("day", "week", "month")

#: 设置里可写字段的 schema（前端渲染 + 后端校验的单一真源）
# 字段：type=float|bool|string|email|url；min/max/step/pattern 用于约束；label/hint 驱动 UI。
SETTINGS_SCHEMA: Dict[str, Dict[str, Any]] = {
    "detection_sensitivity": {
        "type": "float",
        "min": 0.0,
        "max": 1.0,
        "step": 0.01,
        "label": "检测灵敏度",
        "group": "detection",
        "hint": "模型倾向于更多告警（高灵敏度）还是更少误报（低灵敏度）。建议 0.5~0.85。",
    },
    "alert_threshold": {
        "type": "float",
        "min": 0.0,
        "max": 1.0,
        "step": 0.01,
        "label": "告警触发阈值",
        "group": "detection",
        "hint": "预测置信度低于此值将被丢弃。应 ≤ 检测灵敏度。",
    },
    "alert_email": {
        "type": "email",
        "label": "告警邮箱",
        "group": "notifications",
        "hint": "Phase 8 起启用；Phase 7 暂仅做格式校验与配置落盘。",
        "placeholder": "soc@example.com",
        "optional": True,
    },
    "alert_webhook": {
        "type": "url",
        "label": "告警 Webhook",
        "group": "notifications",
        "hint": "严重告警将以 JSON POST 到此地址；仅允许 http(s) 协议。",
        "placeholder": "https://hooks.example.com/soc",
        "optional": True,
    },
    "model_version": {
        "type": "string",
        "label": "当前模型版本",
        "group": "model",
        "pattern": r"^v\d+(?:\.\d+){0,2}$",
        "hint": "格式：v1 / v1.2 / v1.2.3。影响 /api/reports 中 model_performance.version。",
    },
    "model_hot_reload": {
        "type": "bool",
        "label": "开启模型热更新",
        "group": "model",
        "hint": "启用后 Phase 8 检测引擎会在模型文件变更时自动重载。",
    },
}
SETTINGS_EDITABLE_KEYS: Tuple[str, ...] = tuple(SETTINGS_SCHEMA.keys())

#: 威胁情报 IOC 类型
IOC_TYPES: Tuple[str, ...] = ("ip", "domain", "url", "file_hash", "cve")
#: 支持的情报源 provider（占位源未配置时 API 返回 not_configured）
_DEFAULT_PROVIDERS: Tuple[str, ...] = (
    "local",
    "abuseipdb",
    "virustotal",
    "spamhaus",
    "phishtank",
    "openphish",
    "nvd",
    "cnvd",
)
#: 域名合法性校验（与 collector 一致）
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_HASH_RE = re.compile(r"^[a-f0-9]{32,128}$", re.IGNORECASE)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class _ServerState:
    """进程内缓存的运行时状态。"""

    _MAX_ALERTS: int = 500

    def __init__(self) -> None:
        self._alerts: Deque[Dict[str, Any]] = deque(maxlen=self._MAX_ALERTS)
        self._by_id: Dict[str, Dict[str, Any]] = {}
        self._rules: Dict[str, Dict[str, Any]] = {}
        # key = f"{type}:{value_lower_for_domain_or_value_for_ip}"
        self._iocs: Dict[str, Dict[str, Any]] = {}
        # 可写运行时设置（进程内持久，重启丢失；Phase 8 接入持久化层）
        self._settings: Dict[str, Any] = {}
        self.stats: Dict[str, Any] = {
            "total_packets": 0,
            "total_threats": 0,
            "banned_ips": 0,
            "security_score": 100,
            "updated_at": _now_iso(),
        }
        self.banned_ips: Dict[str, str] = {}

    # ---- 告警 --------------------------------------------------------
    def add_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """写入告警；补齐规范化字段并返回写入后的对象（含稳定 id）。

        规范化：id / timestamp / level / status / title / summary / history；
        非法 level 降级为 "low"，非法 status 强制为 "open"。
        """
        norm = dict(alert)
        norm.setdefault("id", _uuid())
        norm.setdefault("timestamp", _now_iso())
        level = norm.get("level")
        if level not in ALERT_LEVELS:
            level = "low"
        norm["level"] = level
        status = norm.get("status")
        if status not in ALERT_STATUSES:
            status = "open"
        norm["status"] = status
        norm.setdefault("threat_type", "unknown")
        norm["source_ip"] = str(norm.get("source_ip") or "").strip()
        norm.setdefault("title", norm.get("details") or norm.get("message") or "未分类告警")
        norm.setdefault("summary", norm.get("title"))
        norm.setdefault("history", [{"status": status, "timestamp": norm["timestamp"]}])

        # 若上游复用了同一 id，覆盖旧记录并从队列里去除
        if norm["id"] in self._by_id:
            self._remove_by_id(norm["id"])

        self._alerts.appendleft(norm)
        self._by_id[norm["id"]] = norm

        # deque 到达上限会从右端丢弃，保持 _by_id 同步
        if len(self._alerts) == self._MAX_ALERTS:
            # 此时右端可能是刚被挤出的元素；由 deque 语义不便直接拿，
            # 改用惰性清理：对 _by_id 的冗余键在每次查询时兜底一次
            self._gc_by_id()
        return norm

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        return self._by_id.get(alert_id)

    def update_alert_status(
        self, alert_id: str, new_status: str
    ) -> Optional[Dict[str, Any]]:
        if new_status not in ALERT_STATUSES:
            return None
        alert = self._by_id.get(alert_id)
        if not alert:
            return None
        alert["status"] = new_status
        alert.setdefault("history", []).append(
            {"status": new_status, "timestamp": _now_iso()}
        )
        return alert

    def distinct_threat_types(self) -> List[str]:
        seen: Dict[str, None] = {}
        for item in self._alerts:
            t = item.get("threat_type") or "unknown"
            seen.setdefault(t, None)
        return sorted(seen.keys())

    def query_alerts(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        level: Optional[str] = None,
        threat_type: Optional[str] = None,
        status: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        q: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """返回 (分页后的结果, 过滤后的总数)。"""
        needle = (q or "").strip().lower()
        matched: List[Dict[str, Any]] = []
        for item in self._alerts:
            if level and item.get("level") != level:
                continue
            if threat_type and item.get("threat_type") != threat_type:
                continue
            if status and item.get("status") != status:
                continue
            if since or until:
                ts = _parse_iso(item.get("timestamp", ""))
                if since and (not ts or ts < since):
                    continue
                if until and (not ts or ts > until):
                    continue
            if needle:
                hay = " ".join(
                    str(item.get(k, ""))
                    for k in ("title", "summary", "threat_type", "source_ip", "dest_ip")
                ).lower()
                if needle not in hay:
                    continue
            matched.append(item)
        total = len(matched)
        sliced = matched[offset : offset + limit] if offset >= 0 else []
        return sliced, total

    # 兼容旧调用点（dashboard.js 聚合）
    def recent_alerts(
        self,
        limit: int = 100,
        level: Optional[str] = None,
        threat_type: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        items, _ = self.query_alerts(
            limit=limit, level=level, threat_type=threat_type, since=since
        )
        return items

    def _remove_by_id(self, alert_id: str) -> None:
        self._by_id.pop(alert_id, None)
        try:
            for idx, item in enumerate(self._alerts):
                if item.get("id") == alert_id:
                    del self._alerts[idx]
                    break
        except ValueError:
            pass

    def _gc_by_id(self) -> None:
        """清理已被 deque 挤出但仍在 _by_id 中的记录。"""
        alive = {item.get("id") for item in self._alerts}
        for stale in [k for k in self._by_id if k not in alive]:
            self._by_id.pop(stale, None)

    # ---- 封禁 IP -----------------------------------------------------
    def ban_ip(self, ip: str, reason: str) -> None:
        self.banned_ips[ip] = reason
        self.stats["banned_ips"] = len(self.banned_ips)

    def unban_ip(self, ip: str) -> bool:
        removed = self.banned_ips.pop(ip, None) is not None
        self.stats["banned_ips"] = len(self.banned_ips)
        return removed

    # ---- 检测规则 ----------------------------------------------------
    def add_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """写入规则并返回规范化对象（含稳定 id / 时间戳 / 统计）。"""
        now = _now_iso()
        norm = dict(rule)
        norm.setdefault("id", _uuid())
        norm.setdefault("created_at", now)
        norm["updated_at"] = now
        norm.setdefault("hits", 0)
        self._rules[norm["id"]] = norm
        return norm

    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        return self._rules.get(rule_id)

    def update_rule(
        self, rule_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        rule = self._rules.get(rule_id)
        if not rule:
            return None
        for k, v in updates.items():
            # id/created_at/hits 不可被外部直接覆盖
            if k in ("id", "created_at", "hits"):
                continue
            rule[k] = v
        rule["updated_at"] = _now_iso()
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        return self._rules.pop(rule_id, None) is not None

    def list_rules(
        self,
        *,
        type_: Optional[str] = None,
        enabled: Optional[bool] = None,
        q: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        needle = (q or "").strip().lower()
        result: List[Dict[str, Any]] = []
        for rule in self._rules.values():
            if type_ and rule.get("type") != type_:
                continue
            if enabled is not None and bool(rule.get("enabled")) != enabled:
                continue
            if needle:
                hay = " ".join(
                    str(rule.get(k, ""))
                    for k in ("name", "description", "pattern", "type", "action")
                ).lower()
                if needle not in hay:
                    continue
            result.append(rule)
        # 默认按 priority 升序、updated_at 降序（新改动靠前）
        def _ts_key(r: Dict[str, Any]) -> float:
            ts = _parse_iso(r.get("updated_at"))
            return -ts.timestamp() if ts else 0.0

        result.sort(key=lambda r: (int(r.get("priority", 100)), _ts_key(r)))
        return result

    def incr_rule_hits(self, rule_id: str, delta: int = 1) -> None:
        rule = self._rules.get(rule_id)
        if not rule:
            return
        rule["hits"] = int(rule.get("hits", 0)) + delta

    # ---- IOC 注册表（富元数据） --------------------------------------
    @staticmethod
    def _ioc_key(ioc_type: str, value: str) -> str:
        if ioc_type == "domain":
            canonical = value.lower()
        elif ioc_type == "file_hash":
            canonical = value.strip().lower()
        elif ioc_type == "cve":
            canonical = value.strip().upper()
        else:
            canonical = value.strip()
        return f"{ioc_type}:{canonical}"

    def add_ioc(
        self,
        *,
        ioc_type: str,
        value: str,
        source: str = "manual",
        reason: Optional[str] = None,
        note: Optional[str] = None,
        score: Optional[int] = None,
    ) -> Dict[str, Any]:
        """新增或刷新一条 IOC（同 key 存在则合并 source/score/note，保持 added_at）。"""
        key = self._ioc_key(ioc_type, value)
        now = _now_iso()
        existing = self._iocs.get(key)
        if existing:
            if source and source not in existing.get("sources", []):
                existing.setdefault("sources", []).append(source)
            if reason:
                existing["reason"] = reason
            if note is not None:
                existing["note"] = note
            if score is not None:
                existing["score"] = int(score)
            existing["updated_at"] = now
            return existing
        entry: Dict[str, Any] = {
            "id": _uuid(),
            "type": ioc_type,
            "value": value if ioc_type == "ip" else value.lower(),
            "sources": [source] if source else ["manual"],
            "reason": reason or "",
            "note": note or "",
            "score": int(score) if score is not None else None,
            "hits": 0,
            "added_at": now,
            "updated_at": now,
        }
        self._iocs[key] = entry
        return entry

    def remove_ioc(self, ioc_type: str, value: str) -> bool:
        key = self._ioc_key(ioc_type, value)
        return self._iocs.pop(key, None) is not None

    def get_ioc(self, ioc_type: str, value: str) -> Optional[Dict[str, Any]]:
        return self._iocs.get(self._ioc_key(ioc_type, value))

    def incr_ioc_hit(self, ioc_type: str, value: str) -> None:
        entry = self._iocs.get(self._ioc_key(ioc_type, value))
        if entry:
            entry["hits"] = int(entry.get("hits", 0)) + 1
            entry["updated_at"] = _now_iso()

    def list_iocs(
        self,
        *,
        type_: Optional[str] = None,
        source: Optional[str] = None,
        q: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        needle = (q or "").strip().lower()
        result: List[Dict[str, Any]] = []
        for item in self._iocs.values():
            if type_ and item.get("type") != type_:
                continue
            if source and source not in item.get("sources", []):
                continue
            if needle:
                hay = " ".join(
                    [
                        str(item.get("value", "")),
                        str(item.get("reason", "")),
                        str(item.get("note", "")),
                        " ".join(item.get("sources", [])),
                    ]
                ).lower()
                if needle not in hay:
                    continue
            result.append(item)
        # 按 added_at 降序（最新在前）
        def _added_ts(e: Dict[str, Any]) -> float:
            ts = _parse_iso(e.get("added_at"))
            return -ts.timestamp() if ts else 0.0

        result.sort(key=_added_ts)
        return result

    def ioc_stats(self) -> Dict[str, Any]:
        total = len(self._iocs)
        by_type: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        for item in self._iocs.values():
            by_type[item.get("type", "unknown")] = (
                by_type.get(item.get("type", "unknown"), 0) + 1
            )
            for s in item.get("sources", []):
                by_source[s] = by_source.get(s, 0) + 1
        return {
            "total": total,
            "ip_count": by_type.get("ip", 0),
            "domain_count": by_type.get("domain", 0),
            "by_type": by_type,
            "by_source": by_source,
            "updated_at": _now_iso(),
        }

    # ---- 可写运行时设置 ---------------------------------------------
    def init_settings(self, defaults: Dict[str, Any]) -> None:
        """首次启动时用环境默认值填充 _settings。"""
        self._settings = dict(defaults)

    def get_setting(self, key: str, default: Any = None) -> Any:
        return self._settings.get(key, default)

    def all_settings(self) -> Dict[str, Any]:
        return dict(self._settings)

    def update_settings(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """原子合并：仅白名单字段会被写入。"""
        for k, v in updates.items():
            if k in SETTINGS_EDITABLE_KEYS:
                self._settings[k] = v
        return self.all_settings()


# =====================================================================
# DB helpers（R2：告警接口数据库优先，保留内存态兼容）
# =====================================================================
def _dt_iso(value: Optional[datetime]) -> Optional[str]:
    if not value:
        return None
    return value.astimezone().isoformat(timespec="seconds")


def _alert_to_api_dict(alert: Alert) -> Dict[str, Any]:
    history = sorted(
        list(alert.histories),
        key=lambda h: h.created_at.timestamp() if h.created_at else 0,
    )
    return {
        "id": alert.id,
        "tenant_id": alert.tenant_id,
        "external_id": alert.external_id,
        "timestamp": _dt_iso(alert.timestamp) or _now_iso(),
        "source_ip": alert.source_ip or "",
        # 兼容前端既有字段命名
        "target_ip": alert.target_ip or "",
        "dest_ip": alert.target_ip or "",
        "threat_type": alert.threat_type or "unknown",
        "level": alert.level or "low",
        "confidence": alert.confidence,
        "engine": alert.engine,
        "status": alert.status or "open",
        # Phase 7 前端依赖 title，当前先复用 summary
        "title": alert.summary or "未分类告警",
        "summary": alert.summary or "",
        "raw_payload": alert.raw_payload,
        "model_version": alert.model_version,
        "created_at": _dt_iso(alert.created_at),
        "updated_at": _dt_iso(alert.updated_at),
        "history": [
            {
                "status": item.to_status,
                "from_status": item.from_status,
                "operator": item.operator,
                "note": item.note,
                "timestamp": _dt_iso(item.created_at),
            }
            for item in history
        ],
    }


def _upsert_alert_to_db(alert_payload: Dict[str, Any]) -> Optional[Alert]:
    """把标准化告警写入 DB（同 id 幂等更新）。"""
    alert_id = str(alert_payload.get("id") or "").strip()
    if not alert_id:
        return None

    ts = _parse_iso(str(alert_payload.get("timestamp") or "")) or datetime.now(timezone.utc)
    tenant_id = str(alert_payload.get("tenant_id") or current_tenant_id()).strip()
    item = tenant_get(db.session, Alert, alert_id, tenant_id)
    if item is not None and item.tenant_id != tenant_id:
        logger.warning("[Alert] reject cross-tenant upsert alert_id=%s", alert_id)
        return None
    is_new = item is None
    if is_new:
        ensure_quota(db.session, tenant_id, METRIC_ALERTS, requested=1)
    if item is None:
        item = Alert(
            id=alert_id,
            tenant_id=tenant_id,
            timestamp=ts,
            source_ip=str(alert_payload.get("source_ip") or ""),
        )
        db.session.add(item)
    item.tenant_id = tenant_id
    item.external_id = str(alert_payload.get("external_id") or "") or None
    item.timestamp = ts
    item.source_ip = str(alert_payload.get("source_ip") or "")
    item.target_ip = str(alert_payload.get("target_ip") or alert_payload.get("dest_ip") or "") or None
    item.threat_type = str(alert_payload.get("threat_type") or "unknown")
    item.level = str(alert_payload.get("level") or "low")
    conf = alert_payload.get("confidence")
    item.confidence = float(conf) if isinstance(conf, (int, float)) else None
    item.engine = str(alert_payload.get("engine") or "") or None
    item.status = str(alert_payload.get("status") or "open")
    item.summary = str(alert_payload.get("summary") or alert_payload.get("title") or "") or None
    raw = alert_payload.get("raw_payload", alert_payload.get("raw"))
    item.raw_payload = str(raw) if raw not in (None, "") else None
    item.model_version = str(alert_payload.get("model_version") or "") or None

    try:
        db.session.flush()
        if is_new:
            db.session.add(
                AlertHistory(
                    tenant_id=item.tenant_id,
                    alert_id=item.id,
                    from_status=None,
                    to_status=item.status,
                    operator="system",
                    note="alert_ingested",
                )
            )
            record_usage(
                db.session,
                tenant_id,
                METRIC_ALERTS,
                actor="system",
                resource_type="alert",
                resource_id=item.id,
            )
        db.session.commit()
        _api_cache_invalidate("stats")
        _api_cache_invalidate("alert_types")
        _api_cache_invalidate("traffic")
    except IntegrityError:
        db.session.rollback()
        existing = tenant_get(db.session, Alert, alert_id, tenant_id)
        if existing is not None:
            return existing
        ext = str(alert_payload.get("external_id") or "").strip()
        if ext:
            dup = (
                tenant_query(db.session.query(Alert), Alert, tenant_id)
                .filter(Alert.external_id == ext)
                .one_or_none()
            )
            if dup is not None:
                return dup
        logger.warning(
            "[Alert] reject conflicting cross-tenant alert insert alert_id=%s tenant_id=%s",
            alert_id,
            tenant_id,
        )
        return None
    return item


def normalize_guardian_stream_fields(fields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """将 ``guardian:alerts`` Stream 字段规范化为与 REST/Socket 一致的告警 dict。

    缺少 ``alert_id`` / ``id`` 的消息无法幂等入库，返回 ``None``（调用方应 ack 丢弃以免堵流）。
    """
    aid = str(fields.get("alert_id") or fields.get("id") or "").strip()
    if not aid:
        return None
    level = str(fields.get("level") or "low")
    if level not in ALERT_LEVELS:
        level = "low"
    status = str(fields.get("status") or "open")
    if status not in ALERT_STATUSES:
        status = "open"
    threat = str(fields.get("type") or fields.get("threat_type") or "unknown")
    details = str(fields.get("details") or "").strip()
    ts_raw = fields.get("timestamp")
    ts_str = str(ts_raw).strip() if ts_raw is not None else ""
    if not ts_str:
        ts_str = _now_iso()
    conf = fields.get("confidence")
    raw_blob = {k: v for k, v in fields.items()}
    return {
        "id": aid,
        "tenant_id": str(fields.get("tenant_id") or DEFAULT_TENANT_ID).strip(),
        "external_id": aid,
        "timestamp": ts_str,
        "source_ip": str(fields.get("source_ip") or "").strip(),
        "target_ip": str(fields.get("target_ip") or fields.get("dest_ip") or "").strip()
        or None,
        "threat_type": threat,
        "level": level,
        "status": status,
        "title": details or "未分类告警",
        "summary": details or "未分类告警",
        "confidence": float(conf) if isinstance(conf, (int, float)) else None,
        "engine": str(fields.get("engine") or "") or None,
        "model_version": str(fields.get("model_version") or "") or None,
        "raw_payload": json.dumps(raw_blob, ensure_ascii=False),
        "history": [{"status": status, "timestamp": ts_str}],
    }


def _query_alerts_from_db(
    *,
    limit: int,
    offset: int,
    level: Optional[str],
    threat_type: Optional[str],
    status: Optional[str],
    since: Optional[datetime],
    until: Optional[datetime],
    q: Optional[str],
) -> Tuple[List[Dict[str, Any]], int]:
    query = tenant_query(db.session.query(Alert), Alert)
    if level:
        query = query.filter(Alert.level == level)
    if threat_type:
        query = query.filter(Alert.threat_type == threat_type)
    if status:
        query = query.filter(Alert.status == status)
    if since:
        query = query.filter(Alert.timestamp >= since)
    if until:
        query = query.filter(Alert.timestamp <= until)
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(
            or_(
                Alert.summary.ilike(like),
                Alert.threat_type.ilike(like),
                Alert.source_ip.ilike(like),
                Alert.target_ip.ilike(like),
            )
        )

    total = query.count()
    rows = query.order_by(Alert.timestamp.desc()).offset(offset).limit(limit).all()
    return [_alert_to_api_dict(row) for row in rows], total


def _update_alert_status_in_db(
    *, alert_id: str, new_status: str, operator: Optional[str], note: Optional[str]
) -> Optional[Dict[str, Any]]:
    row = tenant_get(db.session, Alert, alert_id)
    if not row:
        return None
    prev = row.status
    row.status = new_status
    db.session.add(
        AlertHistory(
            tenant_id=row.tenant_id,
            alert_id=alert_id,
            from_status=prev,
            to_status=new_status,
            operator=operator or "operator",
            note=note or None,
        )
    )
    db.session.commit()
    db.session.refresh(row)
    return _alert_to_api_dict(row)


def _recent_alerts_from_db(
    *,
    limit: int = 500,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    query = tenant_query(db.session.query(Alert), Alert)
    if since:
        query = query.filter(Alert.timestamp >= since)
    if until:
        query = query.filter(Alert.timestamp <= until)
    rows = query.order_by(Alert.timestamp.desc()).limit(limit).all()
    return [_alert_to_api_dict(row) for row in rows]


def _audit_event_to_api_dict(row: AuditEvent) -> Dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "event_type": row.event_type,
        "actor": row.actor,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "payload": row.payload or {},
        "ip_address": row.ip_address,
        "created_at": _dt_iso(row.created_at),
    }


def _record_audit_event(
    *,
    event_type: str,
    actor: Optional[str],
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> None:
    """Best-effort 操作审计入库，并同步写入哈希链日志用于合规举证。"""
    try:
        ip_address = get_remote_address() if has_request_context() else None
        db.session.add(
            AuditEvent(
                tenant_id=_current_tenant_id(),
                event_type=event_type[:64],
                actor=(actor or "anonymous")[:128],
                resource_type=(resource_type or "")[:64] or None,
                resource_id=(resource_id or "")[:255] or None,
                payload=payload or {},
                ip_address=ip_address,
            )
        )
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
        logger.warning("[AuditEvent] 写入失败: %s", event_type, exc_info=True)
        ip_address = None

    try:
        app = current_app._get_current_object()
        audit_logger = app.extensions.get("guardian_security_audit_logger")
        if audit_logger is None:
            from src.audit.security_logger import SecurityLogger

            audit_logger = SecurityLogger(
                log_dir=app.config.get("GUARDIAN_LOG_DIR", "logs"),
                enable_integrity=bool(app.config.get("LOG_INTEGRITY_ENABLED", True)),
            )
            app.extensions["guardian_security_audit_logger"] = audit_logger
        audit_logger.log_event(
            event_type="operation_audit",
            level="info",
            details={
                "event_type": event_type[:64],
                "actor": (actor or "anonymous")[:128],
                "resource_type": (resource_type or "")[:64] or None,
                "resource_id": (resource_id or "")[:255] or None,
                "payload": payload or {},
                "ip_address": ip_address,
            },
            source_ip=ip_address or "",
            confidence=1.0,
        )
    except Exception:  # noqa: BLE001
        logger.warning(
            "[AuditEvent] 哈希链日志写入失败: %s", event_type, exc_info=True
        )


def _hydrate_settings_from_db(state: _ServerState) -> None:
    """用数据库中的设置覆盖进程内默认值（生产真源）。"""
    try:
        for key in SETTINGS_EDITABLE_KEYS:
            row = (
                tenant_query(db.session.query(Setting), Setting)
                .filter(Setting.key == key)
                .one_or_none()
            )
            if row is not None and row.value is not None:
                state._settings[key] = row.value
    except Exception:  # noqa: BLE001
        logger.warning("[Settings] 从 DB 加载失败，使用进程默认值", exc_info=True)


def _current_tenant_id() -> str:
    """Return the tenant carried by the JWT, falling back to legacy single-tenant mode."""
    return current_tenant_id()


def _persist_settings_to_db(updates: Dict[str, Any]) -> None:
    for key, val in updates.items():
        if key not in SETTINGS_EDITABLE_KEYS:
            continue
        row = (
            tenant_query(db.session.query(Setting), Setting)
            .filter(Setting.key == key)
            .one_or_none()
        )
        if row is None:
            row = assign_tenant(Setting(key=key))
            db.session.add(row)
        row.value = val
    db.session.commit()


def _sync_banned_cache_from_db(state: _ServerState) -> None:
    """封禁列表真源为 ``BannedIp`` 表；``state.banned_ips`` 仅为兼容缓存。"""
    try:
        rows = tenant_query(db.session.query(BannedIp), BannedIp).all()
        state.banned_ips = {r.ip: r.reason for r in rows}
        state.stats["banned_ips"] = len(state.banned_ips)
    except Exception:  # noqa: BLE001
        logger.warning("[BannedIp] 缓存同步失败", exc_info=True)


def _persist_banned_ip(
    ip: str, reason: str, *, operator: Optional[str] = None
) -> None:
    reason_s = (reason or "manual")[:200]
    row = (
        tenant_query(db.session.query(BannedIp), BannedIp)
        .filter(BannedIp.ip == ip)
        .one_or_none()
    )
    if row is None:
        db.session.add(
            BannedIp(
                ip=ip,
                tenant_id=_current_tenant_id(),
                reason=reason_s,
                operator=operator,
            )
        )
    else:
        if row.tenant_id != _current_tenant_id():
            return
        row.reason = reason_s
        row.operator = operator
    db.session.commit()


def _record_ban_approval_request(
    ip: str, reason: str, *, operator: Optional[str], source: str
) -> int:
    ensure_quota(db.session, _current_tenant_id(), METRIC_RESPONSE_ACTIONS, requested=1)
    row = ResponseAction(
        tenant_id=_current_tenant_id(),
        action_type="ban_ip",
        target=ip,
        status=STATUS_PENDING_APPROVAL,
        dry_run=True,
        meta={
            "reason": (reason or "manual")[:200],
            "operator": operator or "operator",
            "trigger_source": source,
            "approved": False,
            "legacy_entrypoint": source,
        },
    )
    db.session.add(row)
    record_usage(
        db.session,
        _current_tenant_id(),
        METRIC_RESPONSE_ACTIONS,
        actor=operator or _current_actor(),
        resource_type="response_action",
        resource_id=ip,
    )
    db.session.commit()
    return int(row.id)


_REAL_RESPONSE_GATE_VALUE = "real-enforcement"
_REAL_RESPONSE_ACTION_TYPES = {
    "ban_ip",
    "unban_ip",
    "isolate_host",
    "release_host",
    "cloud_security_group_block",
    "cloud_security_group_unblock",
}
_REAL_RESPONSE_TARGET_TYPES = {"ip", "cidr", "asset", "host", "security_group_rule", "tag"}
_REAL_RESPONSE_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _response_dry_run() -> bool:
    return os.environ.get("DRY_RUN", "true").strip().lower() != "false"


def _response_gate() -> str:
    return os.environ.get("REAL_ENFORCEMENT_GATE", "").strip()


def _response_runtime_payload(
    *,
    status: str,
    reason: str,
    response_action_id: Optional[int] = None,
    approval_id: Optional[int] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "status": status,
        "dry_run": _response_dry_run(),
        "gate": _response_gate(),
        "reason": reason,
        "response_action_id": response_action_id,
    }
    if approval_id is not None:
        payload["approval_id"] = approval_id
    if extra:
        payload.update(extra)
    return payload


def _required_body_text(data: Dict[str, Any], key: str, *, max_len: int = 2000) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_len]


def _response_action_to_api_dict(row: ResponseAction) -> Dict[str, Any]:
    meta = row.meta if isinstance(row.meta, dict) else {}
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "alert_id": row.alert_id,
        "action_type": row.action_type,
        "target": row.target,
        "status": row.status,
        "dry_run": row.dry_run,
        "gate": meta.get("gate") or meta.get("gate_id") or "",
        "reason": meta.get("reason") or row.error or "",
        "provider": meta.get("provider"),
        "provider_config_id": meta.get("provider_config_id"),
        "scheduled_unblock_at": _dt_iso(row.scheduled_unblock_at),
        "meta": meta,
        "error": row.error,
        "created_at": _dt_iso(row.created_at),
        "updated_at": _dt_iso(row.updated_at),
    }


def _response_approval_to_api_dict(row: ResponseApproval) -> Dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "alert_id": row.alert_id,
        "response_action_id": row.response_action_id,
        "provider_config_id": row.provider_config_id,
        "gate_id": row.gate_id,
        "action_type": row.action_type,
        "target_type": row.target_type,
        "target": row.target,
        "provider": row.provider,
        "ttl_seconds": row.ttl_seconds,
        "status": row.status,
        "reason": row.reason,
        "requested_by": row.requested_by,
        "approved_by": row.approved_by,
        "approved_at": _dt_iso(row.approved_at),
        "rejected_by": row.rejected_by,
        "rejected_at": _dt_iso(row.rejected_at),
        "rejection_reason": row.rejection_reason,
        "executed_by": row.executed_by,
        "executed_at": _dt_iso(row.executed_at),
        "reviewed_by": row.reviewed_by,
        "reviewed_at": _dt_iso(row.reviewed_at),
        "expires_at": _dt_iso(row.expires_at),
        "evidence": row.evidence or {},
        "rollback_plan": row.rollback_plan or {},
        "created_at": _dt_iso(row.created_at),
        "updated_at": _dt_iso(row.updated_at),
    }


def _response_whitelist_to_api_dict(row: ResponseWhitelistEntry) -> Dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "scope": row.scope,
        "value_type": row.value_type,
        "value": row.value,
        "environment": row.environment,
        "status": row.status,
        "reason": row.reason,
        "owner": row.owner,
        "created_by": row.created_by,
        "approved_by": row.approved_by,
        "approved_at": _dt_iso(row.approved_at),
        "expires_at": _dt_iso(row.expires_at),
        "evidence": row.evidence or {},
        "created_at": _dt_iso(row.created_at),
        "updated_at": _dt_iso(row.updated_at),
    }


def _response_provider_to_api_dict(row: ResponseProviderConfig) -> Dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "provider_type": row.provider_type,
        "provider_name": row.provider_name,
        "environment": row.environment,
        "status": row.status,
        "config_ref": row.config_ref,
        "credential_ref": row.credential_ref,
        "secret_fingerprint": row.secret_fingerprint,
        "config_metadata": row.config_metadata or {},
        "capabilities": row.capabilities or {},
        "last_validated_at": _dt_iso(row.last_validated_at),
        "last_validation_result": row.last_validation_result or {},
        "created_by": row.created_by,
        "updated_by": row.updated_by,
        "created_at": _dt_iso(row.created_at),
        "updated_at": _dt_iso(row.updated_at),
    }


def _response_schedule_to_api_dict(row: ResponseScheduleTask) -> Dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "task_type": row.task_type,
        "alert_id": row.alert_id,
        "payload": row.payload or {},
        "run_at": _dt_iso(row.run_at),
        "status": row.status,
        "attempt_count": row.attempt_count,
        "max_attempts": row.max_attempts,
        "related_response_action_id": row.related_response_action_id,
        "last_error": row.last_error,
        "created_at": _dt_iso(row.created_at),
        "updated_at": _dt_iso(row.updated_at),
    }


def _response_drill_to_api_dict(row: ResponseDrill) -> Dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "provider_config_id": row.provider_config_id,
        "response_action_id": row.response_action_id,
        "approval_id": row.approval_id,
        "environment": row.environment,
        "drill_type": row.drill_type,
        "target_type": row.target_type,
        "target": row.target,
        "status": row.status,
        "started_at": _dt_iso(row.started_at),
        "ended_at": _dt_iso(row.ended_at),
        "rto_seconds": row.rto_seconds,
        "result": row.result,
        "participants": row.participants or [],
        "evidence": row.evidence or {},
        "created_by": row.created_by,
        "approved_by": row.approved_by,
        "created_at": _dt_iso(row.created_at),
        "updated_at": _dt_iso(row.updated_at),
    }


def _validate_response_target(target_type: str, target: str) -> Optional[str]:
    if target_type == "ip" and not validate_ip(target):
        return "invalid_ip"
    if target_type == "cidr":
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            return "invalid_cidr"
    if target_type in {"asset", "host", "security_group_rule", "tag"} and not target:
        return "target_required"
    return None


def _normalize_response_whitelist_value(value_type: str, value: str) -> Tuple[Optional[str], Optional[str]]:
    raw = str(value or "").strip()
    if value_type == "ip":
        if not validate_ip(raw):
            return None, "invalid_ip"
        return raw, None
    if value_type == "cidr":
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return None, "invalid_cidr"
        if net.version != 4:
            return None, "invalid_cidr"
        return str(net), None
    return None, "invalid_value_type"


def _parse_whitelist_expires_at(raw: Any) -> Optional[datetime]:
    if raw in (None, ""):
        return None
    dt = _parse_iso(str(raw))
    if dt is None:
        raise ValueError("invalid_expires_at")
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _response_whitelist_match(target_type: str, target: str) -> Optional[ResponseWhitelistEntry]:
    now = datetime.now(timezone.utc)
    rows = (
        db.session.query(ResponseWhitelistEntry)
        .filter(
            ResponseWhitelistEntry.tenant_id == _current_tenant_id(),
            ResponseWhitelistEntry.status == "active",
            ResponseWhitelistEntry.scope.in_(tuple(WHITELIST_SCOPES)),
        )
        .all()
    )
    for row in rows:
        expires_at = row.expires_at
        if expires_at is not None:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= now:
                continue
        if row.value_type == target_type and row.value == target:
            return row
        if target_type == "ip" and row.value_type == "cidr":
            try:
                if ipaddress.ip_address(target) in ipaddress.ip_network(row.value, strict=False):
                    return row
            except ValueError:
                continue
        if target_type == "cidr" and row.value_type == "cidr":
            try:
                if ipaddress.ip_network(target, strict=False).subnet_of(
                    ipaddress.ip_network(row.value, strict=False)
                ):
                    return row
            except ValueError:
                continue
    return None


def _response_whitelist_check_payload(target: str) -> Dict[str, Any]:
    normalized = str(target or "").strip()
    eligibility = check_real_ban_eligibility(
        normalized,
        tenant_id=_current_tenant_id(),
        use_db_whitelist=True,
    )
    matched = None
    if eligibility.matched_whitelist_id is not None:
        row = tenant_get(db.session, ResponseWhitelistEntry, eligibility.matched_whitelist_id)
        if row is not None:
            matched = _response_whitelist_to_api_dict(row)
    return {
        "target": normalized,
        "allowed": eligibility.allowed,
        "reason": eligibility.rejection_reason,
        "matched": matched,
        "dry_run": _response_dry_run(),
        "gate": _response_gate(),
    }


def _append_response_action_event(
    action: ResponseAction,
    *,
    status: str,
    reason: str,
    actor: str,
    extra: Optional[Dict[str, Any]] = None,
    commit: bool = False,
) -> None:
    meta = dict(action.meta or {})
    history = list(meta.get("history") or [])
    history.append(
        {
            "status": status,
            "reason": reason,
            "actor": actor,
            "at": _now_iso(),
        }
    )
    meta["history"] = history
    meta["reason"] = reason
    if extra:
        meta.update(extra)
    action.status = status
    action.meta = meta
    db.session.add(
        AuditEvent(
            tenant_id=_current_tenant_id(),
            event_type=f"response.action.{status}"[:64],
            actor=actor[:128],
            resource_type="response_action",
            resource_id=str(action.id) if action.id is not None else None,
            payload={
                "response_action_id": action.id,
                "action_type": action.action_type,
                "target": action.target,
                "status": status,
                "dry_run": action.dry_run,
                "gate": _response_gate(),
                "reason": reason,
                **(extra or {}),
            },
            ip_address=action.target if validate_ip(str(action.target or "")) else None,
        )
    )
    if commit:
        db.session.commit()


def _response_json_ok(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(value.get("ok"))
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return False
        return isinstance(parsed, dict) and bool(parsed.get("ok"))
    return False


def _response_env_whitelist_valid_count(raw: str) -> int:
    count = 0
    for part in (raw or "").split(","):
        item = part.strip()
        if not item:
            continue
        try:
            if "/" in item:
                net = ipaddress.ip_network(item, strict=False)
                if net.version == 4:
                    count += 1
            else:
                addr = ipaddress.ip_address(item)
                if addr.version == 4:
                    count += 1
        except ValueError:
            continue
    return count


def _real_response_provider_available(
    provider: Optional[ResponseProviderConfig],
    *,
    require_validated: bool = True,
) -> Optional[str]:
    if provider is None:
        return "provider_required"
    if provider.tenant_id != _current_tenant_id():
        return "provider_not_found"
    if provider.status != "active":
        return "provider_not_active"
    if provider.provider_type in {"cloud_security_group", "edr"}:
        return "provider_not_implemented"
    if provider.provider_type != "iptables":
        return "provider_not_supported"
    if require_validated and (
        provider.last_validated_at is None
        or not _response_json_ok(provider.last_validation_result)
    ):
        return "provider_validation_required"
    return None


def _real_response_business_whitelist_issue() -> Optional[Dict[str, Any]]:
    raw = os.environ.get("RESPONSE_BUSINESS_IP_WHITELIST", "")
    if raw.strip():
        valid_count = _response_env_whitelist_valid_count(raw)
        if valid_count > 0:
            return None
        return {
            "code": "business_whitelist_invalid",
            "name": "RESPONSE_BUSINESS_IP_WHITELIST",
            "message": (
                "env RESPONSE_BUSINESS_IP_WHITELIST is set but contains no "
                "valid IPv4/CIDR entry"
            ),
        }
    count = (
        db.session.query(ResponseWhitelistEntry)
        .filter(
            ResponseWhitelistEntry.tenant_id == _current_tenant_id(),
            ResponseWhitelistEntry.status == "active",
            ResponseWhitelistEntry.scope.in_(tuple(WHITELIST_SCOPES)),
            ResponseWhitelistEntry.value_type.in_(("ip", "cidr")),
        )
        .count()
    )
    if count > 0:
        return None
    return {
        "code": "business_whitelist_required",
        "name": "response_whitelist_entries",
        "message": (
            "missing business whitelist evidence: set RESPONSE_BUSINESS_IP_WHITELIST "
            "to valid IPv4/CIDR entries or add an active DB row in "
            "response_whitelist_entries before DRY_RUN=false"
        ),
    }


def _real_response_recovery_drill_issue() -> Optional[Dict[str, Any]]:
    count = (
        db.session.query(ResponseDrill)
        .filter(
            ResponseDrill.tenant_id == _current_tenant_id(),
            ResponseDrill.status == "passed",
            ResponseDrill.drill_type.in_(
                ("real_ban_unblock", "provider_rollback", "misblock_recovery")
            ),
            ResponseDrill.ended_at.isnot(None),
        )
        .count()
    )
    if count > 0:
        return None
    return {
        "code": "recovery_drill_required",
        "name": "response_drills",
        "message": (
            "missing recovery drill DB record: response_drills needs a passed "
            "real_ban_unblock/provider_rollback/misblock_recovery row with ended_at "
            "before DRY_RUN=false"
        ),
    }


def _real_response_admission_failures(provider: Optional[ResponseProviderConfig]) -> List[Dict[str, Any]]:
    failures = real_enforcement_env_failures(gate_value=_response_gate(), include_gate=True)
    whitelist_issue = _real_response_business_whitelist_issue()
    if whitelist_issue is not None:
        failures.append(whitelist_issue)
    provider_issue = _real_response_provider_available(provider, require_validated=True)
    if provider_issue:
        failures.append(
            {
                "code": provider_issue,
                "name": "response_provider_configs",
                "message": (
                    "missing provider validation DB evidence: active iptables provider "
                    "config must have last_validated_at and last_validation_result.ok=true"
                    if provider_issue == "provider_validation_required"
                    else "missing active supported provider config for real response"
                ),
            }
        )
    drill_issue = _real_response_recovery_drill_issue()
    if drill_issue is not None:
        failures.append(drill_issue)
    return failures


def _create_response_schedule(action: ResponseAction, approval: ResponseApproval) -> None:
    if not action.scheduled_unblock_at:
        return
    payload = {
        "tenant_id": _current_tenant_id(),
        "ip": action.target,
        "dry_run": action.dry_run,
        "provider": approval.provider,
        "provider_config_id": approval.provider_config_id,
        "approval_id": approval.id,
        "gate_id": approval.gate_id,
    }
    db.session.add(
        ResponseScheduleTask(
            tenant_id=_current_tenant_id(),
            task_type="scheduled_unblock",
            alert_id=action.alert_id,
            payload=payload,
            run_at=action.scheduled_unblock_at,
            status="pending",
            related_response_action_id=action.id,
        )
    )


def _delete_banned_ip_persistent(ip: str) -> bool:
    row = (
        tenant_query(db.session.query(BannedIp), BannedIp)
        .filter(BannedIp.ip == ip)
        .one_or_none()
    )
    if row is None:
        return False
    db.session.delete(row)
    db.session.commit()
    return True


def _rule_row_to_api_dict(row: Rule) -> Dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "type": row.rule_type,
        "pattern": row.pattern,
        "action": row.action,
        "level": row.level,
        "priority": row.priority,
        "enabled": row.enabled,
        "description": row.description or "",
        "hits": int(row.hits or 0),
        "created_at": _dt_iso(row.created_at),
        "updated_at": _dt_iso(row.updated_at),
    }


def _list_rules_from_db(
    *,
    type_: Optional[str],
    enabled: Optional[bool],
    q: Optional[str],
) -> List[Dict[str, Any]]:
    query = tenant_query(db.session.query(Rule), Rule)
    if type_:
        query = query.filter(Rule.rule_type == type_)
    if enabled is not None:
        query = query.filter(Rule.enabled.is_(enabled))
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(
            or_(
                Rule.name.ilike(like),
                Rule.description.ilike(like),
                Rule.pattern.ilike(like),
                Rule.rule_type.ilike(like),
                Rule.action.ilike(like),
            )
        )
    rows = query.order_by(Rule.priority.asc(), Rule.updated_at.desc()).all()
    items = [_rule_row_to_api_dict(r) for r in rows]
    return items


def _insert_rule_from_normalized(norm: Dict[str, Any]) -> Rule:
    rid = _uuid()
    now = datetime.now(timezone.utc)
    row = Rule(
        id=rid,
        tenant_id=_current_tenant_id(),
        name=norm["name"],
        rule_type=norm["type"],
        pattern=norm["pattern"],
        action=norm["action"],
        level=norm["level"],
        priority=int(norm.get("priority", 100)),
        enabled=bool(norm.get("enabled", True)),
        description=norm.get("description"),
        hits=0,
        created_at=now,
        updated_at=now,
    )
    db.session.add(row)
    db.session.commit()
    db.session.refresh(row)
    return row


def _apply_partial_to_rule_row(row: Rule, partial: Dict[str, Any]) -> None:
    if "name" in partial:
        row.name = partial["name"]
    if "type" in partial:
        row.rule_type = partial["type"]
    if "pattern" in partial:
        row.pattern = partial["pattern"]
    if "action" in partial:
        row.action = partial["action"]
    if "level" in partial:
        row.level = partial["level"]
    if "priority" in partial:
        row.priority = int(partial["priority"])
    if "enabled" in partial:
        row.enabled = bool(partial["enabled"])
    if "description" in partial:
        row.description = partial["description"]
    row.updated_at = datetime.now(timezone.utc)


def _incr_rule_hits_db(rule_id: str, delta: int = 1) -> None:
    row = tenant_get(db.session, Rule, rule_id)
    if row:
        row.hits = int(row.hits or 0) + delta
        db.session.commit()


def _active_ioc_count() -> int:
    now = datetime.now(timezone.utc)
    return (
        db.session.query(func.count(IOC.id))
        .filter(
            IOC.tenant_id == _current_tenant_id(),
            (IOC.expires_at.is_(None)) | (IOC.expires_at > now),
        )
        .scalar()
        or 0
    )


def _rules_enabled_count() -> int:
    return (
        db.session.query(func.count(Rule.id))
        .filter(Rule.tenant_id == _current_tenant_id(), Rule.enabled.is_(True))
        .scalar()
        or 0
    )


def _rules_total_count() -> int:
    return (
        db.session.query(func.count(Rule.id))
        .filter(Rule.tenant_id == _current_tenant_id())
        .scalar()
        or 0
    )


def _compute_security_score_db() -> int:
    """基于数据库告警分布的启发式安全分（与仪表盘一致）。"""
    critical = high = open_n = 0
    rows = (
        db.session.query(Alert.level, Alert.status, func.count(Alert.id))
        .filter(Alert.tenant_id == _current_tenant_id())
        .group_by(Alert.level, Alert.status)
        .all()
    )
    for level, status, count in rows:
        n = int(count or 0)
        if level == "critical":
            critical += n
        elif level == "high":
            high += n
        if status == "open":
            open_n += n
    return max(0, min(100, 100 - min(60, critical * 8 + high * 3 + open_n * 2)))


def _incr_ioc_hit_db(ioc_type: str, canon_value: str) -> None:
    row = (
        db.session.query(IOC)
        .filter(
            IOC.tenant_id == _current_tenant_id(),
            IOC.ioc_type == ioc_type,
            IOC.value == canon_value,
        )
        .one_or_none()
    )
    if row:
        row.hits = int(row.hits or 0) + 1
        db.session.commit()


# =====================================================================
# 页面路由
# =====================================================================
# 合法的页面名白名单，避免模板穿越
_PAGE_WHITELIST: Dict[str, str] = {
    "dashboard": "dashboard.html",
    "alerts": "alerts.html",
    "threat_intel": "threat_intel.html",
    "rules": "rules.html",
    "reports": "reports.html",
    "command": "command.html",
    "saas_admin": "saas_admin.html",
    "settings": "settings.html",
}


def _register_page_routes(app: Flask) -> None:
    """注册模板渲染路由。

    服务器端只渲染页面骨架，JWT 在浏览器侧由 `utils.js` 校验；
    页面本身不含敏感数据，所有真实数据通过受保护的 `/api/*` 拉取。
    """

    @app.route("/")
    def index():  # type: ignore[unused-function]
        return redirect(url_for("page_dashboard"))

    @app.route("/login")
    def page_login():  # type: ignore[unused-function]
        return render_template("login.html", page="login")

    # 为每个合法页面生成独立视图函数
    for slug, template in _PAGE_WHITELIST.items():

        def _view(slug: str = slug, template: str = template):
            return render_template(template, page=slug)

        _view.__name__ = f"page_{slug}"
        app.add_url_rule(f"/{slug}", endpoint=f"page_{slug}", view_func=_view)


# =====================================================================
# REST API
# =====================================================================
def _register_api_routes(app: Flask, limiter: Limiter, state: _ServerState) -> None:
    # ---- 健康检查（匿名） --------------------------------------------
    @app.route("/api/health")
    @limiter.exempt
    def health_check():  # type: ignore[unused-function]
        from web.observability_routes import build_api_health_payload

        payload = build_api_health_payload(app)
        return (
            jsonify(
                {
                    **payload,
                    "frontend_safe": True,
                }
            ),
            200,
        )

    # ---- 登录 / Token 刷新 / 当前用户 --------------------------------
    @app.route("/api/auth/login", methods=["POST"])
    @limiter.limit("5 per minute")
    def auth_login():  # type: ignore[unused-function]
        data = request.get_json(silent=True) or {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))

        if not username or not password:
            return (
                jsonify(
                    _error_payload(
                        code="bad_request",
                        message="username 与 password 必填",
                    )
                ),
                400,
            )

        # Phase 8：优先走 ADMIN_PASSWORD_HASH（Werkzeug pbkdf2:sha256），
        # 明文 ADMIN_PASSWORD 仅作向后兼容，命中即打印安全警告。
        # 详见 src/utils/auth.py。
        if not verify_admin_credentials(username, password):
            logger.warning("[Auth] 登录失败: user=%s from %s", username, get_remote_address())
            _record_audit_event(
                event_type="auth.login_failed",
                actor=username or "anonymous",
                resource_type="auth",
                resource_id=username or None,
                payload={"reason": "bad_credentials"},
            )
            return (
                jsonify(
                    _error_payload(
                        code="auth_failed",
                        message="用户名或密码错误",
                    )
                ),
                401,
            )

        requested_tenant_id = str(data.get("tenant_id") or "").strip()
        tenant_id, role = _resolve_login_context(username, requested_tenant_id)
        claims = {"role": role, "tenant_id": tenant_id}
        access_token = create_access_token(identity=username, additional_claims=claims)
        refresh_token = create_refresh_token(identity=username, additional_claims=claims)
        _record_audit_event(
            event_type="auth.login_success",
            actor=username,
            resource_type="auth",
            resource_id=username,
            payload={"role": role, "tenant_id": tenant_id},
        )
        return (
            jsonify(
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "bearer",
                    "username": username,
                    "role": role,
                    "tenant_id": tenant_id,
                }
            ),
            200,
        )

    @app.route("/api/auth/refresh", methods=["POST"])
    @jwt_required(refresh=True)
    def auth_refresh():  # type: ignore[unused-function]
        identity = get_jwt_identity()
        role = _current_role()
        tenant_id = _current_tenant_id()
        _record_audit_event(
            event_type="auth.refresh_success",
            actor=str(identity or "operator"),
            resource_type="auth",
            resource_id=str(identity or ""),
            payload={"role": role, "tenant_id": tenant_id},
        )
        return (
            jsonify(
                {
                    "access_token": create_access_token(
                        identity=identity,
                        additional_claims={
                            "role": role,
                            "tenant_id": tenant_id,
                        },
                    )
                }
            ),
            200,
        )

    @app.route("/api/auth/me")
    @_auth_required()
    def auth_me():  # type: ignore[unused-function]
        return (
            jsonify(
                {
                    "username": _current_actor(),
                    "role": _current_role(),
                    "tenant_id": _current_tenant_id(),
                    "auth_method": _current_auth_method(),
                }
            ),
            200,
        )

    # ---- SaaS 平台控制面 --------------------------------------------
    @app.route("/api/admin/saas/tenants", methods=["GET", "POST"])
    @_require_platform_admin()
    def saas_tenants():  # type: ignore[unused-function]
        if request.method == "GET":
            status = str(request.args.get("status") or "").strip().lower()
            q = str(request.args.get("q") or "").strip()
            query = db.session.query(Tenant)
            if status:
                if status not in TENANT_STATUSES:
                    return jsonify(_error_payload(code="bad_request", message="status 非法")), 400
                query = query.filter(Tenant.status == status)
            if q:
                like = f"%{q}%"
                query = query.filter(or_(Tenant.id.like(like), Tenant.name.like(like), Tenant.slug.like(like)))
            rows = query.order_by(Tenant.created_at.desc()).all()
            return jsonify({"items": [_tenant_admin_summary(row) for row in rows]}), 200

        payload = request.get_json(silent=True) or {}
        name = str(payload.get("name") or "").strip()
        slug = str(payload.get("slug") or "").strip().lower()
        tenant_id = str(payload.get("id") or f"tenant_{uuid.uuid4().hex[:12]}").strip()
        status = str(payload.get("status") or "active").strip().lower()
        plan_code = str(payload.get("plan_code") or payload.get("plan") or "").strip()
        if not name or not slug:
            return jsonify(_error_payload(code="bad_request", message="name 与 slug 必填")), 400
        if status not in TENANT_STATUSES:
            return jsonify(_error_payload(code="bad_request", message="status 必须是 active、suspended、expired")), 400
        row = Tenant(id=tenant_id[:64], name=name[:160], slug=slug[:80], status=status, plan=plan_code[:64] or None)
        db.session.add(row)
        db.session.flush()
        db.session.add(
            Organization(
                id=f"org_{uuid.uuid4().hex[:12]}",
                tenant_id=row.id,
                name=f"{row.name} Organization",
                slug="default",
                status="active",
            )
        )
        if plan_code:
            plan = db.session.query(Plan).filter(Plan.code == plan_code).one_or_none()
            if plan is None:
                db.session.rollback()
                return jsonify(_error_payload(code="bad_request", message="plan_code 不存在")), 400
            db.session.add(
                Subscription(
                    id=f"sub_{uuid.uuid4().hex}",
                    tenant_id=row.id,
                    plan_id=plan.id,
                    status="active",
                )
            )
            sync_quota_rows(db.session, row.id)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify(_error_payload(code="conflict", message="租户 id 或 slug 已存在")), 409
        _record_audit_event(
            event_type="saas.tenant.created",
            actor=_current_actor(),
            resource_type="tenant",
            resource_id=row.id,
            payload={"name": row.name, "slug": row.slug, "status": row.status, "plan": row.plan},
        )
        return jsonify(_tenant_admin_detail(row)), 201

    @app.route("/api/admin/saas/tenants/<tenant_id>", methods=["GET", "PATCH"])
    @_require_platform_admin()
    def saas_tenant_detail(tenant_id: str):  # type: ignore[unused-function]
        row = db.session.get(Tenant, tenant_id)
        if row is None:
            return jsonify(_error_payload(code="not_found", message="租户不存在")), 404
        if request.method == "GET":
            return jsonify(_tenant_admin_detail(row)), 200

        payload = request.get_json(silent=True) or {}
        changed: Dict[str, Any] = {}
        for field, max_len in (("name", 160), ("slug", 80)):
            if field in payload:
                value = str(payload.get(field) or "").strip()
                if not value:
                    return jsonify(_error_payload(code="bad_request", message=f"{field} 不能为空")), 400
                setattr(row, field, value[:max_len])
                changed[field] = getattr(row, field)
        if "status" in payload:
            status = str(payload.get("status") or "").strip().lower()
            if status not in TENANT_STATUSES:
                return jsonify(_error_payload(code="bad_request", message="status 必须是 active、suspended、expired")), 400
            row.status = status
            changed["status"] = status
        row.updated_at = datetime.now(timezone.utc)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify(_error_payload(code="conflict", message="租户 slug 已存在")), 409
        _record_audit_event(
            event_type="saas.tenant.updated",
            actor=_current_actor(),
            resource_type="tenant",
            resource_id=row.id,
            payload=changed,
        )
        return jsonify(_tenant_admin_detail(row)), 200

    @app.route("/api/admin/saas/plans", methods=["GET", "POST"])
    @_require_platform_admin()
    def saas_plans():  # type: ignore[unused-function]
        if request.method == "GET":
            rows = db.session.query(Plan).order_by(Plan.created_at.asc()).all()
            return jsonify({"items": [_plan_to_api_dict(row) for row in rows]}), 200
        payload = request.get_json(silent=True) or {}
        code = str(payload.get("code") or "").strip()
        name = str(payload.get("name") or "").strip()
        limits, err = _normalize_limits(payload.get("limits") or {})
        status = str(payload.get("status") or "active").strip().lower()
        if not code or not name:
            return jsonify(_error_payload(code="bad_request", message="code 与 name 必填")), 400
        if err:
            return jsonify(_error_payload(code="bad_request", message=err)), 400
        if status not in ("active", "disabled"):
            return jsonify(_error_payload(code="bad_request", message="status 必须是 active 或 disabled")), 400
        row = Plan(id=f"plan_{uuid.uuid4().hex}", code=code[:64], name=name[:160], status=status, limits=limits)
        db.session.add(row)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify(_error_payload(code="conflict", message="套餐 code 已存在")), 409
        _record_audit_event(
            event_type="saas.plan.created",
            actor=_current_actor(),
            resource_type="plan",
            resource_id=row.id,
            payload={"code": row.code, "limits": limits},
        )
        return jsonify(_plan_to_api_dict(row)), 201

    @app.route("/api/admin/saas/tenants/<tenant_id>/subscription", methods=["PUT"])
    @_require_platform_admin()
    def saas_bind_subscription(tenant_id: str):  # type: ignore[unused-function]
        tenant = db.session.get(Tenant, tenant_id)
        if tenant is None:
            return jsonify(_error_payload(code="not_found", message="租户不存在")), 404
        payload = request.get_json(silent=True) or {}
        plan_id = str(payload.get("plan_id") or "").strip()
        plan_code = str(payload.get("plan_code") or "").strip()
        license_key_id = str(payload.get("license_key_id") or "").strip() or None
        status = str(payload.get("status") or "active").strip().lower()
        if status not in ("active", "disabled", "expired"):
            return jsonify(_error_payload(code="bad_request", message="订阅 status 非法")), 400
        plan = None
        if plan_id:
            plan = db.session.get(Plan, plan_id)
        elif plan_code:
            plan = db.session.query(Plan).filter(Plan.code == plan_code).one_or_none()
        if plan is None and not license_key_id:
            return jsonify(_error_payload(code="bad_request", message="plan_id/plan_code 或 license_key_id 必填")), 400
        # tenant-scan: allow platform admin binds a tenant-scoped license after route tenant check.
        if license_key_id and db.session.get(LicenseKey, license_key_id) is None:
            return jsonify(_error_payload(code="bad_request", message="license_key_id 不存在")), 400
        now = datetime.now(timezone.utc)
        db.session.query(Subscription).filter(
            Subscription.tenant_id == tenant_id,
            Subscription.status == "active",
        ).update({"status": "disabled", "updated_at": now})
        sub = Subscription(
            id=f"sub_{uuid.uuid4().hex}",
            tenant_id=tenant_id,
            plan_id=plan.id if plan is not None else None,
            license_key_id=license_key_id,
            status=status,
            ends_at=_aware_utc(_parse_iso(str(payload.get("ends_at") or "").strip())),
        )
        tenant.plan = plan.code if plan is not None else tenant.plan
        tenant.updated_at = now
        db.session.add(sub)
        sync_quota_rows(db.session, tenant_id)
        db.session.commit()
        _record_audit_event(
            event_type="saas.subscription.bound",
            actor=_current_actor(),
            resource_type="subscription",
            resource_id=sub.id,
            payload={"tenant_id": tenant_id, "plan_id": sub.plan_id, "license_key_id": sub.license_key_id, "status": sub.status},
        )
        return jsonify(_subscription_to_api_dict(sub)), 200

    @app.route("/api/admin/saas/tenants/<tenant_id>/licenses", methods=["POST"])
    @_require_platform_admin()
    def saas_create_license(tenant_id: str):  # type: ignore[unused-function]
        if db.session.get(Tenant, tenant_id) is None:
            return jsonify(_error_payload(code="not_found", message="租户不存在")), 404
        payload = request.get_json(silent=True) or {}
        limits, err = _normalize_limits(payload.get("limits") or {})
        if err:
            return jsonify(_error_payload(code="bad_request", message=err)), 400
        status = str(payload.get("status") or "active").strip().lower()
        if status not in ("active", "disabled"):
            return jsonify(_error_payload(code="bad_request", message="License status 必须是 active 或 disabled")), 400
        secret = f"lic_{secrets.token_urlsafe(24)}"
        row = LicenseKey(
            id=f"lic_{uuid.uuid4().hex}",
            tenant_id=tenant_id,
            key_prefix=secret[:16],
            key_hash=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
            status=status,
            limits=limits or None,
            issued_to=str(payload.get("issued_to") or "").strip()[:160] or None,
            expires_at=_aware_utc(_parse_iso(str(payload.get("expires_at") or "").strip())),
        )
        db.session.add(row)
        db.session.commit()
        _record_audit_event(
            event_type="saas.license.created",
            actor=_current_actor(),
            resource_type="license",
            resource_id=row.id,
            payload={"tenant_id": tenant_id, "status": row.status, "limits": limits},
        )
        data = _license_to_api_dict(row)
        data["license_key"] = secret
        return jsonify(data), 201

    @app.route("/api/admin/saas/tenants/<tenant_id>/licenses/<license_id>/status", methods=["PATCH"])
    @_require_platform_admin()
    def saas_update_license_status(tenant_id: str, license_id: str):  # type: ignore[unused-function]
        # tenant-scan: allow followed immediately by row.tenant_id == route tenant_id check.
        row = db.session.get(LicenseKey, license_id)
        if row is None or row.tenant_id != tenant_id:
            return jsonify(_error_payload(code="not_found", message="License 不存在")), 404
        payload = request.get_json(silent=True) or {}
        status = str(payload.get("status") or "").strip().lower()
        if status not in ("active", "disabled"):
            return jsonify(_error_payload(code="bad_request", message="status 必须是 active 或 disabled")), 400
        row.status = status
        row.updated_at = datetime.now(timezone.utc)
        sync_quota_rows(db.session, tenant_id)
        db.session.commit()
        _record_audit_event(
            event_type="saas.license.status_updated",
            actor=_current_actor(),
            resource_type="license",
            resource_id=row.id,
            payload={"tenant_id": tenant_id, "status": status},
        )
        return jsonify(_license_to_api_dict(row)), 200

    @app.route("/api/admin/saas/tenants/<tenant_id>/licenses/<license_id>", methods=["PATCH"])
    @_require_platform_admin()
    def saas_update_license(tenant_id: str, license_id: str):  # type: ignore[unused-function]
        # tenant-scan: allow followed immediately by row.tenant_id == route tenant_id check.
        row = db.session.get(LicenseKey, license_id)
        if row is None or row.tenant_id != tenant_id:
            return jsonify(_error_payload(code="not_found", message="License 不存在")), 404
        payload = request.get_json(silent=True) or {}
        changed: Dict[str, Any] = {}
        if "status" in payload:
            status = str(payload.get("status") or "").strip().lower()
            if status not in ("active", "disabled"):
                return jsonify(_error_payload(code="bad_request", message="status 必须是 active 或 disabled")), 400
            row.status = status
            changed["status"] = status
        if "expires_at" in payload:
            raw_expires = str(payload.get("expires_at") or "").strip()
            if raw_expires:
                parsed = _parse_iso(raw_expires)
                if parsed is None:
                    return jsonify(_error_payload(code="bad_request", message="expires_at 必须是 ISO 时间")), 400
                row.expires_at = _aware_utc(parsed)
            else:
                row.expires_at = None
            changed["expires_at"] = _dt_iso(row.expires_at)
        if "issued_to" in payload:
            row.issued_to = str(payload.get("issued_to") or "").strip()[:160] or None
            changed["issued_to"] = row.issued_to
        if "limits" in payload:
            limits, err = _normalize_limits(payload.get("limits") or {})
            if err:
                return jsonify(_error_payload(code="bad_request", message=err)), 400
            row.limits = limits or None
            changed["limits"] = limits
        if not changed:
            return jsonify(_error_payload(code="bad_request", message="没有可更新字段")), 400
        row.updated_at = datetime.now(timezone.utc)
        sync_quota_rows(db.session, tenant_id)
        db.session.commit()
        _record_audit_event(
            event_type="saas.license.updated",
            actor=_current_actor(),
            resource_type="license",
            resource_id=row.id,
            payload={"tenant_id": tenant_id, **changed},
        )
        return jsonify(_license_to_api_dict(row)), 200

    @app.route("/api/admin/saas/tenants/<tenant_id>/usage", methods=["GET"])
    @_require_platform_admin()
    def saas_tenant_usage(tenant_id: str):  # type: ignore[unused-function]
        if db.session.get(Tenant, tenant_id) is None:
            return jsonify(_error_payload(code="not_found", message="租户不存在")), 404
        sync_quota_rows(db.session, tenant_id)
        db.session.commit()
        metric = str(request.args.get("metric") or "").strip()
        if metric and metric not in METERED_METRICS:
            return jsonify(_error_payload(code="bad_request", message="未知配额指标")), 400
        period = str(request.args.get("period") or "").strip()
        if period and not re.fullmatch(r"\d{4}-\d{2}|current", period):
            return jsonify(_error_payload(code="bad_request", message="period 必须是 YYYY-MM 或 current")), 400
        metrics = [metric] if metric else sorted(METERED_METRICS)
        items = [_quota_usage_to_api_dict(tenant_id, item) for item in metrics]
        buckets = [_usage_bucket_to_api_dict(row) for row in usage_buckets(
            db.session,
            tenant_id,
            metric=metric or None,
            period=period or None,
        )]
        return jsonify(
            {
                "tenant_id": tenant_id,
                "period": period or usage_period(),
                "items": items,
                "buckets": buckets,
            }
        ), 200

    @app.route("/api/admin/saas/tenants/<tenant_id>/quotas/<metric>", methods=["PUT"])
    @_require_platform_admin()
    def saas_update_quota(tenant_id: str, metric: str):  # type: ignore[unused-function]
        if db.session.get(Tenant, tenant_id) is None:
            return jsonify(_error_payload(code="not_found", message="租户不存在")), 404
        if metric not in METERED_METRICS:
            return jsonify(_error_payload(code="bad_request", message="未知配额指标")), 400
        payload = request.get_json(silent=True) or {}
        raw_limit = payload.get("limit")
        limit: Optional[int]
        if raw_limit is None or raw_limit == "":
            limit = None
        else:
            try:
                limit = int(raw_limit)
            except (TypeError, ValueError):
                return jsonify(_error_payload(code="bad_request", message="limit 必须是整数或 null")), 400
            if limit < 0:
                return jsonify(_error_payload(code="bad_request", message="limit 不能为负数")), 400
        row = (
            db.session.query(Quota)
            .filter(Quota.tenant_id == tenant_id, Quota.metric == metric)
            .one_or_none()
        )
        if row is None:
            row = Quota(tenant_id=tenant_id, metric=metric, limit=limit, source="manual")
            db.session.add(row)
        else:
            row.limit = limit
            row.source = "manual"
            row.updated_at = datetime.now(timezone.utc)
        thresholds = payload.get("warning_thresholds")
        if thresholds is not None:
            normalized_thresholds, threshold_err = _normalize_warning_thresholds_payload(thresholds)
            if threshold_err:
                return jsonify(_error_payload(code="bad_request", message=threshold_err)), 400
            row.warning_thresholds = normalized_thresholds
        policy = str(payload.get("overage_policy") or "").strip()
        if policy:
            if policy not in OVERAGE_POLICIES:
                return jsonify(_error_payload(code="bad_request", message="未知超额策略")), 400
            row.overage_policy = policy
        db.session.commit()
        _record_audit_event(
            event_type="saas.quota.updated",
            actor=_current_actor(),
            resource_type="quota",
            resource_id=f"{tenant_id}:{metric}",
            payload={
                "tenant_id": tenant_id,
                "metric": metric,
                "limit": limit,
                "warning_thresholds": row.warning_thresholds,
                "overage_policy": row.overage_policy,
            },
        )
        return jsonify(_quota_usage_to_api_dict(tenant_id, metric)), 200

    @app.route("/api/tenant/commercial/status", methods=["GET"])
    @_require_role("admin")
    def tenant_commercial_status():  # type: ignore[unused-function]
        tenant = db.session.get(Tenant, _current_tenant_id())
        if tenant is None:
            return jsonify(_error_payload(code="not_found", message="租户不存在")), 404
        sync_quota_rows(db.session, tenant.id)
        db.session.commit()
        return jsonify(_tenant_commercial_status(tenant)), 200

    @app.route("/api/auth/api_keys", methods=["GET", "POST"])
    @_require_role("admin")
    def api_keys():  # type: ignore[unused-function]
        if request.method == "GET":
            rows = (
                tenant_query(db.session.query(APIKey), APIKey)
                .order_by(APIKey.created_at.desc())
                .all()
            )
            return jsonify({"items": [_api_key_to_api_dict(row) for row in rows]}), 200

        payload = request.get_json(silent=True) or {}
        name = str(payload.get("name") or "").strip()
        role = str(payload.get("role") or "viewer").strip().lower()
        expires_at = _aware_utc(_parse_iso(str(payload.get("expires_at") or "").strip()))
        if not name:
            return jsonify(_error_payload(code="bad_request", message="name 必填")), 400
        if role not in RBAC_ROLES:
            return jsonify({"error": f"role 必须是 {list(RBAC_ROLES)}"}), 400
        if expires_at is None:
            return jsonify(_error_payload(code="bad_request", message="expires_at 必填且必须为 ISO 时间")), 400
        if expires_at <= datetime.now(timezone.utc):
            return jsonify(_error_payload(code="bad_request", message="expires_at 必须是未来时间")), 400

        try:
            ensure_quota(db.session, _current_tenant_id(), METRIC_USERS, requested=0)
        except QuotaExceededError as exc:
            return quota_error_response(exc)

        secret = f"gk_{secrets.token_urlsafe(32)}"
        row = APIKey(
            id=uuid.uuid4().hex,
            tenant_id=_current_tenant_id(),
            name=name[:160],
            key_prefix=secret[:16],
            key_hash=_hash_api_key(secret),
            role=role,
            scopes=list(payload.get("scopes") or []),
            status="active",
            expires_at=expires_at,
        )
        db.session.add(row)
        db.session.commit()
        _record_audit_event(
            event_type="api_key.created",
            actor=_current_actor(),
            resource_type="api_key",
            resource_id=row.id,
            payload={"name": row.name, "role": row.role, "expires_at": row.expires_at.isoformat()},
        )
        return jsonify(_api_key_to_api_dict(row, include_secret=secret)), 201

    @app.route("/api/auth/api_keys/<key_id>/status", methods=["PATCH"])
    @_require_role("admin")
    def api_update_key_status(key_id: str):  # type: ignore[unused-function]
        row = tenant_get(db.session, APIKey, key_id)
        if not row:
            return jsonify({"error": "API Key 不存在"}), 404
        payload = request.get_json(silent=True) or {}
        status = str(payload.get("status") or "").strip().lower()
        if status not in ("active", "disabled"):
            return jsonify({"error": "status 必须是 active 或 disabled"}), 400
        row.status = status
        row.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        _record_audit_event(
            event_type="api_key.status_updated",
            actor=_current_actor(),
            resource_type="api_key",
            resource_id=row.id,
            payload={"status": status},
        )
        return jsonify(_api_key_to_api_dict(row)), 200

    # ---- 态势统计 ----------------------------------------------------
    @app.route("/api/stats")
    @_auth_required()
    def api_stats():  # type: ignore[unused-function]
        cache_key = _api_cache_key("stats")
        cached = _api_cache_get(cache_key)
        if cached is not None:
            return jsonify(cached), 200

        total_threats = 0
        critical = high = open_n = 0
        alert_rows = (
            db.session.query(Alert.level, Alert.status, func.count(Alert.id))
            .filter(Alert.tenant_id == _current_tenant_id())
            .group_by(Alert.level, Alert.status)
            .all()
        )
        for level, status, count in alert_rows:
            n = int(count or 0)
            total_threats += n
            if level == "critical":
                critical += n
            elif level == "high":
                high += n
            if status == "open":
                open_n += n
        state.stats["total_threats"] = total_threats
        state.stats["banned_ips"] = (
            db.session.query(func.count(BannedIp.ip))
            .filter(BannedIp.tenant_id == _current_tenant_id())
            .scalar()
            or 0
        )
        state.stats["security_score"] = max(
            0, min(100, 100 - min(60, critical * 8 + high * 3 + open_n * 2))
        )
        state.stats["updated_at"] = _now_iso()
        payload = dict(state.stats)
        _api_cache_set(cache_key, payload)
        return jsonify(payload), 200

    # ---- 告警列表 / 详情 / 状态流转 / 类型聚合 -----------------------
    @app.route("/api/alerts")
    @_auth_required()
    def api_alerts():  # type: ignore[unused-function]
        limit = _safe_int(request.args.get("limit"), default=100, max_value=500)
        offset = _safe_int(request.args.get("offset"), default=0, max_value=10_000, allow_zero=True)
        level = request.args.get("level") or None
        threat_type = request.args.get("type") or None
        status_filter = request.args.get("status") or None
        q = request.args.get("q") or None
        since_raw = request.args.get("since")
        until_raw = request.args.get("until")
        since = _parse_iso(since_raw) if since_raw else None
        until = _parse_iso(until_raw) if until_raw else None

        if level and level not in ALERT_LEVELS:
            return (
                jsonify(
                    _error_payload(
                        code="invalid_level",
                        message="level 非法",
                    )
                ),
                400,
            )
        if status_filter and status_filter not in ALERT_STATUSES:
            return (
                jsonify(
                    _error_payload(
                        code="invalid_status",
                        message="status 非法",
                    )
                ),
                400,
            )

        items, total = _query_alerts_from_db(
            limit=limit,
            offset=offset,
            level=level,
            threat_type=threat_type,
            status=status_filter,
            since=since,
            until=until,
            q=q,
        )
        resp = jsonify(items)
        # 响应形状保持为数组以兼容 dashboard.js；分页元信息走响应头
        resp.headers["X-Total-Count"] = str(total)
        resp.headers["X-Offset"] = str(offset)
        resp.headers["X-Limit"] = str(limit)
        # 浏览器侧 JS 读取自定义头需要 CORS 暴露
        resp.headers["Access-Control-Expose-Headers"] = (
            "X-Total-Count, X-Offset, X-Limit"
        )
        return resp, 200

    @app.route("/api/alerts/types")
    @_auth_required()
    def api_alert_types():  # type: ignore[unused-function]
        cache_key = _api_cache_key("alert_types")
        cached = _api_cache_get(cache_key)
        if cached is not None:
            return jsonify(cached), 200

        rows = (
            db.session.query(Alert.threat_type)
            .filter(
                Alert.tenant_id == _current_tenant_id(),
                Alert.threat_type.isnot(None),
            )
            .distinct()
            .order_by(Alert.threat_type.asc())
            .all()
        )
        types = [str(r[0] or "unknown") for r in rows]
        _api_cache_set(cache_key, types)
        return jsonify(types), 200

    @app.route("/api/alerts/<alert_id>")
    @_auth_required()
    def api_alert_detail(alert_id: str):  # type: ignore[unused-function]
        alert = tenant_get(db.session, Alert, alert_id)
        if not alert:
            return (
                jsonify(
                    _error_payload(
                        code="alert_not_found",
                        message="告警不存在",
                    )
                ),
                404,
            )
        return jsonify(_alert_to_api_dict(alert)), 200

    @app.route("/api/alerts/<alert_id>/status", methods=["POST"])
    @_auth_required()
    @_require_role("analyst")
    def api_alert_update_status(alert_id: str):  # type: ignore[unused-function]
        payload = request.get_json(silent=True) or {}
        new_status = str(payload.get("status", "")).strip()
        note = str(payload.get("note", "")).strip() or None
        if new_status not in ALERT_STATUSES:
            return (
                jsonify(
                    {
                        "error": "status 非法",
                        "allowed": list(ALERT_STATUSES),
                    }
                ),
                400,
            )
        updated = _update_alert_status_in_db(
            alert_id=alert_id,
            new_status=new_status,
            operator=_current_actor(),
            note=note,
        )
        if not updated:
            return jsonify({"error": "告警不存在"}), 404
        _record_audit_event(
            event_type="alert.status_updated",
            actor=_current_actor(),
            resource_type="alert",
            resource_id=alert_id,
            payload={"status": new_status, "note": note},
        )
        # 兼容层：保持内存态状态同步，避免尚未迁移的聚合逻辑出现视图抖动
        state.update_alert_status(alert_id, new_status)
        # 状态变化通过 WebSocket 同步给其他会话
        try:
            socketio = app.extensions.get("guardian_socketio")
            if socketio is not None:
                socketio.emit(
                    "alert_updated",
                    {"id": updated["id"], "status": updated["status"]},
                )
        except Exception:  # noqa: BLE001 - 推送失败不应阻断主流程
            logger.debug("alert_updated 广播失败", exc_info=True)
        return jsonify(updated), 200

    # ---- 仅调试用：生成演示告警 --------------------------------------
    @app.route("/api/alerts/_seed", methods=["POST"])
    @_auth_required()
    @_require_role("admin")
    def api_alerts_seed():  # type: ignore[unused-function]
        """仅在 DEBUG 或 ALLOW_DEV_SEED=true 时启用，便于 UI review。

        故意使用 `_seed` 下划线前缀以区别于业务接口；生产环境一律返回 403。
        """
        cfg = get_config()
        allow = bool(getattr(cfg, "DEBUG", False)) or (
            os.environ.get("ALLOW_DEV_SEED", "").lower() == "true"
        )
        if not allow:
            return jsonify({"error": "dev seed 在当前环境未启用"}), 403

        data = request.get_json(silent=True) or {}
        count = _safe_int(
            str(data.get("count", 12)),
            default=12,
            max_value=100,
            allow_zero=True,
        )
        created = _seed_demo_alerts(app, count=count) if count > 0 else 0
        return jsonify({"status": "ok", "created": created}), 201

    # ---- 指标：流量趋势 / 攻击类型分布 / Top10 攻击来源 --------------
    @app.route("/api/metrics/traffic")
    @_auth_required()
    def api_metrics_traffic():  # type: ignore[unused-function]
        range_key = (request.args.get("range") or "24h").strip().lower()
        cache_key = _api_cache_key("traffic", range_key)
        cached = _api_cache_get(cache_key)
        if cached is not None:
            return jsonify(cached), 200

        window_map: Dict[str, Tuple[timedelta, int, str]] = {
            "24h": (timedelta(hours=24), 60, "hour"),
            "7d": (timedelta(days=7), 60 * 24, "day"),
            "30d": (timedelta(days=30), 60 * 24, "day"),
        }
        if range_key not in window_map:
            return (
                jsonify(
                    _error_payload(
                        code="invalid_range",
                        message="range 非法，必须是 24h/7d/30d",
                    )
                ),
                400,
            )

        delta, bucket_size_min, bucket_label = window_map[range_key]
        now = datetime.now(timezone.utc).astimezone()
        start = now - delta
        total_min = max(1, int((now - start).total_seconds() // 60))
        bucket_count = max(1, total_min // bucket_size_min)

        points: List[Dict[str, Any]] = []
        for idx in range(bucket_count):
            bucket_start = start + timedelta(minutes=bucket_size_min * idx)
            points.append({"start": bucket_start, "count": 0})

        rows = (
            db.session.query(Alert.timestamp)
            .filter(
                Alert.tenant_id == _current_tenant_id(),
                Alert.timestamp >= start.astimezone(timezone.utc),
                Alert.timestamp <= now.astimezone(timezone.utc),
            )
            .all()
        )
        for (ts,) in rows:
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            ts_local = ts.astimezone()
            if ts_local < start or ts_local > now:
                continue
            bucket_idx = (
                int((ts_local - start).total_seconds() // 60) // bucket_size_min
            )
            if 0 <= bucket_idx < len(points):
                points[bucket_idx]["count"] += 1

        if range_key == "24h":
            xaxis = [p["start"].strftime("%H:%M") for p in points]
        else:
            xaxis = [p["start"].strftime("%m-%d") for p in points]
        series = [int(p["count"]) for p in points]
        payload = {
            "range": range_key,
            "bucket": bucket_label,
            "xaxis": xaxis,
            "series": series,
        }
        _api_cache_set(cache_key, payload)
        return jsonify(payload), 200

    @app.route("/api/metrics/attack_types")
    @_auth_required()
    def api_metrics_attack_types():  # type: ignore[unused-function]
        rows = (
            db.session.query(Alert.threat_type, func.count(Alert.id))
            .filter(Alert.tenant_id == _current_tenant_id())
            .group_by(Alert.threat_type)
            .all()
        )
        distribution = {str(t or "unknown"): int(c) for t, c in rows}
        return (
            jsonify([{"name": k, "value": v} for k, v in distribution.items()]),
            200,
        )

    @app.route("/api/metrics/top_attackers")
    @_auth_required()
    def api_metrics_top_attackers():  # type: ignore[unused-function]
        rows = (
            db.session.query(Alert.source_ip, func.count(Alert.id))
            .filter(Alert.tenant_id == _current_tenant_id(), Alert.source_ip != "")
            .group_by(Alert.source_ip)
            .order_by(func.count(Alert.id).desc())
            .limit(10)
            .all()
        )
        return jsonify([{"ip": ip, "count": int(c)} for ip, c in rows]), 200

    # ---- 封禁 IP 管理 ------------------------------------------------
    @app.route("/api/banned_ips", methods=["GET", "POST"])
    @_auth_required()
    def api_banned_ips():  # type: ignore[unused-function]
        if request.method == "GET":
            rows = (
                tenant_query(db.session.query(BannedIp), BannedIp)
                .order_by(BannedIp.created_at.desc())
                .all()
            )
            return (
                jsonify(
                    [
                        {"ip": r.ip, "reason": r.reason}
                        for r in rows
                    ]
                ),
                200,
            )

        data = request.get_json(silent=True) or {}
        ip = str(data.get("ip", "")).strip()
        reason = str(data.get("reason", "manual"))[:200]
        if not validate_ip(ip):
            return jsonify({"error": "无效的 IP 地址"}), 400
        if RBAC_ROLE_LEVEL.get(_current_role(), -1) < RBAC_ROLE_LEVEL["admin"]:
            return (
                jsonify(_error_payload(code="forbidden", message="需要 admin 或更高角色")),
                403,
            )
        approval_id = _record_ban_approval_request(
            ip,
            reason,
            operator=_current_actor(),
            source="api_banned_ips",
        )
        _record_audit_event(
            event_type="response.ban_ip.pending_approval",
            actor=_current_actor(),
            resource_type="response_action",
            resource_id=ip,
            payload={"reason": reason, "response_action_id": approval_id},
        )
        return (
            jsonify(
                {
                    "status": STATUS_PENDING_APPROVAL,
                    "dry_run": True,
                    "gate": _response_gate(),
                    "ip": ip,
                    "reason": reason,
                    "response_action_id": approval_id,
                }
            ),
            202,
        )

    @app.route("/api/banned_ips/<ip>", methods=["DELETE"])
    @_auth_required()
    @_require_role("admin")
    def api_banned_ip_delete(ip: str):  # type: ignore[unused-function]
        if not validate_ip(ip):
            return jsonify({"error": "无效的 IP 地址"}), 400
        try:
            ensure_quota(db.session, _current_tenant_id(), METRIC_RESPONSE_ACTIONS, requested=1)
        except QuotaExceededError as exc:
            return quota_error_response(exc)
        removed = _delete_banned_ip_persistent(ip)
        if not removed:
            return jsonify({"error": "IP 不在封禁列表"}), 404
        db.session.add(
            ResponseAction(
                tenant_id=_current_tenant_id(),
                action_type="unban_ip",
                target=ip,
                status=STATUS_MANUAL_UNBLOCKED,
                dry_run=True,
                meta={
                    "operator": _current_actor(),
                    "trigger_source": "api_banned_ips",
                    "reason": "manual_unban",
                },
            )
        )
        record_usage(
            db.session,
            _current_tenant_id(),
            METRIC_RESPONSE_ACTIONS,
            actor=_current_actor(),
            resource_type="response_action",
            resource_id=ip,
        )
        db.session.commit()
        _sync_banned_cache_from_db(state)
        _record_audit_event(
            event_type="banned_ip.deleted",
            actor=_current_actor(),
            resource_type="banned_ip",
            resource_id=ip,
        )
        return jsonify({"status": "ok", "ip": ip}), 200

    # ---- Phase C6: 真实响应受控开放 API -------------------------------
    @app.route("/api/response/actions", methods=["GET", "POST"])
    @_auth_required()
    def api_response_actions():  # type: ignore[unused-function]
        if request.method == "GET":
            limit = _safe_int(request.args.get("limit"), 50, 200)
            offset = _safe_int(request.args.get("offset"), 0, 100000, allow_zero=True)
            status = str(request.args.get("status") or "").strip()
            query = db.session.query(ResponseAction).filter(
                ResponseAction.tenant_id == _current_tenant_id()
            )
            if status:
                query = query.filter(ResponseAction.status == status)
            total = query.count()
            rows = (
                query.order_by(ResponseAction.created_at.desc(), ResponseAction.id.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            return (
                jsonify(
                    {
                        "items": [_response_action_to_api_dict(r) for r in rows],
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                        "dry_run": _response_dry_run(),
                        "gate": _response_gate(),
                    }
                ),
                200,
            )

        if RBAC_ROLE_LEVEL.get(_current_role(), -1) < RBAC_ROLE_LEVEL["admin"]:
            return jsonify(_error_payload(code="forbidden", message="需要 admin 或更高角色")), 403

        data = request.get_json(silent=True) or {}
        action_type = str(data.get("action_type") or "ban_ip").strip()
        target_type = str(data.get("target_type") or "ip").strip()
        target = str(data.get("target") or data.get("ip") or "").strip()
        reason = str(data.get("reason") or "approval_required").strip()[:2000]
        ttl_seconds = int(data.get("ttl_seconds") or 3600)
        provider_config_id = data.get("provider_config_id")
        if action_type not in _REAL_RESPONSE_ACTION_TYPES:
            return jsonify(_response_runtime_payload(status="rejected", reason="invalid_action_type")), 400
        if target_type not in _REAL_RESPONSE_TARGET_TYPES:
            return jsonify(_response_runtime_payload(status="rejected", reason="invalid_target_type")), 400
        target_error = _validate_response_target(target_type, target)
        if target_error:
            return jsonify(_response_runtime_payload(status="rejected", reason=target_error)), 400
        if ttl_seconds <= 0:
            return jsonify(_response_runtime_payload(status="rejected", reason="ttl_seconds_required")), 400

        provider = None
        if provider_config_id not in (None, ""):
            provider = tenant_get(db.session, ResponseProviderConfig, int(provider_config_id))
            if provider is None:
                return jsonify(_response_runtime_payload(status="rejected", reason="provider_not_found")), 404

        try:
            ensure_quota(db.session, _current_tenant_id(), METRIC_RESPONSE_ACTIONS, requested=1)
        except QuotaExceededError as exc:
            return quota_error_response(exc)

        now = datetime.now(timezone.utc)
        scheduled_unblock_at = now + timedelta(seconds=ttl_seconds)
        action = ResponseAction(
            tenant_id=_current_tenant_id(),
            alert_id=(str(data.get("alert_id")).strip() if data.get("alert_id") else None),
            action_type=action_type,
            target=target,
            status=STATUS_PENDING_APPROVAL,
            dry_run=True,
            scheduled_unblock_at=scheduled_unblock_at,
            meta={
                "reason": reason,
                "operator": _current_actor(),
                "trigger_source": "api_response_actions",
                "approved": False,
                "gate": _response_gate(),
                "ttl_seconds": ttl_seconds,
                "provider": provider.provider_type if provider else data.get("provider"),
                "provider_config_id": provider.id if provider else None,
                "rollback_plan": data.get("rollback_plan") or {},
                "evidence": data.get("evidence") or {},
            },
        )
        db.session.add(action)
        db.session.flush()
        approval = ResponseApproval(
            tenant_id=_current_tenant_id(),
            alert_id=action.alert_id,
            response_action_id=action.id,
            provider_config_id=provider.id if provider else None,
            gate_id=_response_gate() or None,
            action_type=action_type,
            target_type=target_type,
            target=target,
            provider=provider.provider_type if provider else str(data.get("provider") or "iptables"),
            ttl_seconds=ttl_seconds,
            status="pending",
            reason=reason,
            requested_by=_current_actor(),
            expires_at=scheduled_unblock_at,
            evidence=data.get("evidence") or {},
            rollback_plan=data.get("rollback_plan") or {},
        )
        db.session.add(approval)
        db.session.flush()
        meta = dict(action.meta or {})
        meta["approval_id"] = approval.id
        action.meta = meta
        _append_response_action_event(
            action,
            status=STATUS_PENDING_APPROVAL,
            reason=reason,
            actor=_current_actor(),
            extra={"approval_id": approval.id},
        )
        record_usage(
            db.session,
            _current_tenant_id(),
            METRIC_RESPONSE_ACTIONS,
            actor=_current_actor(),
            resource_type="response_action",
            resource_id=str(action.id),
        )
        db.session.commit()
        return (
            jsonify(
                _response_runtime_payload(
                    status=STATUS_PENDING_APPROVAL,
                    reason=reason,
                    response_action_id=action.id,
                    approval_id=approval.id,
                    extra={
                        "action": _response_action_to_api_dict(action),
                        "approval": _response_approval_to_api_dict(approval),
                    },
                )
            ),
            202,
        )

    @app.route("/api/response/actions/<int:action_id>", methods=["GET"])
    @_auth_required()
    def api_response_action_detail(action_id: int):  # type: ignore[unused-function]
        action = tenant_get(db.session, ResponseAction, action_id)
        if action is None:
            return jsonify(_error_payload(code="not_found", message="response action not found")), 404
        approval = (
            db.session.query(ResponseApproval)
            .filter(
                ResponseApproval.tenant_id == _current_tenant_id(),
                ResponseApproval.response_action_id == action.id,
            )
            .order_by(ResponseApproval.id.desc())
            .first()
        )
        return (
            jsonify(
                {
                    "action": _response_action_to_api_dict(action),
                    "approval": _response_approval_to_api_dict(approval) if approval else None,
                    "dry_run": _response_dry_run(),
                    "gate": _response_gate(),
                }
            ),
            200,
        )

    def _load_response_action_pair(action_id: int) -> Tuple[Optional[ResponseAction], Optional[ResponseApproval], Optional[Any]]:
        action = tenant_get(db.session, ResponseAction, action_id)
        if action is None:
            return None, None, (jsonify(_error_payload(code="not_found", message="response action not found")), 404)
        approval = (
            db.session.query(ResponseApproval)
            .filter(
                ResponseApproval.tenant_id == _current_tenant_id(),
                ResponseApproval.response_action_id == action.id,
            )
            .order_by(ResponseApproval.id.desc())
            .first()
        )
        if approval is None:
            return action, None, (jsonify(_response_runtime_payload(status="rejected", reason="approval_required", response_action_id=action.id)), 409)
        return action, approval, None

    @app.route("/api/response/actions/<int:action_id>/approve", methods=["POST"])
    @_auth_required()
    @_require_role("admin")
    def api_response_action_approve(action_id: int):  # type: ignore[unused-function]
        action, approval, error = _load_response_action_pair(action_id)
        if error:
            return error
        assert action is not None and approval is not None
        if approval.status != "pending":
            return jsonify(_response_runtime_payload(status="rejected", reason="approval_not_pending", response_action_id=action.id, approval_id=approval.id)), 409
        data = request.get_json(silent=True) or {}
        reason = _required_body_text(data, "reason")
        if not reason:
            return jsonify(_response_runtime_payload(status="rejected", reason="approval_reason_required", response_action_id=action.id, approval_id=approval.id)), 400
        approval.status = "approved"
        approval.approved_by = _current_actor()
        approval.approved_at = datetime.now(timezone.utc)
        approval.gate_id = _response_gate() or approval.gate_id
        action.dry_run = _response_dry_run()
        _append_response_action_event(
            action,
            status=STATUS_APPROVED,
            reason=reason,
            actor=_current_actor(),
            extra={
                "approval_id": approval.id,
                "gate": approval.gate_id,
                "approval_only": True,
            },
        )
        db.session.commit()
        return jsonify(_response_runtime_payload(status=STATUS_APPROVED, reason=reason, response_action_id=action.id, approval_id=approval.id)), 200

    @app.route("/api/response/actions/<int:action_id>/reject", methods=["POST"])
    @_auth_required()
    @_require_role("admin")
    def api_response_action_reject(action_id: int):  # type: ignore[unused-function]
        action, approval, error = _load_response_action_pair(action_id)
        if error:
            return error
        assert action is not None and approval is not None
        data = request.get_json(silent=True) or {}
        reason = str(data.get("reason") or "rejected_by_admin").strip()[:2000]
        approval.status = "rejected"
        approval.rejected_by = _current_actor()
        approval.rejected_at = datetime.now(timezone.utc)
        approval.rejection_reason = reason
        _append_response_action_event(
            action,
            status="rejected",
            reason=reason,
            actor=_current_actor(),
            extra={"approval_id": approval.id},
        )
        db.session.commit()
        return jsonify(_response_runtime_payload(status="rejected", reason=reason, response_action_id=action.id, approval_id=approval.id)), 200

    @app.route("/api/response/actions/<int:action_id>/execute", methods=["POST"])
    @_auth_required()
    @_require_role("admin")
    def api_response_action_execute(action_id: int):  # type: ignore[unused-function]
        action, approval, error = _load_response_action_pair(action_id)
        if error:
            return error
        assert action is not None and approval is not None
        dry_run = _response_dry_run()
        gate = _response_gate()
        data = request.get_json(silent=True) or {}
        execution_reason = _required_body_text(data, "reason")
        if not execution_reason:
            return jsonify(_response_runtime_payload(status="rejected", reason="execution_reason_required", response_action_id=action.id, approval_id=approval.id)), 400

        if approval.status != "approved":
            reason = "approval_not_approved"
            return jsonify(_response_runtime_payload(status="rejected", reason=reason, response_action_id=action.id, approval_id=approval.id)), 409
        if action.action_type not in {"ban_ip", "cloud_security_group_block"}:
            reason = "execute_action_not_supported"
            return jsonify(_response_runtime_payload(status="rejected", reason=reason, response_action_id=action.id, approval_id=approval.id)), 409
        if not action.scheduled_unblock_at:
            reason = "scheduled_unblock_at_required"
            _append_response_action_event(action, status="rejected", reason=reason, actor=_current_actor(), extra={"approval_id": approval.id}, commit=True)
            return jsonify(_response_runtime_payload(status="rejected", reason=reason, response_action_id=action.id, approval_id=approval.id)), 409

        whitelist = _response_whitelist_match(approval.target_type, approval.target)
        if whitelist is not None:
            reason = "whitelist_matched"
            _append_response_action_event(
                action,
                status="skipped",
                reason=reason,
                actor=_current_actor(),
                extra={"approval_id": approval.id, "whitelist_id": whitelist.id},
                commit=True,
            )
            return jsonify(_response_runtime_payload(status="skipped", reason=reason, response_action_id=action.id, approval_id=approval.id, extra={"whitelist_id": whitelist.id})), 409

        if dry_run:
            action.dry_run = True
            approval.status = "executed"
            approval.executed_by = _current_actor()
            approval.executed_at = datetime.now(timezone.utc)
            _append_response_action_event(
                action,
                status="dry_run_simulated",
                reason=execution_reason,
                actor=_current_actor(),
                extra={
                    "approval_id": approval.id,
                    "provider_called": False,
                    "dry_run_only": True,
                    "execution_reason": execution_reason,
                },
            )
            _create_response_schedule(action, approval)
            db.session.commit()
            return jsonify(_response_runtime_payload(status="dry_run_simulated", reason=execution_reason, response_action_id=action.id, approval_id=approval.id, extra={"provider_called": False})), 200

        if gate != _REAL_RESPONSE_GATE_VALUE:
            reason = "real_enforcement_gate_required"
            failures = real_enforcement_env_failures(gate_value=gate, include_gate=True)
            _append_response_action_event(
                action,
                status="rejected",
                reason=reason,
                actor=_current_actor(),
                extra={"approval_id": approval.id, "missing_prerequisites": failures},
                commit=True,
            )
            return jsonify(_response_runtime_payload(status="rejected", reason=reason, response_action_id=action.id, approval_id=approval.id, extra={"missing_prerequisites": failures})), 403
        if approval.gate_id != _REAL_RESPONSE_GATE_VALUE:
            reason = "approval_gate_mismatch"
            _append_response_action_event(action, status="rejected", reason=reason, actor=_current_actor(), extra={"approval_id": approval.id, "approval_gate": approval.gate_id}, commit=True)
            return jsonify(_response_runtime_payload(status="rejected", reason=reason, response_action_id=action.id, approval_id=approval.id)), 409
        if approval.target_type != "ip" or not validate_ip(approval.target):
            reason = "valid_ip_target_required"
            _append_response_action_event(action, status="rejected", reason=reason, actor=_current_actor(), extra={"approval_id": approval.id}, commit=True)
            return jsonify(_response_runtime_payload(status="rejected", reason=reason, response_action_id=action.id, approval_id=approval.id)), 400

        from src.response.firewall import approved_response_execution, firewall_manager_from_env
        from src.response.ip_policy import check_real_ban_eligibility

        eligibility = check_real_ban_eligibility(approval.target)
        if not eligibility.allowed:
            reason = eligibility.rejection_reason
            _append_response_action_event(action, status="skipped", reason=reason, actor=_current_actor(), extra={"approval_id": approval.id}, commit=True)
            return jsonify(_response_runtime_payload(status="skipped", reason=reason, response_action_id=action.id, approval_id=approval.id)), 409

        provider = tenant_get(db.session, ResponseProviderConfig, approval.provider_config_id) if approval.provider_config_id else None
        admission_failures = _real_response_admission_failures(provider)
        if admission_failures:
            reason = first_failure_code(
                admission_failures,
                "real_enforcement_admission_required",
            )
            _append_response_action_event(
                action,
                status="rejected",
                reason=reason,
                actor=_current_actor(),
                extra={"approval_id": approval.id, "missing_prerequisites": admission_failures},
                commit=True,
            )
            return jsonify(_response_runtime_payload(status="rejected", reason=reason, response_action_id=action.id, approval_id=approval.id, extra={"missing_prerequisites": admission_failures})), 409

        action.dry_run = False
        approval.status = "executing"
        _append_response_action_event(action, status="executing", reason=execution_reason, actor=_current_actor(), extra={"approval_id": approval.id, "provider_config_id": provider.id})
        db.session.flush()
        with approved_response_execution():
            result = firewall_manager_from_env().ban_input_drop(approval.target, dry_run=False)
        final_status = STATUS_EXECUTED if result.ok else "failed"
        final_reason = execution_reason if result.ok else result.message
        approval.status = "executed" if result.ok else "failed"
        approval.executed_by = _current_actor()
        approval.executed_at = datetime.now(timezone.utc)
        _append_response_action_event(
            action,
            status=final_status,
            reason=final_reason,
            actor=_current_actor(),
            extra={
                "approval_id": approval.id,
                "provider_config_id": provider.id,
                "execution_reason": execution_reason,
                "executed_by": _current_actor(),
                "provider_result": {
                    "ok": result.ok,
                    "message": result.message,
                    "command": result.command,
                },
            },
        )
        if result.ok:
            _persist_banned_ip(approval.target, action.meta.get("reason", approval.reason), operator=_current_actor())
            _create_response_schedule(action, approval)
        db.session.commit()
        return jsonify(_response_runtime_payload(status=final_status, reason=final_reason, response_action_id=action.id, approval_id=approval.id)), (200 if result.ok else 502)

    @app.route("/api/response/actions/<int:action_id>/rollback", methods=["POST"])
    @_auth_required()
    @_require_role("admin")
    def api_response_action_rollback(action_id: int):  # type: ignore[unused-function]
        action, approval, error = _load_response_action_pair(action_id)
        if error:
            return error
        assert action is not None and approval is not None
        if action.status not in {STATUS_EXECUTED, "dry_run_simulated", STATUS_REVIEWED}:
            return jsonify(_response_runtime_payload(status="rejected", reason="rollback_requires_executed", response_action_id=action.id, approval_id=approval.id)), 409
        data = request.get_json(silent=True) or {}
        reason = _required_body_text(data, "reason")
        if not reason:
            return jsonify(_response_runtime_payload(status="rejected", reason="rollback_reason_required", response_action_id=action.id, approval_id=approval.id)), 400
        dry_run = _response_dry_run() or action.status == "dry_run_simulated" or bool(action.dry_run)
        provider_called = False
        provider_result: Dict[str, Any] = {"ok": True, "message": "dry_run_no_provider_call"}
        if not dry_run:
            if _response_gate() != _REAL_RESPONSE_GATE_VALUE:
                return jsonify(_response_runtime_payload(status="rejected", reason="real_enforcement_gate_required", response_action_id=action.id, approval_id=approval.id)), 403
            provider = tenant_get(db.session, ResponseProviderConfig, approval.provider_config_id) if approval.provider_config_id else None
            provider_error = _real_response_provider_available(provider)
            if provider_error:
                return jsonify(_response_runtime_payload(status="rejected", reason=provider_error, response_action_id=action.id, approval_id=approval.id)), 409
            from src.response.firewall import approved_response_execution, firewall_manager_from_env

            with approved_response_execution():
                result = firewall_manager_from_env().unban_input_drop(str(action.target or ""), dry_run=False)
            provider_called = True
            provider_result = {"ok": result.ok, "message": result.message, "command": result.command}
            if not result.ok:
                _append_response_action_event(action, status="failed", reason=result.message, actor=_current_actor(), extra={"rollback": True, "provider_result": provider_result}, commit=True)
                return jsonify(_response_runtime_payload(status="failed", reason=result.message, response_action_id=action.id, approval_id=approval.id, extra={"provider_called": provider_called})), 502
        _delete_banned_ip_persistent(str(action.target or ""))
        _append_response_action_event(
            action,
            status=STATUS_MANUAL_UNBLOCKED,
            reason=f"rollback:{reason}",
            actor=_current_actor(),
            extra={"approval_id": approval.id, "provider_called": provider_called, "provider_result": provider_result},
        )
        db.session.commit()
        return jsonify(_response_runtime_payload(status=STATUS_MANUAL_UNBLOCKED, reason=f"rollback:{reason}", response_action_id=action.id, approval_id=approval.id, extra={"provider_called": provider_called})), 200

    @app.route("/api/response/actions/<int:action_id>/review", methods=["POST"])
    @_auth_required()
    @_require_role("admin")
    def api_response_action_review(action_id: int):  # type: ignore[unused-function]
        action, approval, error = _load_response_action_pair(action_id)
        if error:
            return error
        assert action is not None and approval is not None
        data = request.get_json(silent=True) or {}
        reason = str(data.get("reason") or "post_execution_review").strip()[:2000]
        if action.status not in {STATUS_EXECUTED, "dry_run_simulated", STATUS_MANUAL_UNBLOCKED, STATUS_SCHEDULED_UNBLOCKED}:
            return jsonify(_response_runtime_payload(status="rejected", reason="review_requires_executed", response_action_id=action.id, approval_id=approval.id)), 409
        approval.status = "reviewed"
        approval.reviewed_by = _current_actor()
        approval.reviewed_at = datetime.now(timezone.utc)
        _append_response_action_event(
            action,
            status=STATUS_REVIEWED,
            reason=reason,
            actor=_current_actor(),
            extra={"approval_id": approval.id, "review": data.get("review") or {}},
        )
        db.session.commit()
        return jsonify(_response_runtime_payload(status=STATUS_REVIEWED, reason=reason, response_action_id=action.id, approval_id=approval.id)), 200

    @app.route("/api/response/whitelists/check", methods=["POST"])
    @_auth_required()
    def api_response_whitelists_check():  # type: ignore[unused-function]
        data = request.get_json(silent=True) or {}
        target = str(data.get("target") or data.get("ip") or "").strip()
        if not validate_ip(target):
            return jsonify(_response_runtime_payload(status="rejected", reason="invalid_ip")), 400
        return jsonify(_response_whitelist_check_payload(target)), 200

    @app.route("/api/response/whitelist", methods=["GET", "POST"])
    @app.route("/api/response/whitelists", methods=["GET", "POST"])
    @app.route("/api/response/whitelist/<int:entry_id>", methods=["PUT", "PATCH", "DELETE"])
    @app.route("/api/response/whitelists/<int:entry_id>", methods=["GET", "PUT", "PATCH", "DELETE"])
    @_auth_required()
    def api_response_whitelist(entry_id: Optional[int] = None):  # type: ignore[unused-function]
        if request.method == "GET" and entry_id is None:
            rows = (
                db.session.query(ResponseWhitelistEntry)
                .filter(ResponseWhitelistEntry.tenant_id == _current_tenant_id())
                .order_by(ResponseWhitelistEntry.created_at.desc(), ResponseWhitelistEntry.id.desc())
                .all()
            )
            return jsonify({"items": [_response_whitelist_to_api_dict(r) for r in rows], "dry_run": _response_dry_run(), "gate": _response_gate()}), 200
        if request.method == "GET" and entry_id is not None:
            row = tenant_get(db.session, ResponseWhitelistEntry, entry_id)
            if row is None:
                return jsonify(_error_payload(code="not_found", message="whitelist entry not found")), 404
            return jsonify({"entry": _response_whitelist_to_api_dict(row), "dry_run": _response_dry_run(), "gate": _response_gate()}), 200
        if RBAC_ROLE_LEVEL.get(_current_role(), -1) < RBAC_ROLE_LEVEL["admin"]:
            return jsonify(_error_payload(code="forbidden", message="需要 admin 或更高角色")), 403
        data = request.get_json(silent=True) or {}
        if request.method == "POST":
            value_type = str(data.get("value_type") or "ip").strip()
            value = str(data.get("value") or "").strip()
            scope = str(data.get("scope") or "business").strip()
            status = str(data.get("status") or "active").strip()
            if scope not in WHITELIST_SCOPES:
                return jsonify(_response_runtime_payload(status="rejected", reason="invalid_scope")), 400
            if status not in {"pending", "active", "disabled", "expired"}:
                return jsonify(_response_runtime_payload(status="rejected", reason="invalid_status")), 400
            if value_type not in {"ip", "cidr"}:
                return jsonify(_response_runtime_payload(status="rejected", reason="invalid_value_type")), 400
            normalized_value, err = _normalize_response_whitelist_value(value_type, value)
            if err:
                return jsonify(_response_runtime_payload(status="rejected", reason=err)), 400
            try:
                expires_at = _parse_whitelist_expires_at(data.get("expires_at"))
            except ValueError as exc:
                return jsonify(_response_runtime_payload(status="rejected", reason=str(exc))), 400
            row = ResponseWhitelistEntry(
                tenant_id=_current_tenant_id(),
                scope=scope,
                value_type=value_type,
                value=normalized_value or value,
                environment=str(data.get("environment") or "production").strip()[:64],
                status=status,
                reason=str(data.get("reason") or "protected_asset").strip()[:2000],
                owner=(str(data.get("owner")).strip()[:128] if data.get("owner") else None),
                created_by=str(data.get("created_by") or _current_actor()).strip()[:128],
                approved_by=_current_actor() if status == "active" else None,
                approved_at=datetime.now(timezone.utc) if status == "active" else None,
                expires_at=expires_at,
                evidence=data.get("evidence") or {},
            )
            db.session.add(row)
            db.session.flush()
            db.session.add(AuditEvent(tenant_id=_current_tenant_id(), event_type="response.whitelist.created", actor=_current_actor(), resource_type="response_whitelist", resource_id=str(row.id), payload=_response_whitelist_to_api_dict(row), ip_address=row.value if validate_ip(row.value) else None))
            db.session.commit()
            return jsonify({"status": row.status, "dry_run": _response_dry_run(), "gate": _response_gate(), "reason": row.reason, "response_action_id": None, "entry": _response_whitelist_to_api_dict(row)}), 201
        row = tenant_get(db.session, ResponseWhitelistEntry, entry_id)
        if row is None:
            return jsonify(_error_payload(code="not_found", message="whitelist entry not found")), 404
        if request.method == "DELETE":
            row.status = "disabled"
            db.session.add(AuditEvent(tenant_id=_current_tenant_id(), event_type="response.whitelist.disabled", actor=_current_actor(), resource_type="response_whitelist", resource_id=str(row.id), payload={"value": row.value}, ip_address=row.value if validate_ip(row.value) else None))
            db.session.commit()
            return jsonify({"status": "disabled", "dry_run": _response_dry_run(), "gate": _response_gate(), "reason": "whitelist_disabled", "response_action_id": None}), 200
        old_payload = _response_whitelist_to_api_dict(row)
        if "scope" in data and str(data.get("scope") or "").strip() not in WHITELIST_SCOPES:
            return jsonify(_response_runtime_payload(status="rejected", reason="invalid_scope")), 400
        if "status" in data and str(data.get("status") or "").strip() not in {"pending", "active", "disabled", "expired"}:
            return jsonify(_response_runtime_payload(status="rejected", reason="invalid_status")), 400
        if "value_type" in data or "value" in data:
            value_type = str(data.get("value_type") or row.value_type).strip()
            if value_type not in {"ip", "cidr"}:
                return jsonify(_response_runtime_payload(status="rejected", reason="invalid_value_type")), 400
            normalized_value, err = _normalize_response_whitelist_value(
                value_type, str(data.get("value") if "value" in data else row.value)
            )
            if err:
                return jsonify(_response_runtime_payload(status="rejected", reason=err)), 400
            row.value_type = value_type
            row.value = normalized_value or row.value
        for key in ("scope", "status", "reason", "owner", "environment"):
            if key in data:
                setattr(row, key, str(data.get(key) or "").strip())
        if "expires_at" in data:
            try:
                row.expires_at = _parse_whitelist_expires_at(data.get("expires_at"))
            except ValueError as exc:
                return jsonify(_response_runtime_payload(status="rejected", reason=str(exc))), 400
        if "evidence" in data:
            row.evidence = data.get("evidence") or {}
        if row.status == "active" and not row.approved_by:
            row.approved_by = _current_actor()
            row.approved_at = datetime.now(timezone.utc)
        db.session.add(AuditEvent(tenant_id=_current_tenant_id(), event_type="response.whitelist.updated", actor=_current_actor(), resource_type="response_whitelist", resource_id=str(row.id), payload={"before": old_payload, "after": _response_whitelist_to_api_dict(row)}, ip_address=row.value if validate_ip(row.value) else None))
        db.session.commit()
        return jsonify({"status": row.status, "dry_run": _response_dry_run(), "gate": _response_gate(), "reason": "whitelist_updated", "response_action_id": None, "entry": _response_whitelist_to_api_dict(row)}), 200

    @app.route("/api/response/providers", methods=["GET"])
    @_auth_required()
    def api_response_providers():  # type: ignore[unused-function]
        rows = (
            db.session.query(ResponseProviderConfig)
            .filter(ResponseProviderConfig.tenant_id == _current_tenant_id())
            .order_by(ResponseProviderConfig.created_at.desc(), ResponseProviderConfig.id.desc())
            .all()
        )
        return jsonify({"items": [_response_provider_to_api_dict(r) for r in rows], "dry_run": _response_dry_run(), "gate": _response_gate()}), 200

    @app.route("/api/response/providers/<int:provider_id>/test", methods=["POST"])
    @_auth_required()
    @_require_role("admin")
    def api_response_provider_test(provider_id: int):  # type: ignore[unused-function]
        provider = tenant_get(db.session, ResponseProviderConfig, provider_id)
        if provider is None:
            return jsonify(_response_runtime_payload(status="rejected", reason="provider_not_found")), 404
        reason = _real_response_provider_available(provider, require_validated=False)
        result = {"ok": reason is None, "reason": reason or "provider_available"}
        provider.last_validated_at = datetime.now(timezone.utc)
        provider.last_validation_result = result
        db.session.add(AuditEvent(tenant_id=_current_tenant_id(), event_type="response.provider.tested", actor=_current_actor(), resource_type="response_provider", resource_id=str(provider.id), payload=result))
        db.session.commit()
        return jsonify(_response_runtime_payload(status="ok" if result["ok"] else "rejected", reason=result["reason"], extra={"provider": _response_provider_to_api_dict(provider)})), (200 if result["ok"] else 409)

    @app.route("/api/response/schedules", methods=["GET"])
    @_auth_required()
    def api_response_schedules():  # type: ignore[unused-function]
        rows = (
            db.session.query(ResponseScheduleTask)
            .filter(ResponseScheduleTask.tenant_id == _current_tenant_id())
            .order_by(ResponseScheduleTask.run_at.asc(), ResponseScheduleTask.id.asc())
            .limit(200)
            .all()
        )
        return jsonify({"items": [_response_schedule_to_api_dict(r) for r in rows], "dry_run": _response_dry_run(), "gate": _response_gate()}), 200

    @app.route("/api/response/drills", methods=["POST"])
    @_auth_required()
    @_require_role("admin")
    def api_response_drills():  # type: ignore[unused-function]
        data = request.get_json(silent=True) or {}
        target_type = str(data.get("target_type") or "ip").strip()
        target = str(data.get("target") or "").strip()
        err = _validate_response_target(target_type, target)
        if err:
            return jsonify(_response_runtime_payload(status="rejected", reason=err)), 400
        drill_type = str(data.get("drill_type") or "dry_run_ban_unblock").strip()
        status = str(data.get("status") or "planned").strip()
        ended_at = _parse_iso(str(data.get("ended_at"))) if data.get("ended_at") else None
        if (
            status == "passed"
            and drill_type in {"real_ban_unblock", "provider_rollback", "misblock_recovery"}
            and ended_at is None
        ):
            return jsonify(_response_runtime_payload(status="rejected", reason="ended_at_required_for_passed_recovery_drill")), 400
        row = ResponseDrill(
            tenant_id=_current_tenant_id(),
            provider_config_id=int(data["provider_config_id"]) if data.get("provider_config_id") else None,
            response_action_id=int(data["response_action_id"]) if data.get("response_action_id") else None,
            approval_id=int(data["approval_id"]) if data.get("approval_id") else None,
            environment=str(data.get("environment") or "preprod").strip()[:64],
            drill_type=drill_type,
            target_type=target_type,
            target=target,
            status=status,
            started_at=_parse_iso(str(data.get("started_at"))) if data.get("started_at") else None,
            ended_at=ended_at,
            rto_seconds=int(data["rto_seconds"]) if data.get("rto_seconds") is not None else None,
            result=str(data.get("result")) if data.get("result") is not None else None,
            participants=data.get("participants") or [],
            evidence=data.get("evidence") or {},
            created_by=_current_actor(),
            approved_by=str(data.get("approved_by")).strip()[:128] if data.get("approved_by") else None,
        )
        db.session.add(row)
        db.session.flush()
        db.session.add(AuditEvent(tenant_id=_current_tenant_id(), event_type="response.drill.created", actor=_current_actor(), resource_type="response_drill", resource_id=str(row.id), payload=_response_drill_to_api_dict(row), ip_address=target if validate_ip(target) else None))
        db.session.commit()
        return jsonify({"status": row.status, "dry_run": _response_dry_run(), "gate": _response_gate(), "reason": "drill_created", "response_action_id": row.response_action_id, "drill": _response_drill_to_api_dict(row)}), 201

    # ---- 命令面板 ----------------------------------------------------
    @app.route("/api/command", methods=["POST"])
    @_auth_required()
    @_require_role("admin")
    @limiter.limit("30 per minute")
    def api_command():  # type: ignore[unused-function]
        data = request.get_json(silent=True) or {}
        raw = str(data.get("command", "")).strip()
        try:
            result = _execute_safe_command(raw, state)
        except QuotaExceededError as exc:
            return quota_error_response(exc)
        _record_audit_event(
            event_type="command.executed",
            actor=_current_actor(),
            resource_type="command",
            resource_id=raw.split(" ", 1)[0] if raw else None,
            payload={"command": raw, "ok": bool(result.get("ok", True))},
        )
        return jsonify(result), 200

    # ---- 规则 CRUD + 测试 + seed -----------------------------------
    @app.route("/api/rules", methods=["GET", "POST"])
    @_auth_required()
    def api_rules():  # type: ignore[unused-function]
        if request.method == "GET":
            type_ = request.args.get("type") or None
            q = request.args.get("q") or None
            enabled_raw = request.args.get("enabled")
            enabled: Optional[bool] = None
            if enabled_raw is not None and enabled_raw != "":
                if enabled_raw.lower() in ("true", "1", "yes"):
                    enabled = True
                elif enabled_raw.lower() in ("false", "0", "no"):
                    enabled = False
                else:
                    return jsonify({"error": "enabled 取值非法（true/false）"}), 400
            if type_ and type_ not in RULE_TYPES:
                return jsonify({"error": f"type 必须是 {list(RULE_TYPES)}"}), 400
            cache_key = _api_cache_key("rules", type_ or "", enabled if enabled is not None else "", q or "")
            cached = _api_cache_get(cache_key)
            if cached is not None:
                resp = jsonify(cached)
                resp.headers["X-Total-Count"] = str(len(cached))
                resp.headers["Access-Control-Expose-Headers"] = "X-Total-Count"
                return resp, 200
            items = _list_rules_from_db(type_=type_, enabled=enabled, q=q)
            _api_cache_set(cache_key, items)
            resp = jsonify(items)
            resp.headers["X-Total-Count"] = str(len(items))
            resp.headers["Access-Control-Expose-Headers"] = "X-Total-Count"
            return resp, 200

        payload = request.get_json(silent=True) or {}
        if RBAC_ROLE_LEVEL.get(_current_role(), -1) < RBAC_ROLE_LEVEL["admin"]:
            return (
                jsonify(_error_payload(code="forbidden", message="需要 admin 或更高角色")),
                403,
            )
        normalized, err = _validate_rule_payload(payload)
        if err or not normalized:
            return jsonify({"error": err or "规则校验失败"}), 400
        try:
            ensure_quota(db.session, _current_tenant_id(), METRIC_RULES, requested=1)
        except QuotaExceededError as exc:
            return quota_error_response(exc)
        row = _insert_rule_from_normalized(normalized)
        _api_cache_invalidate("rules")
        record_usage(
            db.session,
            _current_tenant_id(),
            METRIC_RULES,
            actor=_current_actor(),
            resource_type="rule",
            resource_id=row.id,
        )
        db.session.commit()
        _record_audit_event(
            event_type="rule.created",
            actor=_current_actor(),
            resource_type="rule",
            resource_id=row.id,
            payload={"name": row.name, "type": row.rule_type},
        )
        return jsonify(_rule_row_to_api_dict(row)), 201

    @app.route("/api/rules/<rule_id>", methods=["GET", "PUT", "DELETE"])
    @_auth_required()
    def api_rule_detail(rule_id: str):  # type: ignore[unused-function]
        if request.method == "GET":
            row = tenant_get(db.session, Rule, rule_id)
            if not row:
                return jsonify({"error": "规则不存在"}), 404
            return jsonify(_rule_row_to_api_dict(row)), 200

        if request.method == "PUT":
            if RBAC_ROLE_LEVEL.get(_current_role(), -1) < RBAC_ROLE_LEVEL["admin"]:
                return (
                    jsonify(_error_payload(code="forbidden", message="需要 admin 或更高角色")),
                    403,
                )
            row = tenant_get(db.session, Rule, rule_id)
            if not row:
                return jsonify({"error": "规则不存在"}), 404
            payload = request.get_json(silent=True) or {}
            normalized, err = _validate_rule_payload(payload, partial=True)
            if err or normalized is None:
                return jsonify({"error": err or "规则校验失败"}), 400
            if not normalized:
                return jsonify({"error": "请求体为空"}), 400
            merged = dict(_rule_row_to_api_dict(row))
            for k, v in normalized.items():
                merged[k] = v
            full_check, err2 = _validate_rule_payload(merged)
            if err2 or not full_check:
                return jsonify({"error": err2 or "规则校验失败"}), 400
            _apply_partial_to_rule_row(row, normalized)
            db.session.commit()
            db.session.refresh(row)
            _api_cache_invalidate("rules")
            _record_audit_event(
                event_type="rule.updated",
                actor=_current_actor(),
                resource_type="rule",
                resource_id=rule_id,
                payload={"updated_keys": list(normalized.keys())},
            )
            return jsonify(_rule_row_to_api_dict(row)), 200

        # DELETE
        if RBAC_ROLE_LEVEL.get(_current_role(), -1) < RBAC_ROLE_LEVEL["admin"]:
            return (
                jsonify(_error_payload(code="forbidden", message="需要 admin 或更高角色")),
                403,
            )
        row = tenant_get(db.session, Rule, rule_id)
        if not row:
            return jsonify({"error": "规则不存在"}), 404
        db.session.delete(row)
        record_usage(
            db.session,
            _current_tenant_id(),
            METRIC_RULES,
            delta=-1,
            actor=_current_actor(),
            resource_type="rule",
            resource_id=rule_id,
        )
        db.session.commit()
        _api_cache_invalidate("rules")
        _record_audit_event(
            event_type="rule.deleted",
            actor=_current_actor(),
            resource_type="rule",
            resource_id=rule_id,
        )
        return jsonify({"status": "ok", "id": rule_id}), 200

    @app.route("/api/rules/<rule_id>/toggle", methods=["PATCH"])
    @_auth_required()
    @_require_role("admin")
    def api_rule_toggle(rule_id: str):  # type: ignore[unused-function]
        row = tenant_get(db.session, Rule, rule_id)
        if not row:
            return jsonify({"error": "规则不存在"}), 404
        payload = request.get_json(silent=True) or {}
        if "enabled" in payload:
            row.enabled = bool(payload["enabled"])
        else:
            row.enabled = not bool(row.enabled)
        row.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        db.session.refresh(row)
        _api_cache_invalidate("rules")
        _record_audit_event(
            event_type="rule.toggled",
            actor=_current_actor(),
            resource_type="rule",
            resource_id=rule_id,
            payload={"enabled": bool(row.enabled)},
        )
        return jsonify(_rule_row_to_api_dict(row)), 200

    @app.route("/api/rules/test", methods=["POST"])
    @_auth_required()
    @limiter.limit("60 per minute")
    def api_rule_test():  # type: ignore[unused-function]
        """根据请求体校验规则命中。两种用法：

        1) 仅测试已保存规则：`{"rule_id": "xxx", "sample": {...}}`
        2) 测试临时规则（编辑抽屉尚未保存）：`{"rule": {...}, "sample": {...}}`
        """
        payload = request.get_json(silent=True) or {}
        sample = payload.get("sample") or {}
        if not isinstance(sample, dict):
            return jsonify({"error": "sample 必须是对象"}), 400

        rule_id = payload.get("rule_id")
        rule: Optional[Dict[str, Any]] = None
        if rule_id:
            db_row = tenant_get(db.session, Rule, str(rule_id))
            if not db_row:
                return jsonify({"error": "规则不存在"}), 404
            rule = _rule_row_to_api_dict(db_row)
        else:
            raw = payload.get("rule")
            if not isinstance(raw, dict):
                return jsonify({"error": "必须提供 rule_id 或 rule 对象"}), 400
            normalized, err = _validate_rule_payload(raw)
            if err or not normalized:
                return jsonify({"error": err or "规则校验失败"}), 400
            rule = normalized

        result = _evaluate_rule(rule, sample)
        # 命中 且 规则来自已保存：累加 hits 以便表格能显示真实数据
        if result.get("matched") and rule_id:
            _incr_rule_hits_db(str(rule_id))
        # 附加一份结果快照，便于前端直接回显
        result["rule"] = {
            "id": rule.get("id"),
            "name": rule.get("name"),
            "type": rule.get("type"),
            "pattern": rule.get("pattern"),
            "action": rule.get("action"),
            "level": rule.get("level"),
        }
        return jsonify(result), 200

    @app.route("/api/rules/_seed", methods=["POST"])
    @_auth_required()
    @_require_role("admin")
    def api_rules_seed():  # type: ignore[unused-function]
        """DEBUG 或 ALLOW_DEV_SEED 下可用，便于 UI review。"""
        cfg = get_config()
        allow = bool(getattr(cfg, "DEBUG", False)) or (
            os.environ.get("ALLOW_DEV_SEED", "").lower() == "true"
        )
        if not allow:
            return jsonify({"error": "dev seed 在当前环境未启用"}), 403
        created = _seed_demo_rules(app)
        return jsonify({"status": "ok", "created": created}), 201

    @app.route("/api/threat_intel", methods=["GET"])
    @_auth_required()
    def api_threat_intel():  # type: ignore[unused-function]
        type_ = request.args.get("type") or None
        source = request.args.get("source") or None
        q = request.args.get("q") or None
        if type_ and type_ not in IOC_TYPES:
            return jsonify({"error": f"type 必须是 {list(IOC_TYPES)}"}), 400
        from src.collectors.ioc_repository import IOCRepository
        from web.database import db

        rows = IOCRepository(db.session).list_active_dicts()
        needle = (q or "").strip().lower()
        entries: List[Dict[str, Any]] = []
        for d in rows:
            if type_ and d["ioc_type"] != type_:
                continue
            if source and source not in (d.get("sources") or []):
                continue
            if needle:
                hay = " ".join(
                    [
                        str(d.get("value", "")),
                        str(d.get("reason", "")),
                        str(d.get("note", "")),
                        " ".join(d.get("sources") or []),
                    ]
                ).lower()
                if needle not in hay:
                    continue
            entries.append(_db_ioc_row_to_api_entry(d))
        by_type: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        for e in entries:
            by_type[e.get("type", "unknown")] = by_type.get(e.get("type", "unknown"), 0) + 1
            for s in e.get("sources") or []:
                by_source[s] = by_source.get(s, 0) + 1
        stats = {
            "total": len(entries),
            "by_type": by_type,
            "by_source": by_source,
        }
        resp = jsonify({"stats": stats, "entries": entries})
        resp.headers["X-Total-Count"] = str(len(entries))
        resp.headers["Access-Control-Expose-Headers"] = "X-Total-Count"
        return resp, 200

    @app.route("/api/threat_intel/providers", methods=["GET"])
    @_auth_required()
    def api_threat_intel_providers():  # type: ignore[unused-function]
        ti: ThreatIntelCollector = app.extensions["guardian_threat_intel"]
        mock = _threat_intel_mock_enabled()

        def _key_provider(has_key: bool) -> Dict[str, Any]:
            return {
                "enabled": bool(has_key) or mock,
                "configured": bool(has_key),
                "mock": mock and not has_key,
                "status": "live"
                if has_key
                else ("mock" if mock else "not_configured"),
            }

        pending = {
            "enabled": False,
            "configured": False,
            "mock": False,
            "status": "not_configured",
        }
        return (
            jsonify(
                {
                    "local": {
                        "enabled": True,
                        "configured": True,
                        "mock": False,
                        "status": "live",
                    },
                    "abuseipdb": _key_provider(bool(ti.abuseipdb_key)),
                    "virustotal": _key_provider(bool(ti.virustotal_key)),
                    "spamhaus": pending,
                    "phishtank": pending,
                    "openphish": pending,
                    "nvd": pending,
                    "cnvd": pending,
                }
            ),
            200,
        )

    @app.route("/api/threat_intel/iocs", methods=["POST"])
    @_auth_required()
    @_require_role("admin")
    @limiter.limit("60 per minute")
    def api_threat_intel_add_ioc():  # type: ignore[unused-function]
        payload = request.get_json(silent=True) or {}
        normalized, err = _validate_ioc_payload(payload)
        if err or not normalized:
            return jsonify({"error": err or "IOC 校验失败"}), 400

        from src.collectors.ioc_repository import IOCRepository
        from web.database import db

        ti: ThreatIntelCollector = app.extensions["guardian_threat_intel"]
        repo = IOCRepository(db.session)
        existing = repo.find_active_dict(normalized["type"], normalized["value"])
        if existing is None:
            try:
                ensure_quota(db.session, _current_tenant_id(), METRIC_IOCS, requested=1)
            except QuotaExceededError as exc:
                return quota_error_response(exc)
        row = repo.upsert_merge(
            ioc_type=normalized["type"],
            value=normalized["value"],
            source=normalized.get("source", "manual"),
            score=normalized.get("score"),
            ttl_seconds=normalized.get("ttl_seconds"),
            reason=normalized.get("reason"),
            note=normalized.get("note"),
            metadata=normalized.get("metadata"),
        )
        if existing is None:
            record_usage(
                db.session,
                _current_tenant_id(),
                METRIC_IOCS,
                actor=_current_actor(),
                resource_type="ioc",
                resource_id=f"{normalized['type']}:{normalized['value']}",
            )
        db.session.commit()
        ti.add_ioc_to_blacklist(normalized["type"], normalized["value"])
        _record_audit_event(
            event_type="ioc.created",
            actor=_current_actor(),
            resource_type="ioc",
            resource_id=f"{normalized['type']}:{normalized['value']}",
            payload={"source": normalized.get("source", "manual")},
        )
        return jsonify(_db_ioc_row_to_api_entry(row)), 201

    @app.route(
        "/api/threat_intel/iocs/<ioc_type>/<path:value>", methods=["DELETE"]
    )
    @_auth_required()
    @_require_role("admin")
    def api_threat_intel_remove_ioc(ioc_type: str, value: str):  # type: ignore[unused-function]
        if ioc_type not in IOC_TYPES:
            return jsonify({"error": f"type 必须是 {list(IOC_TYPES)}"}), 400
        canon = _canonical_ioc_value(ioc_type, value)
        if ioc_type == "ip" and not validate_ip(canon):
            return jsonify({"error": "无效的 IP 地址"}), 400
        if ioc_type == "domain" and not _is_valid_domain(canon):
            return jsonify({"error": "无效的域名"}), 400
        if ioc_type == "url" and not _is_valid_url(canon):
            return jsonify({"error": "无效的 URL"}), 400
        if ioc_type == "file_hash" and not _is_valid_file_hash(canon):
            return jsonify({"error": "无效的哈希"}), 400
        if ioc_type == "cve" and not _is_valid_cve(canon):
            return jsonify({"error": "无效的 CVE"}), 400

        from src.collectors.ioc_repository import IOCRepository
        from web.database import db

        repo = IOCRepository(db.session)
        removed_db = repo.delete(ioc_type, canon)
        if removed_db:
            record_usage(
                db.session,
                _current_tenant_id(),
                METRIC_IOCS,
                delta=-1,
                actor=_current_actor(),
                resource_type="ioc",
                resource_id=f"{ioc_type}:{canon}",
            )
        db.session.commit()
        ti: ThreatIntelCollector = app.extensions["guardian_threat_intel"]
        if ioc_type == "ip":
            ti.remove_ip_from_blacklist(canon)
        elif ioc_type == "domain":
            ti.remove_domain_from_blacklist(canon)
        else:
            ti.refresh_local_from_db()
        if not removed_db:
            return jsonify({"error": "IOC 不存在"}), 404
        _record_audit_event(
            event_type="ioc.deleted",
            actor=_current_actor(),
            resource_type="ioc",
            resource_id=f"{ioc_type}:{canon}",
        )
        return jsonify({"status": "ok", "type": ioc_type, "value": canon}), 200

    @app.route("/api/threat_intel/query", methods=["POST"])
    @_auth_required()
    @limiter.limit("30 per minute")
    def api_threat_intel_query():  # type: ignore[unused-function]
        payload = request.get_json(silent=True) or {}
        ioc_type = str(payload.get("type", "")).strip()
        value = str(payload.get("value", "")).strip()
        providers_raw = payload.get("providers")
        if ioc_type not in IOC_TYPES:
            return jsonify({"error": f"type 必须是 {list(IOC_TYPES)}"}), 400
        canon = _canonical_ioc_value(ioc_type, value)
        if ioc_type == "ip" and not validate_ip(canon):
            return jsonify({"error": "无效的 IP 地址"}), 400
        if ioc_type == "domain" and not _is_valid_domain(canon):
            return jsonify({"error": "无效的域名"}), 400
        if ioc_type == "url" and not _is_valid_url(canon):
            return jsonify({"error": "无效的 URL"}), 400
        if ioc_type == "file_hash" and not _is_valid_file_hash(canon):
            return jsonify({"error": "无效的哈希"}), 400
        if ioc_type == "cve" and not _is_valid_cve(canon):
            return jsonify({"error": "无效的 CVE"}), 400

        providers: List[str] = (
            [str(p) for p in providers_raw]
            if isinstance(providers_raw, list) and providers_raw
            else list(_DEFAULT_PROVIDERS)
        )
        for p in providers:
            if p not in _DEFAULT_PROVIDERS:
                return (
                    jsonify(
                        {
                            "error": f"provider 非法：{p}",
                            "allowed": list(_DEFAULT_PROVIDERS),
                        }
                    ),
                    400,
                )

        ti: ThreatIntelCollector = app.extensions["guardian_threat_intel"]
        results: Dict[str, Dict[str, Any]] = {}
        for provider in providers:
            if provider == "local":
                results["local"] = _threat_intel_local_lookup(app, state, ioc_type, canon)
            elif provider == "abuseipdb":
                results["abuseipdb"] = _threat_intel_abuseipdb(ti, ioc_type, canon)
            elif provider == "virustotal":
                results["virustotal"] = _threat_intel_virustotal(ti, ioc_type, canon)
            elif provider in ("spamhaus", "phishtank", "openphish", "nvd", "cnvd"):
                results[provider] = ti.query_provider(provider, ioc_type, canon)

        overall = _threat_intel_summarize(results)
        if results.get("local", {}).get("hit"):
            _incr_ioc_hit_db(ioc_type, canon)
        return (
            jsonify(
                {
                    "type": ioc_type,
                    "value": canon,
                    "results": results,
                    "overall": overall,
                    "evaluated_at": _now_iso(),
                }
            ),
            200,
        )

    @app.route("/api/threat_intel/_seed", methods=["POST"])
    @_auth_required()
    @_require_role("admin")
    def api_threat_intel_seed():  # type: ignore[unused-function]
        cfg = get_config()
        allow = bool(getattr(cfg, "DEBUG", False)) or (
            os.environ.get("ALLOW_DEV_SEED", "").lower() == "true"
        )
        if not allow:
            return jsonify({"error": "dev seed 在当前环境未启用"}), 403
        created = _seed_demo_iocs(app)
        return jsonify({"status": "ok", "created": created}), 201

    @app.route("/api/audit/events", methods=["GET"])
    @_auth_required()
    @_require_role("admin")
    def api_audit_events():  # type: ignore[unused-function]
        limit = _safe_int(request.args.get("limit"), default=100, max_value=500)
        offset = _safe_int(
            request.args.get("offset"),
            default=0,
            max_value=10_000,
            allow_zero=True,
        )
        event_type = (request.args.get("event_type") or "").strip()
        actor = (request.args.get("actor") or "").strip()
        resource_type = (request.args.get("resource_type") or "").strip()
        resource_id = (request.args.get("resource_id") or "").strip()
        ip_address = (request.args.get("ip_address") or "").strip()
        since = _parse_iso(request.args.get("since"))
        until = _parse_iso(request.args.get("until"))

        query = db.session.query(AuditEvent).filter(
            AuditEvent.tenant_id == _current_tenant_id()
        )
        if event_type:
            query = query.filter(AuditEvent.event_type == event_type)
        if actor:
            query = query.filter(AuditEvent.actor == actor)
        if resource_type:
            query = query.filter(AuditEvent.resource_type == resource_type)
        if resource_id:
            query = query.filter(AuditEvent.resource_id == resource_id)
        if ip_address:
            query = query.filter(AuditEvent.ip_address == ip_address)
        if since:
            query = query.filter(AuditEvent.created_at >= since)
        if until:
            query = query.filter(AuditEvent.created_at <= until)

        total = query.count()
        rows = (
            query.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return (
            jsonify(
                {
                    "items": [_audit_event_to_api_dict(row) for row in rows],
                    "total": total,
                    "offset": offset,
                    "limit": limit,
                }
            ),
            200,
        )

    @app.route("/api/reports", methods=["GET"])
    @_auth_required()
    def api_reports():  # type: ignore[unused-function]
        """返回可选的报告周期列表。Phase 7 先列出固定 period。"""
        return (
            jsonify(
                {
                    "available_periods": list(REPORT_PERIODS),
                    "default": "day",
                }
            ),
            200,
        )

    @app.route("/api/reports/summary", methods=["GET"])
    @_auth_required()
    def api_reports_summary():  # type: ignore[unused-function]
        period = request.args.get("period", "day").lower()
        if period not in REPORT_PERIODS:
            return (
                jsonify(
                    {
                        "error": f"period 必须是 {list(REPORT_PERIODS)}",
                    }
                ),
                400,
            )
        summary = _build_report_summary(app, period=period)
        return jsonify(summary), 200

    @app.route("/api/reports/export", methods=["GET"])
    @_auth_required()
    def api_reports_export():  # type: ignore[unused-function]
        """同 summary 数据源；``format=html`` 返回可打印/另存为 PDF 的 HTML。"""
        period = request.args.get("period", "day").lower()
        fmt = (request.args.get("format") or "json").strip().lower()
        if period not in REPORT_PERIODS:
            return (
                jsonify({"error": f"period 必须是 {list(REPORT_PERIODS)}"}),
                400,
            )
        if fmt not in ("json", "html"):
            return (
                jsonify(
                    {
                        "error": "format 必须是 json 或 html",
                        "note": "pdf 请使用 HTML + 浏览器打印为 PDF，或后续对接 headless 渲染。",
                    }
                ),
                400,
            )
        summary = _build_report_summary(app, period=period)
        if fmt == "html":
            resp = render_template("report_export.html", summary=summary)
            return (
                resp,
                200,
                {
                    "Content-Type": "text/html; charset=utf-8",
                    "Content-Disposition": 'inline; filename="guardian-report.html"',
                },
            )
        return jsonify(summary), 200

    @app.route("/api/settings", methods=["GET", "PUT"])
    @_auth_required()
    def api_settings():  # type: ignore[unused-function]
        if request.method == "GET":
            cache_key = _api_cache_key("settings")
            cached = _api_cache_get(cache_key)
            if cached is not None:
                return jsonify(cached), 200
            snapshot = _build_settings_snapshot(app)
            _api_cache_set(cache_key, snapshot)
            return jsonify(snapshot), 200

        if RBAC_ROLE_LEVEL.get(_current_role(), -1) < RBAC_ROLE_LEVEL["admin"]:
            return (
                jsonify(_error_payload(code="forbidden", message="需要 admin 或更高角色")),
                403,
            )
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"error": "请求体必须是对象"}), 400

        normalized, errors = _validate_settings_payload(
            payload, existing=state.all_settings()
        )
        if errors:
            return (
                jsonify(
                    {
                        "error": "部分字段校验未通过",
                        "errors": errors,
                    }
                ),
                400,
            )

        state.update_settings(normalized)
        _persist_settings_to_db(normalized)
        _api_cache_invalidate("settings")
        logger.info(
            "[Settings] 运行时配置更新: %s", list(normalized.keys())
        )
        _record_audit_event(
            event_type="settings.updated",
            actor=_current_actor(),
            resource_type="settings",
            payload={"updated_keys": list(normalized.keys())},
        )
        snapshot = _build_settings_snapshot(app)
        snapshot["status"] = "saved"
        snapshot["updated_keys"] = list(normalized.keys())
        return jsonify(snapshot), 200

    @app.route("/api/settings/test_webhook", methods=["POST"])
    @_auth_required()
    @limiter.limit("5 per minute")
    def api_settings_test_webhook():  # type: ignore[unused-function]
        payload = request.get_json(silent=True) or {}
        url = str(payload.get("url") or state.get_setting("alert_webhook") or "").strip()
        err = _validate_webhook_url(url)
        if err:
            return jsonify({"ok": False, "reason": err}), 400
        try:
            ensure_quota(db.session, _current_tenant_id(), METRIC_NOTIFICATIONS, requested=1)
        except QuotaExceededError as exc:
            return quota_error_response(exc)

        import requests as _requests

        try:
            resp = _requests.post(
                url,
                json={
                    "event": "ag_test_webhook",
                    "source": "ai-security-guardian",
                    "timestamp": _now_iso(),
                    "message": "这是一次手动触发的 Webhook 联通性测试。",
                },
                timeout=5,
                headers={"User-Agent": "AI-Security-Guardian/Phase7"},
            )
            record_usage(
                db.session,
                _current_tenant_id(),
                METRIC_NOTIFICATIONS,
                actor=_current_actor(),
                resource_type="notification",
                resource_id="webhook_test",
            )
            db.session.commit()
            return (
                jsonify(
                    {
                        "ok": resp.status_code < 400,
                        "status_code": resp.status_code,
                        "latency_ms": int(resp.elapsed.total_seconds() * 1000),
                    }
                ),
                200,
            )
        except _requests.exceptions.Timeout:
            return jsonify({"ok": False, "reason": "timeout"}), 200
        except _requests.exceptions.RequestException as exc:
            # 不回显 URL 以免暴露敏感路径；只回显异常类型
            return (
                jsonify(
                    {
                        "ok": False,
                        "reason": "request_error",
                        "detail": type(exc).__name__,
                    }
                ),
                200,
            )

    @app.route("/api/settings/test_email", methods=["POST"])
    @_auth_required()
    @limiter.limit("5 per minute")
    def api_settings_test_email():  # type: ignore[unused-function]
        """Phase 7 阶段仅校验邮箱格式；Phase 8 接入 SMTP 后改为真实投递。"""
        payload = request.get_json(silent=True) or {}
        email = str(
            payload.get("email") or state.get_setting("alert_email") or ""
        ).strip()
        if not email:
            return jsonify({"ok": False, "reason": "empty"}), 400
        if not _EMAIL_RE.match(email):
            return jsonify({"ok": False, "reason": "invalid_email_format"}), 400
        try:
            ensure_quota(db.session, _current_tenant_id(), METRIC_NOTIFICATIONS, requested=1)
        except QuotaExceededError as exc:
            return quota_error_response(exc)
        record_usage(
            db.session,
            _current_tenant_id(),
            METRIC_NOTIFICATIONS,
            actor=_current_actor(),
            resource_type="notification",
            resource_id="email_test",
        )
        db.session.commit()
        return (
            jsonify(
                {
                    "ok": True,
                    "stubbed": True,
                    "note": "邮件通道将在 Phase 8 接入 SMTP；当前仅做格式校验。",
                    "would_send_to": email,
                }
            ),
            200,
        )


# =====================================================================
# 命令面板：严格白名单 + 不拼接 shell
# =====================================================================
_COMMAND_PATTERN = re.compile(r"^(block|unblock|isolate|rate-limit|status)(?:\s+(\S+))?$")


def _execute_safe_command(raw: str, state: _ServerState) -> Dict[str, Any]:
    """对终端命令面板做白名单解析，绝不拼接到 shell。"""
    if not raw:
        return {"ok": False, "command": raw, "output": "命令为空"}

    match = _COMMAND_PATTERN.match(raw)
    if not match:
        return {
            "ok": False,
            "command": raw,
            "output": "命令不被允许。可用：block <ip> | unblock <ip> | isolate <ip> | rate-limit <ip> | status",
        }

    action, arg = match.group(1), match.group(2) or ""

    if action == "status":
        _sync_banned_cache_from_db(state)
        b_count = (
            tenant_query(db.session.query(func.count(BannedIp.ip)), BannedIp).scalar() or 0
        )
        t_count = tenant_query(db.session.query(func.count(Alert.id)), Alert).scalar() or 0
        return {
            "ok": True,
            "command": raw,
            "output": (
                f"banned_ips={b_count}, "
                f"threats={t_count}, "
                f"score={_compute_security_score_db()}"
            ),
        }

    if not validate_ip(arg):
        return {"ok": False, "command": raw, "output": f"无效 IP: {arg!r}"}

    if action == "block":
        approval_id = _record_ban_approval_request(
            arg,
            "command panel",
            operator="command_panel",
            source="command_panel",
        )
        return {
            "ok": True,
            "command": raw,
            "output": f"已创建封禁审批: {arg}",
            "status": STATUS_PENDING_APPROVAL,
            "response_action_id": approval_id,
        }
    if action == "unblock":
        ensure_quota(db.session, _current_tenant_id(), METRIC_RESPONSE_ACTIONS, requested=1)
        removed = _delete_banned_ip_persistent(arg)
        if removed:
            record_usage(
                db.session,
                _current_tenant_id(),
                METRIC_RESPONSE_ACTIONS,
                actor="command_panel",
                resource_type="response_action",
                resource_id=arg,
            )
            db.session.commit()
        _sync_banned_cache_from_db(state)
        return {
            "ok": removed,
            "command": raw,
            "output": f"{'已解封' if removed else 'IP 不在封禁列表中'}: {arg}",
        }
    if action == "rate-limit":
        return {"ok": True, "command": raw, "output": f"已对 {arg} 打开限速策略（示例）"}
    if action == "isolate":
        return {"ok": True, "command": raw, "output": f"CRITICAL：建议隔离主机 {arg}"}

    return {"ok": False, "command": raw, "output": "未知命令"}


# =====================================================================
# WebSocket
# =====================================================================
def _register_socket_handlers(socketio: SocketIO, state: _ServerState) -> None:
    @socketio.on("connect")
    def _on_connect():  # type: ignore[unused-function]
        # Phase 7 暂不在 WebSocket 握手阶段强制 JWT（浏览器首次连接尚未携带 header）；
        # 业务数据本身仅通过受保护 REST 获取，WebSocket 仅用于广播非敏感事件。
        logger.info("[WebSocket] 客户端已连接")
        socketio.emit("metrics_update", state.stats)

    @socketio.on("disconnect")
    def _on_disconnect():  # type: ignore[unused-function]
        logger.info("[WebSocket] 客户端已断开")

    @socketio.on("ping_client")
    def _on_ping(data: Any):  # type: ignore[unused-function]
        socketio.emit("pong_client", {"echo": data, "ts": _now_iso()})


def _register_access_log_writer(app: Flask) -> None:
    """Optionally emit Apache/Nginx-compatible access logs for main.py ingestion."""
    enabled = os.environ.get("FLASK_ACCESS_LOG_ENABLED", "").lower() == "true"
    if not enabled:
        return

    log_path = os.environ.get("FLASK_ACCESS_LOG_PATH", "logs/access.log")

    def _escape_log_value(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    @app.after_request
    def _write_access_log(response):  # type: ignore[unused-function]
        try:
            full_path = request.full_path.rstrip("?") or request.path
            client_ip = (
                request.headers.get("X-Forwarded-For", request.remote_addr or "-")
                .split(",", 1)[0]
                .strip()
                or "-"
            )
            timestamp = datetime.now(timezone.utc).astimezone().strftime(
                "%d/%b/%Y:%H:%M:%S %z"
            )
            size = response.calculate_content_length()
            line = (
                f'{client_ip} - - [{timestamp}] '
                f'"{request.method} {_escape_log_value(full_path)} HTTP/{request.environ.get("SERVER_PROTOCOL", "HTTP/1.1").split("/", 1)[-1]}" '
                f'{response.status_code} {size if size is not None else "-"} '
                f'"{_escape_log_value(request.referrer or "-")}" '
                f'"{_escape_log_value(request.user_agent.string or "-")}"'
            )
            path = os.path.abspath(log_path)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:  # noqa: BLE001
            logger.debug("access log write failed", exc_info=True)
        return response


def push_alert(app: Flask, alert: Dict[str, Any]) -> Dict[str, Any]:
    """供后端检测/响应流水线调用：先入库再广播（与 Stream consumer 语义一致）。

    事件名统一为 `alert`（对齐 DESIGN §8.2 与 Phase 7 前端提示词）。
    仅当数据库写入成功时才更新内存缓存并 ``Socket.IO`` 广播；失败时返回空 dict。
    """
    state: _ServerState = app.extensions["guardian_state"]
    sio: SocketIO = app.extensions["guardian_socketio"]
    pre: Dict[str, Any] = dict(alert)
    pre.setdefault("id", _uuid())
    pre.setdefault("timestamp", _now_iso())
    level = pre.get("level")
    if level not in ALERT_LEVELS:
        pre["level"] = "low"
    status = pre.get("status")
    if status not in ALERT_STATUSES:
        pre["status"] = "open"
    pre.setdefault("threat_type", "unknown")
    pre["source_ip"] = str(pre.get("source_ip") or "").strip()
    pre.setdefault("title", pre.get("details") or pre.get("message") or "未分类告警")
    pre.setdefault("summary", pre.get("title"))
    pre.setdefault("history", [{"status": pre["status"], "timestamp": pre["timestamp"]}])

    try:
        with app.app_context():
            row = _upsert_alert_to_db(pre)
            if row is None:
                api_dict = None
            else:
                api_dict = _alert_to_api_dict(row)
    except QuotaExceededError as exc:
        logger.warning("[Alert] 告警配额超限: %s", exc)
        return {}
    except Exception:  # noqa: BLE001
        logger.exception("[Alert] 告警入库失败，跳过 Socket 广播")
        return {}

    if not api_dict:
        logger.warning("[Alert] 入库跳过（缺少 id）")
        return {}
    state.add_alert(api_dict)
    state.stats["total_threats"] = state.stats.get("total_threats", 0) + 1
    try:
        sio.emit("alert", api_dict)
    except Exception:  # noqa: BLE001
        logger.debug("[Alert] Socket emit 失败", exc_info=True)
    return api_dict


def push_metrics(app: Flask, metrics: Dict[str, Any]) -> None:
    """广播指标更新，触发前端卡片/图表刷新。"""
    state: _ServerState = app.extensions["guardian_state"]
    sio: SocketIO = app.extensions["guardian_socketio"]
    state.stats.update(metrics)
    state.stats["updated_at"] = _now_iso()
    sio.emit("metrics_update", state.stats)


# =====================================================================
# 错误处理
# =====================================================================
def _register_jwt_error_handlers(jwt: JWTManager) -> None:
    @jwt.unauthorized_loader
    def _missing(reason: str):  # type: ignore[unused-function]
        body = _error_payload(code="jwt_missing", message="缺少有效 JWT")
        body["reason"] = reason
        return jsonify(body), 401

    @jwt.invalid_token_loader
    def _invalid(reason: str):  # type: ignore[unused-function]
        body = _error_payload(code="jwt_invalid", message="JWT 无效")
        body["reason"] = reason
        return jsonify(body), 401

    @jwt.expired_token_loader
    def _expired(jwt_header, jwt_payload):  # type: ignore[unused-function]
        return jsonify(_error_payload(code="jwt_expired", message="JWT 已过期")), 401

    @jwt.revoked_token_loader
    def _revoked(jwt_header, jwt_payload):  # type: ignore[unused-function]
        return jsonify(_error_payload(code="jwt_revoked", message="JWT 已被吊销")), 401


def _register_common_error_handlers(app: Flask) -> None:
    @app.errorhandler(429)
    def _rate_limit(err):  # type: ignore[unused-function]
        body = _error_payload(
            code="rate_limited",
            message="请求过于频繁，已触发限流",
        )
        body["retry_after"] = getattr(err, "description", None)
        return (
            jsonify(body),
            429,
        )

    @app.errorhandler(403)
    def _forbidden(err):  # type: ignore[unused-function]
        return jsonify(_error_payload(code="forbidden", message="无权限访问")), 403

    @app.errorhandler(404)
    def _not_found(err):  # type: ignore[unused-function]
        # 仅对 /api/* 返回 JSON；页面请求让 Flask 走默认模板/重定向
        if request.path.startswith("/api/"):
            return (
                jsonify(
                    _error_payload(code="not_found", message="资源不存在")
                ),
                404,
            )
        return redirect(url_for("page_dashboard"))


# =====================================================================
# 小工具
# =====================================================================
def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _api_cache_key(namespace: str, *parts: Any) -> str:
    tenant = _current_tenant_id()
    suffix = "|".join(str(p) for p in parts)
    return f"{namespace}:{tenant}:{suffix}"


def _api_cache_get(key: str) -> Optional[Any]:
    cache = current_app.extensions.setdefault("guardian_core_api_cache", {})
    item = cache.get(key)
    if not item:
        return None
    expires_at, value = item
    if expires_at <= time.monotonic():
        cache.pop(key, None)
        return None
    return copy.deepcopy(value)


def _api_cache_set(key: str, value: Any, *, ttl: float = 5.0) -> Any:
    cache = current_app.extensions.setdefault("guardian_core_api_cache", {})
    cache[key] = (time.monotonic() + ttl, copy.deepcopy(value))
    return value


def _api_cache_invalidate(namespace: str) -> None:
    cache = current_app.extensions.setdefault("guardian_core_api_cache", {})
    prefix = f"{namespace}:"
    for key in [k for k in cache if k.startswith(prefix)]:
        cache.pop(key, None)


def _register_api_auth_gate(app: Flask) -> None:
    """Authenticate all API calls through either JWT or tenant-bound API keys."""

    exempt_paths = {"/api/health", "/api/auth/login", "/api/auth/refresh"}

    @app.before_request
    def _guardian_api_auth_gate():  # type: ignore[unused-function]
        if request.method == "OPTIONS":
            return None
        if not request.path.startswith("/api/") or request.path in exempt_paths:
            return None
        return _authenticate_api_request()


def _authenticate_api_request():
    raw_key = _extract_api_key()
    if raw_key:
        ok, response = _authenticate_api_key(raw_key)
        if not ok:
            return response
        return None

    try:
        verify_jwt_in_request()
    except Exception:
        raise

    identity = str(get_jwt_identity() or "").strip()
    claims = get_jwt() or {}
    tenant_id = str(claims.get("tenant_id") or "").strip()
    if not tenant_id:
        _record_audit_event(
            event_type="auth.jwt_failed",
            actor=identity or "anonymous",
            resource_type="auth",
            resource_id=identity or None,
            payload={"reason": "missing_tenant"},
        )
        return jsonify(_error_payload(code="forbidden", message="JWT 缺少租户上下文")), 403

    role = _resolve_jwt_role(identity, tenant_id)
    if role is None:
        _record_audit_event(
            event_type="auth.jwt_failed",
            actor=identity or "anonymous",
            resource_type="auth",
            resource_id=identity or None,
            payload={"reason": "tenant_membership_denied", "tenant_id": tenant_id},
        )
        return jsonify(_error_payload(code="forbidden", message="无权访问该租户")), 403

    request.guardian_auth_method = "jwt"
    request.guardian_actor = identity
    request.guardian_tenant_id = tenant_id
    request.guardian_role = role
    if not _is_tenant_status_self_service_path():
        denied = _tenant_access_denied_response(tenant_id)
        if denied is not None:
            return denied
    if os.environ.get("AUTH_SUCCESS_AUDIT_ENABLED", "false").lower() == "true":
        _record_audit_event(
            event_type="auth.jwt_authenticated",
            actor=identity,
            resource_type="auth",
            resource_id=identity,
            payload={"role": role, "tenant_id": tenant_id, "path": request.path},
        )
    try:
        _meter_api_call()
    except QuotaExceededError as exc:
        return quota_error_response(exc)
    return None


def _extract_api_key() -> str:
    key = str(request.headers.get("X-API-Key") or "").strip()
    if key:
        return key
    auth = str(request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("apikey "):
        return auth.split(" ", 1)[1].strip()
    return ""


def _authenticate_api_key(raw_key: str):
    prefix = raw_key[:16]
    # tenant-scan: allow API key prefix is globally unique; resolved row sets request tenant.
    row = db.session.query(APIKey).filter(APIKey.key_prefix == prefix).one_or_none()
    now = datetime.now(timezone.utc)
    if row is None or not secrets.compare_digest(row.key_hash, _hash_api_key(raw_key)):
        _record_audit_event(
            event_type="auth.api_key_failed",
            actor=f"api_key:{prefix or 'unknown'}",
            resource_type="api_key",
            resource_id=prefix or None,
            payload={"reason": "not_found_or_mismatch"},
        )
        return False, (jsonify(_error_payload(code="auth_failed", message="API Key 无效")), 401)
    if row.status != "active":
        request.guardian_tenant_id = row.tenant_id
        _record_audit_event(
            event_type="auth.api_key_failed",
            actor=f"api_key:{row.key_prefix}",
            resource_type="api_key",
            resource_id=row.id,
            payload={"reason": "disabled", "tenant_id": row.tenant_id},
        )
        return False, (jsonify(_error_payload(code="auth_failed", message="API Key 已停用")), 401)
    expires_at = _aware_utc(row.expires_at)
    if expires_at is not None and expires_at <= now:
        request.guardian_tenant_id = row.tenant_id
        _record_audit_event(
            event_type="auth.api_key_failed",
            actor=f"api_key:{row.key_prefix}",
            resource_type="api_key",
            resource_id=row.id,
            payload={"reason": "expired", "tenant_id": row.tenant_id},
        )
        return False, (jsonify(_error_payload(code="auth_failed", message="API Key 已过期")), 401)

    request.guardian_auth_method = "api_key"
    request.guardian_actor = f"api_key:{row.key_prefix}"
    request.guardian_tenant_id = row.tenant_id
    request.guardian_role = row.role if row.role in RBAC_ROLES else "viewer"
    request.guardian_api_key_id = row.id
    if not _is_tenant_status_self_service_path():
        denied = _tenant_access_denied_response(row.tenant_id)
        if denied is not None:
            return False, denied
    row.last_used_at = now
    db.session.commit()
    if os.environ.get("AUTH_SUCCESS_AUDIT_ENABLED", "false").lower() == "true":
        _record_audit_event(
            event_type="auth.api_key_authenticated",
            actor=request.guardian_actor,
            resource_type="api_key",
            resource_id=row.id,
            payload={"role": request.guardian_role, "tenant_id": row.tenant_id, "path": request.path},
        )
    try:
        _meter_api_call()
    except QuotaExceededError as exc:
        return False, quota_error_response(exc)
    return True, None


def _meter_api_call() -> None:
    tenant_id = _current_tenant_id()
    operation = "read" if request.method in {"GET", "HEAD", "OPTIONS"} else "write"
    if not _api_call_metering_sync_enabled():
        _meter_api_call_buffered(tenant_id, operation)
        return

    used = _current_api_call_usage(tenant_id)
    quota_cfg = _api_call_quota_config(tenant_id)
    limit = quota_cfg.get("limit")
    if limit is not None and used + 1 > int(limit):
        ensure_quota(
            db.session,
            tenant_id,
            METRIC_API_CALLS,
            requested=1,
            current=used,
            operation=operation,
            actor=_current_actor(),
        )
    _increment_api_call_usage_fast(tenant_id)
    db.session.commit()


def _api_call_metering_sync_enabled() -> bool:
    raw = os.environ.get("API_CALL_METERING_SYNC")
    if raw is not None:
        return raw.strip().lower() in {"true", "1", "yes", "on"}
    return bool(current_app.config.get("TESTING", False))


def _meter_api_call_buffered(tenant_id: str, operation: str) -> None:
    buffered = _api_call_buffered_delta(tenant_id)
    used = _current_api_call_usage(tenant_id) + buffered
    quota_cfg = _api_call_quota_config(tenant_id)
    limit = quota_cfg.get("limit")
    overage_checked = False
    if limit is not None and used + 1 > int(limit):
        ensure_quota(
            db.session,
            tenant_id,
            METRIC_API_CALLS,
            requested=1,
            current=used,
            operation=operation,
            actor=_current_actor(),
        )
        overage_checked = True

    pending = _buffer_api_call_delta(tenant_id, 1)
    if pending >= 100 or overage_checked:
        _flush_api_call_usage_buffer(tenant_id)
        db.session.commit()


def _api_call_metering_lock() -> threading.Lock:
    lock = current_app.extensions.get("guardian_api_call_metering_lock")
    if lock is None:
        lock = threading.Lock()
        current_app.extensions["guardian_api_call_metering_lock"] = lock
    return lock


def _api_call_buffered_delta(tenant_id: str) -> int:
    with _api_call_metering_lock():
        buffer = current_app.extensions.setdefault("guardian_api_call_metering_buffer", {})
        return int(buffer.get(tenant_id, 0) or 0)


def _buffer_api_call_delta(tenant_id: str, delta: int) -> int:
    with _api_call_metering_lock():
        buffer = current_app.extensions.setdefault("guardian_api_call_metering_buffer", {})
        pending = int(buffer.get(tenant_id, 0) or 0) + int(delta)
        buffer[tenant_id] = pending
        return pending


def _flush_api_call_usage_buffer(tenant_id: str) -> None:
    with _api_call_metering_lock():
        buffer = current_app.extensions.setdefault("guardian_api_call_metering_buffer", {})
        delta = int(buffer.pop(tenant_id, 0) or 0)
    if delta > 0:
        _increment_api_call_usage_fast(tenant_id, delta=delta)


def _api_call_quota_config(tenant_id: str) -> Dict[str, Any]:
    now = time.monotonic()
    cache = current_app.extensions.setdefault("guardian_api_call_quota_cache", {})
    cached = cache.get(tenant_id)
    if cached and cached.get("expires_at", 0.0) > now:
        return cached["value"]
    snapshot = quota_snapshot(db.session, tenant_id, METRIC_API_CALLS, used=0)
    value = {
        "limit": snapshot.limit,
        "overage_policy": snapshot.overage_policy,
        "warning_thresholds": tuple(snapshot.warning_thresholds),
    }
    cache[tenant_id] = {"expires_at": now + 10.0, "value": value}
    return value


def _current_api_call_usage(tenant_id: str) -> int:
    used = (
        db.session.query(UsageMeter.used)
        .filter(
            UsageMeter.tenant_id == tenant_id,
            UsageMeter.metric == METRIC_API_CALLS,
            UsageMeter.period == "current",
        )
        .scalar()
    )
    return int(used or 0)


def _increment_api_call_usage_fast(tenant_id: str, *, delta: int = 1) -> None:
    """Increment API call counters without per-request audit rows."""
    now = datetime.now(timezone.utc)
    periods = ("current",)
    for period in periods:
        db.session.execute(
            text(
                """
                INSERT INTO usage_meters
                    (tenant_id, metric, period, period_start, period_end, used, created_at, updated_at)
                VALUES
                    (:tenant_id, :metric, :period, NULL, NULL, 0, :now, :now)
                ON CONFLICT(tenant_id, metric, period) DO NOTHING
                """
            ),
            {
                "tenant_id": tenant_id,
                "metric": METRIC_API_CALLS,
                "period": period,
                "now": now,
            },
        )
        db.session.execute(
            text(
                """
                UPDATE usage_meters
                SET used = used + :delta, updated_at = :now
                WHERE tenant_id = :tenant_id AND metric = :metric AND period = :period
                """
            ),
            {
                "tenant_id": tenant_id,
                "metric": METRIC_API_CALLS,
                "period": period,
                "delta": int(delta),
                "now": now,
            },
        )


def _is_tenant_status_self_service_path() -> bool:
    return request.path in {"/api/tenant/commercial/status"}


def _hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _api_key_to_api_dict(row: APIKey, *, include_secret: Optional[str] = None) -> Dict[str, Any]:
    data = {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "key_prefix": row.key_prefix,
        "role": row.role,
        "status": row.status,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
    if include_secret:
        data["api_key"] = include_secret
    return data


def _tenant_admin_summary(row: Tenant) -> Dict[str, Any]:
    alert_count = (
        db.session.query(func.count(Alert.id))
        .filter(Alert.tenant_id == row.id)
        .scalar()
        or 0
    )
    active_sub = (
        db.session.query(Subscription)
        .filter(Subscription.tenant_id == row.id, Subscription.status == "active")
        .order_by(Subscription.created_at.desc())
        .first()
    )
    return {
        "id": row.id,
        "name": row.name,
        "slug": row.slug,
        "status": row.status,
        "plan": row.plan,
        "active_subscription": _subscription_to_api_dict(active_sub) if active_sub else None,
        "usage_summary": {"alerts": int(alert_count)},
        "created_at": _dt_iso(row.created_at),
        "updated_at": _dt_iso(row.updated_at),
    }


def _tenant_admin_detail(row: Tenant) -> Dict[str, Any]:
    subscriptions = (
        db.session.query(Subscription)
        .filter(Subscription.tenant_id == row.id)
        .order_by(Subscription.created_at.desc())
        .all()
    )
    licenses = (
        db.session.query(LicenseKey)
        .filter(LicenseKey.tenant_id == row.id)
        .order_by(LicenseKey.created_at.desc())
        .all()
    )
    quotas = [_quota_usage_to_api_dict(row.id, metric) for metric in sorted(METERED_METRICS)]
    return {
        **_tenant_admin_summary(row),
        "subscriptions": [_subscription_to_api_dict(sub) for sub in subscriptions],
        "licenses": [_license_to_api_dict(lic) for lic in licenses],
        "quotas": quotas,
    }


def _tenant_commercial_status(row: Tenant) -> Dict[str, Any]:
    licenses = (
        db.session.query(LicenseKey)
        .filter(LicenseKey.tenant_id == row.id)
        .order_by(LicenseKey.created_at.desc())
        .all()
    )
    quotas = [_quota_usage_to_api_dict(row.id, metric) for metric in sorted(METERED_METRICS)]
    overages = [item for item in quotas if item.get("exceeded")]
    active_sub = (
        db.session.query(Subscription)
        .filter(Subscription.tenant_id == row.id, Subscription.status == "active")
        .order_by(Subscription.created_at.desc())
        .first()
    )
    return {
        "tenant": {
            "id": row.id,
            "name": row.name,
            "slug": row.slug,
            "status": row.status,
            "plan": row.plan,
        },
        "current_plan": _plan_to_api_dict(active_sub.plan) if active_sub and active_sub.plan else None,
        "subscription": _subscription_to_api_dict(active_sub) if active_sub else None,
        "licenses": [_license_to_api_dict(lic) for lic in licenses],
        "quotas": quotas,
        "overages": overages,
        "has_overage": bool(overages),
    }


def _plan_to_api_dict(row: Plan) -> Dict[str, Any]:
    return {
        "id": row.id,
        "code": row.code,
        "name": row.name,
        "status": row.status,
        "limits": dict(row.limits or {}),
        "created_at": _dt_iso(row.created_at),
        "updated_at": _dt_iso(row.updated_at),
    }


def _license_to_api_dict(row: LicenseKey) -> Dict[str, Any]:
    expires_at = _aware_utc(row.expires_at)
    is_expired = expires_at is not None and expires_at <= datetime.now(timezone.utc)
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "key_prefix": row.key_prefix,
        "status": row.status,
        "effective_status": "expired" if is_expired else row.status,
        "limits": dict(row.limits or {}),
        "issued_to": row.issued_to,
        "expires_at": _dt_iso(row.expires_at),
        "is_expired": is_expired,
        "created_at": _dt_iso(row.created_at),
        "updated_at": _dt_iso(row.updated_at),
    }


def _subscription_to_api_dict(row: Optional[Subscription]) -> Dict[str, Any]:
    if row is None:
        return {}
    ends_at = _aware_utc(row.ends_at)
    is_expired = ends_at is not None and ends_at <= datetime.now(timezone.utc)
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "plan_id": row.plan_id,
        "plan_code": row.plan.code if row.plan else None,
        "license_key_id": row.license_key_id,
        "status": row.status,
        "effective_status": "expired" if is_expired else row.status,
        "starts_at": _dt_iso(row.starts_at),
        "ends_at": _dt_iso(row.ends_at),
        "is_expired": is_expired,
        "created_at": _dt_iso(row.created_at),
        "updated_at": _dt_iso(row.updated_at),
    }


def _quota_usage_to_api_dict(tenant_id: str, metric: str) -> Dict[str, Any]:
    snap = quota_snapshot(db.session, tenant_id, metric)
    row = (
        db.session.query(Quota)
        .filter(Quota.tenant_id == tenant_id, Quota.metric == metric)
        .one_or_none()
    )
    data = snap.to_dict()
    data["source"] = row.source if row is not None else "effective"
    if snap.limit is None:
        data["usage_ratio"] = None
    elif snap.limit <= 0:
        data["usage_ratio"] = 1.0 if snap.used > 0 else 0.0
    else:
        data["usage_ratio"] = round(snap.used / snap.limit, 4)
    return data


def _usage_bucket_to_api_dict(row: UsageMeter) -> Dict[str, Any]:
    return {
        "tenant_id": row.tenant_id,
        "metric": row.metric,
        "period": row.period,
        "period_start": _dt_iso(row.period_start),
        "period_end": _dt_iso(row.period_end),
        "used": int(row.used or 0),
        "created_at": _dt_iso(row.created_at),
        "updated_at": _dt_iso(row.updated_at),
    }


def _normalize_warning_thresholds_payload(raw: Any) -> Tuple[List[float], Optional[str]]:
    if not isinstance(raw, list):
        return [], "warning_thresholds 必须是数组"
    out: List[float] = []
    for value in raw:
        try:
            threshold = float(value)
        except (TypeError, ValueError):
            return [], "warning_thresholds 只能包含 0 到 1 之间的数字"
        if threshold <= 0 or threshold > 1:
            return [], "warning_thresholds 只能包含 0 到 1 之间的数字"
        out.append(round(threshold, 4))
    return sorted(set(out)), None


def _normalize_limits(raw: Any) -> Tuple[Dict[str, Optional[int]], Optional[str]]:
    if not isinstance(raw, dict):
        return {}, "limits 必须是对象"
    out: Dict[str, Optional[int]] = {}
    for key, value in raw.items():
        metric = str(key).strip()
        if metric not in METERED_METRICS:
            return {}, f"未知配额指标: {metric}"
        if value is None or value == "":
            out[metric] = None
            continue
        try:
            limit = int(value)
        except (TypeError, ValueError):
            return {}, f"{metric} 必须是整数或 null"
        if limit < 0:
            return {}, f"{metric} 不能为负数"
        out[metric] = limit
    return out, None


def _aware_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _resolve_jwt_role(identity: str, tenant_id: str) -> Optional[str]:
    from web.models import Membership, Role, User

    user = (
        db.session.query(User)
        .filter((User.username == identity) | (User.email == identity))
        .one_or_none()
    )
    if user is None:
        if tenant_id != login_tenant_id(identity):
            return None
        return _login_role(identity)
    membership = (
        db.session.query(Membership)
        .join(Role, Membership.role_id == Role.id)
        .filter(
            Membership.user_id == user.id,
            Membership.tenant_id == tenant_id,
            Membership.status == "active",
            Role.name.in_(RBAC_ROLES),
        )
        .one_or_none()
    )
    if membership is None:
        return None
    return membership.role.name


def _resolve_login_context(username: str, requested_tenant_id: str = "") -> Tuple[str, str]:
    from web.models import Membership, Role, User

    user = (
        db.session.query(User)
        .filter((User.username == username) | (User.email == username))
        .one_or_none()
    )
    if user is None:
        return login_tenant_id(username), _login_role(username)

    query = (
        db.session.query(Membership)
        .join(Role, Membership.role_id == Role.id)
        .filter(
            Membership.user_id == user.id,
            Membership.status == "active",
            Role.name.in_(RBAC_ROLES),
        )
    )
    if requested_tenant_id:
        query = query.filter(Membership.tenant_id == requested_tenant_id)
    membership = query.order_by(Membership.created_at.asc()).first()
    if membership is None:
        return login_tenant_id(username), _login_role(username)
    return membership.tenant_id, membership.role.name


def _current_actor() -> str:
    if has_request_context():
        actor = getattr(request, "guardian_actor", "")
        if actor:
            return str(actor)
    try:
        return str(get_jwt_identity() or "operator")
    except Exception:  # noqa: BLE001
        return "operator"


def _current_auth_method() -> str:
    if has_request_context():
        method = getattr(request, "guardian_auth_method", "")
        if method:
            return str(method)
    return "jwt"


def _login_role(username: str) -> str:
    """解析当前单账号的角色；为后续多用户表预留 JWT claim 形状。"""
    configured = (
        os.environ.get("ADMIN_ROLE")
        or os.environ.get(f"ADMIN_ROLE_{username.upper()}")
        or "admin"
    )
    role = str(configured).strip().lower()
    return role if role in RBAC_ROLES else "admin"


def _current_role() -> str:
    if has_request_context():
        request_role = str(getattr(request, "guardian_role", "") or "").strip().lower()
        if request_role in RBAC_ROLES:
            return request_role
    try:
        role = str((get_jwt() or {}).get("role") or "admin").strip().lower()
    except Exception:  # noqa: BLE001
        role = "admin"
    return role if role in RBAC_ROLES else "admin"


def _auth_required():
    """Marker decorator; request authentication is enforced by before_request."""

    def _decorator(fn):
        @wraps(fn)
        def _wrapped(*args, **kwargs):
            return fn(*args, **kwargs)

        return _wrapped

    return _decorator


def _require_role(min_role: str):
    """最小 RBAC 装饰器：viewer < analyst < admin。"""

    def _decorator(fn):
        @wraps(fn)
        def _wrapped(*args, **kwargs):
            role = _current_role()
            if RBAC_ROLE_LEVEL.get(role, -1) < RBAC_ROLE_LEVEL.get(min_role, 99):
                return (
                    jsonify(
                        _error_payload(
                            code="forbidden",
                            message=f"需要 {min_role} 或更高角色",
                        )
                    ),
                    403,
                )
            return fn(*args, **kwargs)

        return _wrapped

    return _decorator


def _is_platform_admin() -> bool:
    if _current_role() != "admin":
        return False
    return _current_tenant_id() == configured_default_tenant_id()


def _require_platform_admin():
    """SaaS 控制面只允许平台租户上的 admin 操作。"""

    def _decorator(fn):
        @wraps(fn)
        def _wrapped(*args, **kwargs):
            if not _is_platform_admin():
                return (
                    jsonify(
                        _error_payload(
                            code="forbidden",
                            message="需要平台管理员权限",
                        )
                    ),
                    403,
                )
            return fn(*args, **kwargs)

        return _wrapped

    return _decorator


def _tenant_access_denied_response(tenant_id: str):
    row = db.session.get(Tenant, tenant_id)
    if row is None:
        return jsonify(_error_payload(code="forbidden", message="租户不存在或不可用")), 403
    if row.status == "active":
        return None
    _record_audit_event(
        event_type="tenant.access_denied",
        actor=_current_actor(),
        resource_type="tenant",
        resource_id=tenant_id,
        payload={"status": row.status, "path": request.path if has_request_context() else None},
    )
    return (
        jsonify(
            _error_payload(
                code="tenant_inactive",
                message=f"租户状态为 {row.status}，访问受限",
            )
        ),
        403,
    )


def _error_payload(
    *,
    code: str,
    message: str,
) -> Dict[str, Any]:
    """统一错误体；保留 `error` 字段兼容已有前端分支。"""
    return {
        "error": message,
        "code": code,
        "message": message,
    }


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _safe_int(
    value: Optional[str],
    default: int,
    max_value: int,
    *,
    allow_zero: bool = False,
) -> int:
    if value is None:
        return default
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    lower = 0 if allow_zero else 1
    return max(lower, min(v, max_value))


def _uuid() -> str:
    return uuid.uuid4().hex


# =====================================================================
# 仅开发环境：生成演示告警（便于 UI review，生产环境已在路由层拒绝）
# =====================================================================
_DEMO_TYPES: Tuple[Tuple[str, str, str], ...] = (
    ("port_scan", "端口扫描", "连接速率异常，疑似全端口扫描"),
    ("sql_injection", "SQL 注入尝试", "请求体命中 ' OR 1=1 -- 特征"),
    ("xss", "XSS 注入", "请求参数包含未转义 <script> 标签"),
    ("brute_force", "暴力破解", "登录端口 1 分钟内 200 次失败尝试"),
    ("dos", "DoS 流量异常", "单 IP SYN flood 超阈值"),
    ("malware_c2", "C2 回连", "目的域命中威胁情报 IOC"),
    ("credential_stuff", "凭据填充", "多账户短时高失败率"),
    ("unknown", "模型异常检测", "聚类偏离正常流量基线"),
)

_DEMO_LEVELS: Tuple[Tuple[str, float], ...] = (
    ("low", 0.35),
    ("medium", 0.30),
    ("high", 0.20),
    ("critical", 0.15),
)

_DEMO_PROTOCOLS: Tuple[str, ...] = ("TCP", "UDP", "HTTP", "HTTPS", "DNS")


def _weighted_choice(pairs: Iterable[Tuple[str, float]], rng: random.Random) -> str:
    items = list(pairs)
    r = rng.random()
    acc = 0.0
    for key, weight in items:
        acc += weight
        if r <= acc:
            return key
    return items[-1][0]


def _fake_public_ip(rng: random.Random) -> str:
    # 避开保留段，随机返回可用作演示的公网 IP 形态
    while True:
        a = rng.randint(1, 223)
        if a in (10, 127, 169, 172, 192, 224, 240):
            continue
        return f"{a}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _seed_demo_alerts(app: Flask, count: int = 12) -> int:
    """写入 demo 告警并通过 WebSocket 广播。仅开发环境调用。"""
    state: _ServerState = app.extensions["guardian_state"]
    socketio: SocketIO = app.extensions["guardian_socketio"]
    rng = random.Random()
    now = datetime.now(timezone.utc).astimezone()
    created = 0
    for _ in range(count):
        threat_key, title, summary = rng.choice(_DEMO_TYPES)
        level = _weighted_choice(_DEMO_LEVELS, rng)
        src = _fake_public_ip(rng)
        dst = f"10.0.{rng.randint(0, 4)}.{rng.randint(1, 254)}"
        proto = rng.choice(_DEMO_PROTOCOLS)
        # 近 24h 内随机时间
        ts = (now - timedelta(minutes=rng.randint(0, 1440))).isoformat(timespec="seconds")
        confidence = round(rng.uniform(0.55, 0.99), 3)
        alert = {
            "id": _uuid(),
            "timestamp": ts,
            "level": level,
            "status": "open",
            "threat_type": threat_key,
            "title": title,
            "summary": f"{summary}（来源 {src}）",
            "source_ip": src,
            "source_port": rng.randint(1024, 65535),
            "dest_ip": dst,
            "dest_port": rng.choice([22, 80, 443, 3306, 3389, 8080]),
            "protocol": proto,
            "confidence": confidence,
            "model_version": "v1",
            "recommended_action": "block" if level in ("high", "critical") else "monitor",
            "features": {
                "packets_per_sec": rng.randint(10, 5000),
                "avg_packet_size": rng.randint(40, 1500),
                "unique_ports": rng.randint(1, 120),
                "failed_ratio": round(rng.uniform(0.0, 0.98), 2),
                "payload_entropy": round(rng.uniform(2.0, 7.9), 2),
            },
            "indicators": [
                f"src={src}",
                f"proto={proto}",
                f"model_version=v1 confidence={confidence}",
            ],
            "explanation": (
                f"模型在 {proto} 流量上检测到 {title}。"
                f"关键特征：包速率偏离基线 > 3σ；载荷熵 {round(rng.uniform(3.0, 7.5), 2)}；"
                f"来源 IP 在近 1 小时出现 {rng.randint(3, 120)} 次。"
            ),
            "raw": (
                f"{proto} {src}:{rng.randint(1024, 65535)} -> {dst}:{rng.choice([80, 443])}\n"
                f"GET /admin?q=' OR 1=1 -- HTTP/1.1\n"
                f"User-Agent: sqlmap/1.7.2\n"
                f"Host: {dst}\n"
            ),
        }
        with app.app_context():
            row = _upsert_alert_to_db(alert)
        if row is None:
            continue
        api_dict = _alert_to_api_dict(row)
        state.add_alert(api_dict)
        state.stats["total_threats"] = state.stats.get("total_threats", 0) + 1
        try:
            socketio.emit("alert", api_dict)
        except Exception:  # noqa: BLE001
            logger.debug("alert 广播失败", exc_info=True)
        created += 1
    state.stats["updated_at"] = _now_iso()
    return created


# =====================================================================
# 检测规则：校验 / 测试引擎 / 演示种子
# =====================================================================
# 允许用于 threshold 表达式的特征名（白名单）
_RULE_FEATURE_KEYS: Tuple[str, ...] = (
    "packets_per_sec",
    "avg_packet_size",
    "unique_ports",
    "failed_ratio",
    "payload_entropy",
    "confidence",
)
# threshold 规则表达式：`<feature> <op> <number>`；仅允许上述白名单 + 有限操作符
_RULE_THRESHOLD_RE = re.compile(
    r"^\s*(?P<key>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?P<op>>=|<=|>|<|==|!=)\s*(?P<val>-?\d+(?:\.\d+)?)\s*$"
)


def _validate_rule_payload(
    payload: Dict[str, Any], *, partial: bool = False
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """规范化 / 校验规则入参。partial=True 用于 PUT 合并语义。

    返回 (normalized, error)；任一成功则另一为 None。
    """
    result: Dict[str, Any] = {}

    # 必填字段（完整创建时）
    required = ("name", "type", "pattern", "action", "level")
    if not partial:
        missing = [k for k in required if not str(payload.get(k, "")).strip()]
        if missing:
            return None, f"缺少必填字段：{', '.join(missing)}"

    if "name" in payload:
        name = str(payload.get("name", "")).strip()
        if not name or len(name) > _RULE_NAME_MAX:
            return None, f"name 必填且长度 <= {_RULE_NAME_MAX}"
        result["name"] = name

    if "type" in payload:
        rtype = str(payload.get("type", "")).strip()
        if rtype not in RULE_TYPES:
            return None, f"type 必须是 {RULE_TYPES}"
        result["type"] = rtype

    if "pattern" in payload:
        pattern = str(payload.get("pattern", ""))
        if len(pattern) > _RULE_PATTERN_MAX:
            return None, f"pattern 长度不得超过 {_RULE_PATTERN_MAX} 字符"
        result["pattern"] = pattern

    if "action" in payload:
        action = str(payload.get("action", "")).strip()
        if action not in RULE_ACTIONS:
            return None, f"action 必须是 {RULE_ACTIONS}"
        result["action"] = action

    if "level" in payload:
        level = str(payload.get("level", "")).strip()
        if level not in ALERT_LEVELS:
            return None, f"level 必须是 {ALERT_LEVELS}"
        result["level"] = level

    if "priority" in payload:
        try:
            prio = int(payload.get("priority"))
        except (TypeError, ValueError):
            return None, "priority 必须是整数（1~999）"
        if prio < 1 or prio > 999:
            return None, "priority 必须在 1~999"
        result["priority"] = prio
    elif not partial:
        result["priority"] = 100

    if "enabled" in payload:
        result["enabled"] = bool(payload.get("enabled"))
    elif not partial:
        result["enabled"] = True

    if "description" in payload:
        desc = str(payload.get("description", ""))
        if len(desc) > _RULE_DESC_MAX:
            return None, f"description 长度不得超过 {_RULE_DESC_MAX} 字符"
        result["description"] = desc

    # 对 pattern 做类型相关的结构校验
    effective_type = result.get("type") or (
        payload.get("type") if partial else None
    )
    effective_pattern = result.get("pattern")
    if effective_pattern is not None and effective_type:
        err = _validate_rule_pattern(effective_type, effective_pattern)
        if err:
            return None, err

    return result, None


def _validate_rule_pattern(rule_type: str, pattern: str) -> Optional[str]:
    """根据规则类型对 pattern 做结构校验，返回错误字符串或 None。"""
    if rule_type == "signature":
        if not pattern.strip():
            return "signature 规则需要非空的匹配串"
        # 避免提交可编译为昂贵回溯的正则：只允许普通字符串或前后斜杠包裹的小正则
        if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 1:
            body = pattern[1:-1]
            try:
                re.compile(body)
            except re.error as exc:
                return f"signature 正则无效：{exc}"
        return None

    if rule_type == "threshold":
        if not _RULE_THRESHOLD_RE.match(pattern):
            return (
                "threshold 规则格式：'<feature> <op> <number>'；"
                f"feature 允许 {_RULE_FEATURE_KEYS}，op ∈ >,>=,<,<=,==,!="
            )
        m = _RULE_THRESHOLD_RE.match(pattern)
        if m and m.group("key") not in _RULE_FEATURE_KEYS:
            return f"threshold 只允许特征：{_RULE_FEATURE_KEYS}"
        return None

    if rule_type == "anomaly":
        if not pattern.strip():
            return "anomaly 规则需要声明关注的特征列表（逗号分隔）"
        keys = [k.strip() for k in pattern.split(",") if k.strip()]
        bad = [k for k in keys if k not in _RULE_FEATURE_KEYS]
        if bad:
            return f"anomaly 仅允许特征：{_RULE_FEATURE_KEYS}；无效：{bad}"
        return None

    return None


def _evaluate_rule(
    rule: Dict[str, Any], sample: Dict[str, Any]
) -> Dict[str, Any]:
    """对给定样本评估规则命中情况。

    样本字段（可选）：
        payload: str   —— 用于 signature 匹配
        src_ip: str    —— 用于在 reason 中回显
        features: dict —— 用于 threshold / anomaly（数值）
    """
    rule_type = rule.get("type")
    pattern = str(rule.get("pattern", ""))
    payload = str(sample.get("payload", ""))
    features = sample.get("features") or {}
    matched = False
    reason = ""

    if rule_type == "signature":
        if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 1:
            body = pattern[1:-1]
            try:
                matched = bool(re.search(body, payload))
                reason = (
                    f"正则 {pattern} 在 payload 中匹配"
                    if matched
                    else f"正则 {pattern} 未命中 payload"
                )
            except re.error as exc:
                return {
                    "matched": False,
                    "reason": f"正则编译失败：{exc}",
                    "rule_type": rule_type,
                    "evaluated_at": _now_iso(),
                }
        else:
            matched = pattern in payload
            reason = (
                f"payload 包含子串 '{pattern}'"
                if matched
                else f"payload 中未出现 '{pattern}'"
            )
    elif rule_type == "threshold":
        m = _RULE_THRESHOLD_RE.match(pattern)
        if not m:
            return {
                "matched": False,
                "reason": "threshold pattern 格式非法",
                "rule_type": rule_type,
                "evaluated_at": _now_iso(),
            }
        key, op, raw_val = m.group("key"), m.group("op"), m.group("val")
        if key not in _RULE_FEATURE_KEYS:
            return {
                "matched": False,
                "reason": f"特征 {key} 不在白名单",
                "rule_type": rule_type,
                "evaluated_at": _now_iso(),
            }
        if key not in features:
            return {
                "matched": False,
                "reason": f"sample.features 缺少特征 {key}",
                "rule_type": rule_type,
                "evaluated_at": _now_iso(),
            }
        try:
            left = float(features[key])
            right = float(raw_val)
        except (TypeError, ValueError):
            return {
                "matched": False,
                "reason": f"特征 {key} 或阈值 {raw_val} 非数值",
                "rule_type": rule_type,
                "evaluated_at": _now_iso(),
            }
        ops = {
            ">": left > right,
            ">=": left >= right,
            "<": left < right,
            "<=": left <= right,
            "==": left == right,
            "!=": left != right,
        }
        matched = bool(ops.get(op))
        reason = (
            f"实测 {key}={left} {op} {right} → {'命中' if matched else '未命中'}"
        )
    elif rule_type == "anomaly":
        keys = [k.strip() for k in pattern.split(",") if k.strip()]
        missing = [k for k in keys if k not in features]
        if missing:
            return {
                "matched": False,
                "reason": f"sample.features 缺少特征：{missing}",
                "rule_type": rule_type,
                "evaluated_at": _now_iso(),
            }
        # anomaly 示例判定：特征绝对值超出常识范围则命中；纯演示逻辑，Phase 8 替换为真实离群检测
        anomalies: List[str] = []
        bounds = {
            "packets_per_sec": (0, 3000),
            "avg_packet_size": (40, 1500),
            "unique_ports": (0, 50),
            "failed_ratio": (0.0, 0.6),
            "payload_entropy": (0.0, 6.5),
            "confidence": (0.0, 1.0),
        }
        for k in keys:
            lo, hi = bounds.get(k, (float("-inf"), float("inf")))
            try:
                v = float(features[k])
            except (TypeError, ValueError):
                continue
            if v < lo or v > hi:
                anomalies.append(f"{k}={v} 超出 [{lo}, {hi}]")
        matched = bool(anomalies)
        reason = "；".join(anomalies) if matched else "所有特征在常识范围内"
    else:
        return {
            "matched": False,
            "reason": f"未知规则类型 {rule_type}",
            "rule_type": rule_type,
            "evaluated_at": _now_iso(),
        }

    src = sample.get("src_ip")
    if src and matched:
        reason = f"[src={src}] " + reason
    return {
        "matched": matched,
        "reason": reason,
        "rule_type": rule_type,
        "evaluated_at": _now_iso(),
    }


_DEMO_RULES: Tuple[Dict[str, Any], ...] = (
    {
        "name": "SQLi 关键特征",
        "type": "signature",
        "pattern": "' OR 1=1",
        "action": "block",
        "level": "high",
        "priority": 10,
        "description": "检测请求体中的典型 SQL 布尔注入 Payload。",
        "enabled": True,
    },
    {
        "name": "可疑 User-Agent (sqlmap)",
        "type": "signature",
        "pattern": "/sqlmap\\/\\d+\\./",
        "action": "alert",
        "level": "medium",
        "priority": 20,
        "description": "自动化注入工具指纹。",
        "enabled": True,
    },
    {
        "name": "高速扫描来源",
        "type": "threshold",
        "pattern": "packets_per_sec > 1500",
        "action": "block",
        "level": "high",
        "priority": 30,
        "description": "单 IP 包速率超基线 3σ，疑似扫描或 DoS。",
        "enabled": True,
    },
    {
        "name": "失败率异常",
        "type": "threshold",
        "pattern": "failed_ratio >= 0.85",
        "action": "alert",
        "level": "medium",
        "priority": 40,
        "description": "短时失败率极高，疑似爆破。",
        "enabled": True,
    },
    {
        "name": "低置信度模型输出",
        "type": "threshold",
        "pattern": "confidence < 0.6",
        "action": "monitor",
        "level": "low",
        "priority": 90,
        "description": "模型置信度偏低，仅记录不阻断。",
        "enabled": False,
    },
    {
        "name": "多维度异常聚类",
        "type": "anomaly",
        "pattern": "packets_per_sec,unique_ports,failed_ratio",
        "action": "alert",
        "level": "critical",
        "priority": 5,
        "description": "多项特征同时偏离基线，严重告警。",
        "enabled": True,
    },
)


def _seed_demo_rules(app: Flask) -> int:
    created = 0
    for tpl in _DEMO_RULES:
        norm, err = _validate_rule_payload(dict(tpl))
        if err or not norm:
            logger.warning("[Rules] demo 规则校验失败：%s -> %s", tpl.get("name"), err)
            continue
        _insert_rule_from_normalized(norm)
        created += 1
    return created


# =====================================================================
# 威胁情报：校验 / provider 分发 / mock / seed
# =====================================================================
_IOC_REASON_MAX: int = 200
_IOC_NOTE_MAX: int = 400
_IOC_SOURCE_MAX: int = 40


def _is_valid_domain(value: str) -> bool:
    return bool(value) and bool(_DOMAIN_RE.match(value))


def _is_valid_url(value: str) -> bool:
    v = (value or "").strip()
    return len(v) <= 2048 and (v.startswith("http://") or v.startswith("https://"))


def _is_valid_file_hash(value: str) -> bool:
    return bool(_HASH_RE.match((value or "").strip()))


def _is_valid_cve(value: str) -> bool:
    return bool(_CVE_RE.match((value or "").strip()))


def _canonical_ioc_value(ioc_type: str, value: str) -> str:
    t = ioc_type.lower().strip()
    v = value.strip()
    if t == "domain":
        return v.lower()
    if t == "file_hash":
        return v.lower()
    if t == "cve":
        m = _CVE_RE.match(v)
        return m.group(1).upper() if m else v.upper()
    return v


def _db_ioc_row_to_api_entry(d: Dict[str, Any]) -> Dict[str, Any]:
    def _iso(x: Any) -> Optional[str]:
        if x is None:
            return None
        if hasattr(x, "isoformat"):
            return x.isoformat()
        return str(x)

    return {
        "id": d["id"],
        "type": d["ioc_type"],
        "value": d["value"],
        "sources": d.get("sources") or [],
        "reason": d.get("reason") or "",
        "note": d.get("note") or "",
        "score": d.get("score"),
        "ttl_seconds": d.get("ttl_seconds"),
        "first_seen": _iso(d.get("first_seen")),
        "last_seen": _iso(d.get("last_seen")),
        "expires_at": _iso(d.get("expires_at")),
        "metadata": d.get("metadata"),
        "hits": d.get("hits", 0),
        "added_at": _iso(d.get("added_at")),
        "updated_at": _iso(d.get("updated_at")),
    }


def _validate_ioc_payload(
    payload: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    ioc_type = str(payload.get("type", "")).strip()
    raw_value = str(payload.get("value", "")).strip()
    if ioc_type not in IOC_TYPES:
        return None, f"type 必须是 {list(IOC_TYPES)}"
    if ioc_type == "ip":
        if not validate_ip(raw_value):
            return None, "无效的 IP 地址"
    elif ioc_type == "domain":
        if not _is_valid_domain(raw_value):
            return None, "无效的域名"
    elif ioc_type == "url":
        if not _is_valid_url(raw_value):
            return None, "无效的 URL（需 http/https，长度≤2048）"
    elif ioc_type == "file_hash":
        if not _is_valid_file_hash(raw_value):
            return None, "无效的文件哈希（32~128 位十六进制）"
    elif ioc_type == "cve":
        if not _is_valid_cve(raw_value):
            return None, "无效的 CVE 编号"

    value = _canonical_ioc_value(ioc_type, raw_value)

    source = str(payload.get("source", "manual")).strip() or "manual"
    if len(source) > _IOC_SOURCE_MAX:
        return None, f"source 长度不得超过 {_IOC_SOURCE_MAX}"

    reason = str(payload.get("reason", ""))
    if len(reason) > _IOC_REASON_MAX:
        return None, f"reason 长度不得超过 {_IOC_REASON_MAX}"

    note = str(payload.get("note", ""))
    if len(note) > _IOC_NOTE_MAX:
        return None, f"note 长度不得超过 {_IOC_NOTE_MAX}"

    score_raw = payload.get("score")
    score: Optional[int] = None
    if score_raw not in (None, ""):
        try:
            score = int(score_raw)
        except (TypeError, ValueError):
            return None, "score 必须是整数"
        if score < 0 or score > 100:
            return None, "score 必须在 0~100"

    ttl_raw = payload.get("ttl_seconds")
    ttl_seconds: Optional[int] = None
    if ttl_raw not in (None, ""):
        try:
            ttl_seconds = int(ttl_raw)
        except (TypeError, ValueError):
            return None, "ttl_seconds 必须是整数"
        if ttl_seconds < 0 or ttl_seconds > 86400 * 365 * 10:
            return None, "ttl_seconds 超出合理范围"

    meta = payload.get("metadata")
    if meta is not None and not isinstance(meta, dict):
        return None, "metadata 必须是 JSON 对象"

    return (
        {
            "type": ioc_type,
            "value": value,
            "source": source,
            "reason": reason,
            "note": note,
            "score": score,
            "ttl_seconds": ttl_seconds,
            "metadata": meta,
        },
        None,
    )


def _threat_intel_mock_enabled() -> bool:
    cfg = get_config()
    return bool(getattr(cfg, "DEBUG", False)) or (
        os.environ.get("THREAT_INTEL_MOCK", "").lower() == "true"
    ) or (os.environ.get("ALLOW_DEV_SEED", "").lower() == "true")


def _threat_intel_local_lookup(
    app: Flask, state: _ServerState, ioc_type: str, value: str
) -> Dict[str, Any]:
    try:
        from src.collectors.ioc_repository import IOCRepository
        from web.database import db

        with app.app_context():
            row = IOCRepository(db.session).find_active_dict(ioc_type, value)
        if row:
            exp = row.get("expires_at")
            return {
                "provider": "local",
                "ok": True,
                "hit": True,
                "is_malicious": True,
                "score": row.get("score"),
                "sources": row.get("sources", []),
                "reason": row.get("reason") or "命中本地 IOC（数据库）",
                "added_at": row.get("added_at").isoformat() if row.get("added_at") else None,
                "updated_at": row.get("updated_at").isoformat() if row.get("updated_at") else None,
                "expires_at": exp.isoformat() if exp else None,
                "metadata": row.get("metadata"),
                "hits": row.get("hits", 0),
            }
    except Exception:  # noqa: BLE001
        pass

    return {
        "provider": "local",
        "ok": True,
        "hit": False,
        "is_malicious": False,
        "reason": "本地黑名单未命中",
    }


def _threat_intel_abuseipdb(
    ti: ThreatIntelCollector, ioc_type: str, value: str
) -> Dict[str, Any]:
    if ioc_type != "ip":
        return {
            "provider": "abuseipdb",
            "ok": False,
            "reason": "abuseipdb 仅支持 IP 查询",
        }
    if ti.abuseipdb_key:
        return ti.query_abuseipdb_detailed(value)
    if _threat_intel_mock_enabled():
        return _mock_abuseipdb(value)
    return {
        "provider": "abuseipdb",
        "ok": False,
        "reason": "api_key_missing",
    }


def _threat_intel_virustotal(
    ti: ThreatIntelCollector, ioc_type: str, value: str
) -> Dict[str, Any]:
    if ti.virustotal_key:
        return ti.query_provider("virustotal", ioc_type, value)
    if _threat_intel_mock_enabled():
        return _mock_virustotal(ioc_type, value)
    return {
        "provider": "virustotal",
        "ok": False,
        "reason": "api_key_missing",
    }


def _threat_intel_summarize(
    results: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    is_malicious = False
    max_score: Optional[int] = None
    providers_hit: List[str] = []
    for prov, r in results.items():
        if not r.get("ok"):
            continue
        if r.get("is_malicious") or r.get("hit"):
            is_malicious = True
            providers_hit.append(prov)
        s = r.get("score")
        if isinstance(s, (int, float)) and s is not None:
            if max_score is None or s > max_score:
                max_score = int(s)
    return {
        "is_malicious": is_malicious,
        "max_score": max_score,
        "providers_hit": providers_hit,
    }


def _mock_hash_int(seed: str, mod: int, offset: int = 0) -> int:
    """基于稳定哈希把字符串映射到确定性整数区间。"""
    import hashlib

    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    num = int.from_bytes(digest[:8], "big")
    return (num % mod) + offset


def _mock_abuseipdb(ip: str) -> Dict[str, Any]:
    score = _mock_hash_int(f"abuseipdb:{ip}", 101)  # 0..100
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
        "last_reported_at": _now_iso(),
    }


def _mock_virustotal(ioc_type: str, value: str) -> Dict[str, Any]:
    seed = f"vt:{ioc_type}:{value.lower()}"
    malicious = _mock_hash_int(seed + ":mal", 20)
    suspicious = _mock_hash_int(seed + ":sus", 10)
    harmless = _mock_hash_int(seed + ":har", 50, offset=30)
    undetected = _mock_hash_int(seed + ":und", 20, offset=5)
    reputation = _mock_hash_int(seed + ":rep", 101, offset=-50)  # -50..50
    base = {
        "ok": True,
        "provider": "virustotal",
        "mocked": True,
        "is_malicious": malicious >= 3,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "reputation": reputation,
    }
    if ioc_type == "ip":
        base.update(
            {
                "country": _mock_abuseipdb(value)["country_code"],
                "as_owner": "AS65535 Mock Networks",
                "network": ".".join(value.split(".")[:3]) + ".0/24",
            }
        )
    else:
        base.update(
            {
                "categories": {
                    "Mock Vendor": "malware"
                    if malicious >= 3
                    else "business",
                },
                "registrar": "Mock Registrar Ltd.",
            }
        )
    return base


_DEMO_IOCS: Tuple[Dict[str, Any], ...] = (
    {
        "type": "ip",
        "value": "185.220.101.1",
        "source": "abuseipdb",
        "reason": "Tor exit node 高置信度滥用",
        "note": "来自威胁情报共享的样本",
        "score": 92,
    },
    {
        "type": "ip",
        "value": "45.95.168.7",
        "source": "manual",
        "reason": "近期针对内部 API 的暴力登录来源",
        "score": 78,
    },
    {
        "type": "ip",
        "value": "194.26.29.254",
        "source": "manual",
        "reason": "扫描器来源（多端口高速探测）",
        "score": 65,
    },
    {
        "type": "domain",
        "value": "evil-example.com",
        "source": "virustotal",
        "reason": "C2 回连域名（样本），分类为 malware",
        "score": 88,
    },
    {
        "type": "domain",
        "value": "phish-test.xyz",
        "source": "phishtank",
        "reason": "钓鱼样本域名",
        "score": 70,
    },
)


def _seed_demo_iocs(app: Flask) -> int:
    ti: ThreatIntelCollector = app.extensions["guardian_threat_intel"]
    from src.collectors.ioc_repository import IOCRepository
    from web.database import db

    created = 0
    for item in _DEMO_IOCS:
        norm, err = _validate_ioc_payload(dict(item))
        if err or not norm:
            logger.warning(
                "[ThreatIntel] demo IOC 校验失败：%s -> %s",
                item.get("value"),
                err,
            )
            continue
        IOCRepository(db.session).upsert_merge(
            ioc_type=norm["type"],
            value=norm["value"],
            source=norm["source"],
            reason=norm.get("reason"),
            note=norm.get("note"),
            score=norm.get("score"),
        )
        ti.add_ioc_to_blacklist(norm["type"], norm["value"])
        created += 1
    db.session.commit()
    ti.refresh_local_from_db()
    return created


# =====================================================================
# 系统设置：默认值 / 校验 / 快照
# =====================================================================
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_RATE_LIMIT_RE = re.compile(
    r"^\d+\s+per\s+(second|minute|hour|day)$", re.IGNORECASE
)


def _default_editable_settings() -> Dict[str, Any]:
    """从环境变量 / get_config 提取初次启动时的可写字段默认值。"""
    return {
        "detection_sensitivity": _safe_float(
            os.environ.get("DETECTION_SENSITIVITY"), default=0.7, lo=0.0, hi=1.0
        ),
        "alert_threshold": _safe_float(
            os.environ.get("ALERT_THRESHOLD"), default=0.6, lo=0.0, hi=1.0
        ),
        "alert_email": os.environ.get("ALERT_EMAIL", ""),
        "alert_webhook": os.environ.get("ALERT_WEBHOOK", ""),
        "model_version": os.environ.get("MODEL_VERSION", "v1"),
        "model_hot_reload": os.environ.get("MODEL_HOT_RELOAD", "false").lower()
        == "true",
    }


def _safe_float(
    value: Optional[str], *, default: float, lo: float, hi: float
) -> float:
    if value is None or value == "":
        return default
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def _validate_webhook_url(url: str) -> Optional[str]:
    """Webhook URL 校验：与 ``check_webhook_url_safe`` 对齐，防 SSRF。"""
    if not url or not str(url).strip():
        return "empty"
    if len(url) > 2048:
        return "URL 长度过长"
    chk = check_webhook_url_safe(str(url).strip())
    if chk.ok:
        return None
    _reasons = {
        "empty_url": "URL 为空",
        "parse_error": "URL 解析失败",
        "scheme_not_http": "必须以 http:// 或 https:// 开头",
        "missing_host": "缺少主机名",
        "localhost_forbidden": "不允许使用 localhost",
        "blocked_ip_literal": "不允许指向回环、链路本地、元数据或内网地址",
        "dns_resolution_failed": "主机名无法解析",
        "blocked_hostname": "不允许指向元数据或保留主机名",
    }
    if chk.reason.startswith("resolved_to_blocked:"):
        return "DNS 解析结果指向禁止网段"
    return _reasons.get(chk.reason, "Webhook 地址未通过安全检查")


def _validate_settings_payload(
    payload: Dict[str, Any],
    existing: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """返回 (normalized, errors_by_field)。只处理 schema 中白名单的字段。

    existing 用于跨字段校验（如 alert_threshold ≤ detection_sensitivity），
    即便用户只提交了其中一个字段也能拿到另一个的当前值。
    """
    existing = existing or {}
    normalized: Dict[str, Any] = {}
    errors: Dict[str, str] = {}
    for key, raw in payload.items():
        if key not in SETTINGS_SCHEMA:
            # 忽略未知字段，但不报错，保持 PATCH-friendly 语义
            continue
        spec = SETTINGS_SCHEMA[key]
        kind = spec["type"]
        if kind == "float":
            try:
                v = float(raw)
            except (TypeError, ValueError):
                errors[key] = "必须是数字"
                continue
            lo, hi = spec.get("min", 0.0), spec.get("max", 1.0)
            if v < lo or v > hi:
                errors[key] = f"必须在 {lo} ~ {hi}"
                continue
            normalized[key] = round(v, 4)
        elif kind == "bool":
            if isinstance(raw, bool):
                normalized[key] = raw
            elif isinstance(raw, str):
                s = raw.strip().lower()
                if s in ("true", "1", "yes", "on"):
                    normalized[key] = True
                elif s in ("false", "0", "no", "off", ""):
                    normalized[key] = False
                else:
                    errors[key] = "必须是 true / false"
            else:
                errors[key] = "必须是布尔值"
        elif kind == "email":
            value = str(raw or "").strip()
            if not value and spec.get("optional"):
                normalized[key] = ""
                continue
            if not _EMAIL_RE.match(value):
                errors[key] = "邮箱格式不合法"
                continue
            normalized[key] = value
        elif kind == "url":
            value = str(raw or "").strip()
            if not value and spec.get("optional"):
                normalized[key] = ""
                continue
            err = _validate_webhook_url(value)
            if err:
                errors[key] = err
                continue
            normalized[key] = value
        elif kind == "string":
            value = str(raw or "").strip()
            if not value:
                errors[key] = "不能为空"
                continue
            pattern = spec.get("pattern")
            if pattern and not re.match(pattern, value):
                errors[key] = "格式非法"
                continue
            normalized[key] = value

    # 跨字段规则：告警阈值不应高于检测灵敏度
    effective_sens = normalized.get("detection_sensitivity")
    if effective_sens is None:
        effective_sens = existing.get("detection_sensitivity")
    effective_thr = normalized.get("alert_threshold")
    if effective_thr is None:
        effective_thr = existing.get("alert_threshold")
    if (
        effective_thr is not None
        and effective_sens is not None
        and "alert_threshold" not in errors
        and float(effective_thr) > float(effective_sens)
    ):
        errors["alert_threshold"] = "不能高于检测灵敏度"

    return normalized, errors


def _build_settings_snapshot(app: Flask) -> Dict[str, Any]:
    state: _ServerState = app.extensions["guardian_state"]
    cfg = get_config()
    editable = state.all_settings()
    runtime = {
        "jwt_access_expires_seconds": int(cfg.JWT_TOKEN_EXPIRES),
        "jwt_refresh_expires_seconds": int(cfg.JWT_REFRESH_TOKEN_EXPIRES),
        "api_rate_limit": cfg.API_RATE_LIMIT,
        "log_integrity_enabled": bool(cfg.LOG_INTEGRITY_ENABLED),
        "allowed_origins": list(cfg.ALLOWED_ORIGINS),
    }
    return {
        "editable": editable,
        "runtime": runtime,
        "schema": SETTINGS_SCHEMA,
    }


# =====================================================================
# 审计报告：从现有状态即席聚合 5 个模块
# =====================================================================
_PERIOD_DELTA: Dict[str, timedelta] = {
    "day": timedelta(days=1),
    "week": timedelta(days=7),
    "month": timedelta(days=30),
}


def _report_window(period: str) -> Tuple[datetime, datetime]:
    now = datetime.now(timezone.utc).astimezone()
    start = now - _PERIOD_DELTA.get(period, timedelta(days=1))
    return start, now


def _build_report_summary(app: Flask, *, period: str = "day") -> Dict[str, Any]:
    state: _ServerState = app.extensions["guardian_state"]
    start, end = _report_window(period)
    start_u = start.astimezone(timezone.utc)
    end_u = end.astimezone(timezone.utc)

    tenant_id = _current_tenant_id()
    base = db.session.query(Alert).filter(
        Alert.tenant_id == tenant_id,
        Alert.timestamp >= start_u,
        Alert.timestamp <= end_u,
    )
    total_alerts = base.count()

    level_rows = (
        db.session.query(Alert.level, func.count(Alert.id))
        .filter(
            Alert.tenant_id == tenant_id,
            Alert.timestamp >= start_u,
            Alert.timestamp <= end_u,
        )
        .group_by(Alert.level)
        .all()
    )
    by_level: Dict[str, int] = {lv: 0 for lv in ALERT_LEVELS}
    for lv, cnt in level_rows:
        key = str(lv or "low")
        if key in by_level:
            by_level[key] = int(cnt)

    status_rows = (
        db.session.query(Alert.status, func.count(Alert.id))
        .filter(
            Alert.tenant_id == tenant_id,
            Alert.timestamp >= start_u,
            Alert.timestamp <= end_u,
        )
        .group_by(Alert.status)
        .all()
    )
    by_status: Dict[str, int] = {st: 0 for st in ALERT_STATUSES}
    for st, cnt in status_rows:
        key = str(st or "open")
        if key in by_status:
            by_status[key] = int(cnt)

    type_rows = (
        db.session.query(Alert.threat_type, func.count(Alert.id))
        .filter(
            Alert.tenant_id == tenant_id,
            Alert.timestamp >= start_u,
            Alert.timestamp <= end_u,
        )
        .group_by(Alert.threat_type)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
        .all()
    )
    by_type = {str(t or "unknown"): int(c) for t, c in type_rows}

    top_rows = (
        db.session.query(Alert.source_ip, func.count(Alert.id))
        .filter(
            Alert.tenant_id == tenant_id,
            Alert.timestamp >= start_u,
            Alert.timestamp <= end_u,
            Alert.source_ip != "",
        )
        .group_by(Alert.source_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
        .all()
    )
    top_sources = {ip: int(c) for ip, c in top_rows}

    avg_conf_raw = (
        db.session.query(func.avg(Alert.confidence))
        .filter(
            Alert.tenant_id == tenant_id,
            Alert.timestamp >= start_u,
            Alert.timestamp <= end_u,
            Alert.confidence.isnot(None),
        )
        .scalar()
    )
    avg_conf = round(float(avg_conf_raw), 3) if avg_conf_raw is not None else 0.0

    aw = base.filter(Alert.confidence.isnot(None))
    conf_bins = [
        int(
            aw.filter(Alert.confidence < 0.2).count(),
        ),
        int(
            aw.filter(Alert.confidence >= 0.2, Alert.confidence < 0.4).count(),
        ),
        int(
            aw.filter(Alert.confidence >= 0.4, Alert.confidence < 0.6).count(),
        ),
        int(
            aw.filter(Alert.confidence >= 0.6, Alert.confidence < 0.8).count(),
        ),
        int(aw.filter(Alert.confidence >= 0.8).count()),
    ]

    buckets = _bucket_timeline_from_db(start, end, period)

    responses = _collect_report_responses(start_u, end_u)

    mv = (
        db.session.query(ModelVersion)
        .filter(ModelVersion.tenant_id == tenant_id)
        .order_by(
            ModelVersion.deployed_at.desc().nulls_last(),
            ModelVersion.id.desc(),
        )
        .first()
    )
    mv_label = (
        mv.version
        if mv
        else (
            state.get_setting("model_version")
            or os.environ.get("MODEL_VERSION", "v1")
        )
    )

    model_perf = {
        "version": mv_label,
        "registry_note": mv.notes if mv and mv.notes else None,
        "total_checked": total_alerts,
        "avg_confidence": avg_conf,
        "confidence_distribution": [
            {"range": "0.0 – 0.2", "count": conf_bins[0]},
            {"range": "0.2 – 0.4", "count": conf_bins[1]},
            {"range": "0.4 – 0.6", "count": conf_bins[2]},
            {"range": "0.6 – 0.8", "count": conf_bins[3]},
            {"range": "0.8 – 1.0", "count": conf_bins[4]},
        ],
        "high_confidence_ratio": (
            round(sum(conf_bins[3:]) / total_alerts, 3) if total_alerts else 0.0
        ),
        "detection_rate": (
            round(1.0 - (by_status.get("ignored", 0) / total_alerts), 3)
            if total_alerts
            else 0.0
        ),
        "mean_resolution_latency_sec": _mean_resolution_latency_db(start_u, end_u),
    }

    recommendations = _build_recommendations(
        by_level=by_level,
        by_status=by_status,
        by_type=by_type,
        top_sources=top_sources,
        total_alerts=total_alerts,
        enabled_rules=_rules_enabled_count(),
        ioc_total=_active_ioc_count(),
        avg_confidence=avg_conf,
    )

    banned_total = (
        db.session.query(func.count(BannedIp.ip))
        .filter(BannedIp.tenant_id == tenant_id)
        .scalar()
        or 0
    )

    overview = {
        "total_alerts": total_alerts,
        "critical_alerts": by_level.get("critical", 0),
        "high_alerts": by_level.get("high", 0),
        "medium_alerts": by_level.get("medium", 0),
        "low_alerts": by_level.get("low", 0),
        "open_alerts": by_status.get("open", 0),
        "resolved_alerts": by_status.get("resolved", 0),
        "acknowledged_alerts": by_status.get("acknowledged", 0),
        "ignored_alerts": by_status.get("ignored", 0),
        "security_score": _compute_security_score_db(),
        "banned_ips": int(banned_total),
        "iocs_total": _active_ioc_count(),
        "rules_total": _rules_total_count(),
        "rules_enabled": _rules_enabled_count(),
    }

    return {
        "period": period,
        "window": {
            "start": start.isoformat(timespec="seconds"),
            "end": end.isoformat(timespec="seconds"),
        },
        "generated_at": _now_iso(),
        "overview": overview,
        "threats": {
            "by_level": [
                {"level": lv, "count": by_level.get(lv, 0)} for lv in ALERT_LEVELS
            ],
            "by_type": sorted(
                [{"type": k, "count": v} for k, v in by_type.items()],
                key=lambda x: -x["count"],
            )[:10],
            "top_sources": sorted(
                [{"ip": ip, "count": cnt} for ip, cnt in top_sources.items()],
                key=lambda x: -x["count"],
            )[:10],
            "timeline": buckets,
        },
        "responses": responses[:50],
        "model_performance": model_perf,
        "recommendations": recommendations,
    }


def _bucket_timeline_from_db(
    start: datetime, end: datetime, period: str
) -> List[Dict[str, Any]]:
    """按时间窗口对 ``alerts.timestamp`` 分桶计数（数据库聚合）。"""
    bucket_size_min = 60 if period == "day" else 60 * 24
    total_min = int((end - start).total_seconds() / 60)
    count = max(1, total_min // bucket_size_min)
    buckets: List[Dict[str, Any]] = []
    for i in range(count):
        b_start = start + timedelta(minutes=bucket_size_min * i)
        b_end = min(end, b_start + timedelta(minutes=bucket_size_min))
        b_start_u = b_start.astimezone(timezone.utc)
        b_end_u = b_end.astimezone(timezone.utc)
        n = (
            db.session.query(func.count(Alert.id))
            .filter(
                Alert.tenant_id == _current_tenant_id(),
                Alert.timestamp >= b_start_u,
                Alert.timestamp < b_end_u,
            )
            .scalar()
            or 0
        )
        buckets.append(
            {
                "start": b_start.isoformat(timespec="seconds"),
                "count": int(n),
            }
        )
    return buckets


def _collect_report_responses(
    start_u: datetime, end_u: datetime
) -> List[Dict[str, Any]]:
    """响应动作（``ResponseAction``）、周期内封禁、人工状态流转（``AlertHistory``）。"""
    out: List[Dict[str, Any]] = []

    for ra in (
        db.session.query(ResponseAction)
        .filter(
            ResponseAction.tenant_id == _current_tenant_id(),
            ResponseAction.created_at >= start_u,
            ResponseAction.created_at <= end_u,
        )
        .order_by(ResponseAction.created_at.desc())
        .limit(40)
        .all()
    ):
        meta = ra.meta if isinstance(ra.meta, dict) else {}
        out.append(
            {
                "timestamp": _dt_iso(ra.created_at),
                "action": ra.action_type,
                "target": ra.target or "",
                "reason": meta.get("reason") or ra.error or "",
                "operator": meta.get("operator"),
                "status": ra.status,
                "dry_run": ra.dry_run,
            }
        )

    for b in (
        db.session.query(BannedIp)
        .filter(
            BannedIp.tenant_id == _current_tenant_id(),
            BannedIp.created_at >= start_u,
            BannedIp.created_at <= end_u,
        )
        .all()
    ):
        out.append(
            {
                "timestamp": _dt_iso(b.created_at),
                "action": "ban_ip",
                "target": b.ip,
                "reason": b.reason,
                "operator": b.operator or "operator",
            }
        )

    rows = (
        db.session.query(AlertHistory, Alert)
        .join(Alert, AlertHistory.alert_id == Alert.id)
        .filter(
            AlertHistory.tenant_id == _current_tenant_id(),
            Alert.tenant_id == _current_tenant_id(),
            AlertHistory.created_at >= start_u,
            AlertHistory.created_at <= end_u,
            AlertHistory.to_status.in_(("acknowledged", "resolved", "ignored")),
        )
        .order_by(AlertHistory.created_at.desc())
        .limit(60)
        .all()
    )
    for h, al in rows:
        out.append(
            {
                "timestamp": _dt_iso(h.created_at),
                "action": f"mark_{h.to_status}",
                "target": al.source_ip or al.id,
                "alert_id": al.id,
                "alert_title": al.summary or "未分类告警",
                "reason": h.note or al.summary,
                "operator": h.operator or "operator",
            }
        )

    out.sort(
        key=lambda r: -(
            _parse_iso(r.get("timestamp")).timestamp()
            if _parse_iso(r.get("timestamp"))
            else 0
        )
    )
    return out


def _mean_resolution_latency_db(start_u: datetime, end_u: datetime) -> int:
    """已通过 DB 的 ``resolved`` 流转：告警创建 → 标记 resolved 的平均秒数。"""
    spans: List[float] = []
    q = (
        db.session.query(AlertHistory)
        .join(Alert, AlertHistory.alert_id == Alert.id)
        .filter(
            AlertHistory.tenant_id == _current_tenant_id(),
            AlertHistory.to_status == "resolved",
            AlertHistory.created_at >= start_u,
            AlertHistory.created_at <= end_u,
        )
        .limit(2000)
    )
    for h in q.all():
        al = h.alert
        if al is None or al.created_at is None or h.created_at is None:
            continue
        spans.append((h.created_at - al.created_at).total_seconds())
    if not spans:
        return 0
    return int(sum(spans) / len(spans))


def _build_recommendations(
    *,
    by_level: Dict[str, int],
    by_status: Dict[str, int],
    by_type: Dict[str, int],
    top_sources: Dict[str, int],
    total_alerts: int,
    enabled_rules: int,
    ioc_total: int,
    avg_confidence: float,
) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []
    if total_alerts == 0:
        recs.append(
            {
                "severity": "info",
                "title": "当前无告警",
                "body": "本报告周期未发现可见威胁。建议继续保持流量采样与规则覆盖度。",
            }
        )
        return recs

    if by_level.get("critical", 0) > 0:
        recs.append(
            {
                "severity": "critical",
                "title": f"{by_level['critical']} 起严重告警需立即响应",
                "body": "建议排查命中「多维度异常聚类」规则或严重级别样本的来源主机，必要时立即隔离。",
            }
        )
    if by_level.get("high", 0) >= 3:
        recs.append(
            {
                "severity": "high",
                "title": f"{by_level['high']} 起高危告警集中出现",
                "body": "优先处置 Top 3 攻击来源 IP，考虑加入威胁情报黑名单并同步到防火墙。",
            }
        )

    open_ratio = by_status.get("open", 0) / total_alerts if total_alerts else 0
    if open_ratio > 0.5:
        recs.append(
            {
                "severity": "medium",
                "title": f"超过 {int(open_ratio * 100)}% 告警未处置",
                "body": "建议安排值班人员统一确认未处置告警；可在 /alerts 页面按状态=未处理筛选快速处理。",
            }
        )

    if top_sources:
        topn = sorted(top_sources.items(), key=lambda kv: -kv[1])[:3]
        if any(cnt >= 3 for _, cnt in topn):
            ips = "、".join(f"{ip}({cnt})" for ip, cnt in topn)
            recs.append(
                {
                    "severity": "high",
                    "title": "高频攻击来源需封禁",
                    "body": f"近期命中最多的来源：{ips}。建议通过命令面板 `block <ip>` 或威胁情报页面添加 IOC。",
                }
            )

    if enabled_rules == 0 and total_alerts > 0:
        recs.append(
            {
                "severity": "high",
                "title": "所有检测规则已被禁用",
                "body": "规则管理页面中未启用任何规则，AI 模型可能缺乏前置特征过滤。请至少启用 signature 与 threshold 各一条。",
            }
        )
    elif enabled_rules < 3:
        recs.append(
            {
                "severity": "medium",
                "title": "规则覆盖度偏低",
                "body": f"当前仅启用 {enabled_rules} 条规则；建议至少覆盖特征匹配、阈值检测、异常聚类三种类型各一条。",
            }
        )

    if avg_confidence and avg_confidence < 0.6:
        recs.append(
            {
                "severity": "medium",
                "title": "模型平均置信度偏低",
                "body": f"本周期平均置信度 {avg_confidence:.2f}，建议结合最新流量重训或更新模型版本，避免低置信度告警淹没值班。",
            }
        )

    # 若 iocs 数量远低于告警量，说明情报利用不足
    if total_alerts >= 10 and ioc_total < 5:
        recs.append(
            {
                "severity": "low",
                "title": "威胁情报利用不足",
                "body": "告警数量较多但本地 IOC 条目偏少，建议在威胁情报页面批量导入近期被命中的来源 IP / 域名。",
            }
        )

    if not recs:
        recs.append(
            {
                "severity": "info",
                "title": "整体态势良好",
                "body": "当前报告周期内无明显高危迹象，继续保持。",
            }
        )
    return recs


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(name)s - %(levelname)s - %(message)s",
    )
    app, socketio = create_app()
    port = int(os.environ.get("PORT", "5000"))
    debug = bool(app.config.get("DEBUG", False))
    # DISABLE_RELOADER=true 在开发环境下仍可获得 debug pages，
    # 但避免 watchdog 多进程在 Windows 上与外部终端调度冲突。
    use_reloader = (
        debug and os.environ.get("DISABLE_RELOADER", "").lower() != "true"
    )
    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=debug,
        use_reloader=use_reloader,
        allow_unsafe_werkzeug=True,
    )

