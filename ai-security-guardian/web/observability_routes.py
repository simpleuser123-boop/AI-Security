"""Kubernetes 风格健康检查与 Prometheus 文本指标（不含密钥）。"""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from flask import Flask, Response, jsonify
from sqlalchemy import text

from src.observability.guardian_metrics import read_guardian_redis_snapshot
from src.utils.redis_client import RedisClient
from web.audit_integrity_patrol import get_last_audit_integrity_valid
from web.database import db

_DEFAULT_READY_TIMEOUT_SEC = 0.3
_DEFAULT_API_HEALTH_TIMEOUT_SEC = 0.2


def _redis_for_app(app: Flask) -> RedisClient:
    client = app.extensions.get("guardian_redis_client")
    if isinstance(client, RedisClient):
        return client

    cfg = app.extensions.get("guardian_os_config")
    if cfg is None:
        from config.config import get_config

        cfg = get_config()
    return RedisClient(
        host=getattr(cfg, "REDIS_HOST", "localhost"),
        port=int(getattr(cfg, "REDIS_PORT", 6379)),
        db=int(getattr(cfg, "REDIS_DB", 0)),
        password=str(getattr(cfg, "REDIS_PASSWORD", "") or ""),
    )
    app.extensions["guardian_redis_client"] = client
    return client


def _dependency_timeout(app: Flask, default: float) -> float:
    raw = (
        app.config.get("HEALTHCHECK_DEPENDENCY_TIMEOUT_SEC")
        or os.environ.get("HEALTHCHECK_DEPENDENCY_TIMEOUT_SEC")
        or default
    )
    try:
        timeout = float(raw)
    except (TypeError, ValueError):
        timeout = default
    return max(0.05, min(timeout, 2.0))


def _run_check(
    name: str,
    fn: Callable[[], Tuple[bool, str]],
    *,
    timeout_sec: float,
) -> Dict[str, Any]:
    started = time.perf_counter()
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"health-{name}")
    future = executor.submit(fn)
    try:
        ok, detail = future.result(timeout=timeout_sec)
        timed_out = False
    except TimeoutError:
        ok = False
        detail = f"{name}_timeout_after_{timeout_sec:.3f}s"
        timed_out = True
    except Exception as exc:  # noqa: BLE001
        ok = False
        detail = f"{name}_error: {type(exc).__name__}"
        timed_out = False
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    return {
        "ok": bool(ok),
        "detail": detail,
        "timed_out": timed_out,
        "latency_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def _default_secret_key() -> str:
    return "dev-only-insecure-key-never-use-in-production"


def _checks_database() -> Tuple[bool, str]:
    try:
        db.session.execute(text("SELECT 1"))
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        return False, f"db_error: {type(exc).__name__}"


def _checks_redis(client: RedisClient) -> Tuple[bool, str]:
    try:
        if client.mode != "redis" or not client.is_available:
            return False, f"redis_unavailable_{client.mode}"
        if client.ping():
            return True, "ok"
        return False, "redis_ping_failed"
    except Exception as exc:  # noqa: BLE001
        return False, f"redis_error: {type(exc).__name__}"


def _checks_config(app: Flask) -> Tuple[bool, str]:
    env = os.environ.get("FLASK_ENV", "development")
    sk = app.config.get("SECRET_KEY", "")
    if env == "production" and (not sk or sk == _default_secret_key()):
        return False, "insecure_or_missing_secret_key"
    if env == "production":
        if not (os.environ.get("ADMIN_PASSWORD_HASH") or "").strip():
            return False, "admin_password_hash_required"
        if not (os.environ.get("REDIS_PASSWORD") or "").strip():
            return False, "redis_password_required"
    return True, "ok"


def _checks_models(app: Flask, rds: RedisClient) -> Tuple[bool, str]:
    if app.config.get("TESTING") or os.environ.get("FLASK_ENV") == "testing":
        return True, "testing_skip_model_signal"

    snap = read_guardian_redis_snapshot(rds)
    updated = snap.get("updated_ts", 0.0)
    stale_sec = float(os.environ.get("GUARDIAN_METRICS_MAX_AGE_SEC", "180"))
    if updated and (time.time() - updated) <= stale_sec:
        if snap.get("model_ready", 0) > 0:
            return True, "guardian_model_signal_ok"
        return False, "guardian_reports_zero_models"

    md = app.config.get("MODEL_DIR", "models/saved")
    model_dir = Path(md)
    if not model_dir.is_absolute():
        model_dir = Path(app.root_path).parent / model_dir
    try:
        if model_dir.is_dir() and any(model_dir.iterdir()):
            return True, "model_dir_nonempty_no_guardian_heartbeat"
    except OSError:
        pass
    return False, "no_guardian_metrics_and_empty_model_dir"


def collect_health_checks(
    app: Flask,
    *,
    timeout_sec: Optional[float] = None,
    include_config: bool = True,
) -> Tuple[Dict[str, Any], List[str], List[str]]:
    timeout = timeout_sec or _dependency_timeout(app, _DEFAULT_READY_TIMEOUT_SEC)
    checks: Dict[str, Any] = {}
    fatal: List[str] = []
    degraded: List[str] = []
    testing = app.config.get("TESTING") or os.environ.get("FLASK_ENV") == "testing"

    def _db_probe() -> Tuple[bool, str]:
        with app.app_context():
            return _checks_database()

    checks["database"] = _run_check("database", _db_probe, timeout_sec=timeout)
    if not checks["database"]["ok"]:
        fatal.append("database")

    rds: Optional[RedisClient] = None

    def _redis_probe() -> Tuple[bool, str]:
        nonlocal rds
        rds = _redis_for_app(app)
        return _checks_redis(rds)

    redis_check = _run_check("redis", _redis_probe, timeout_sec=timeout)
    redis_check["mode"] = rds.mode if rds is not None else "unknown"
    checks["redis"] = redis_check
    if not redis_check["ok"]:
        if testing:
            degraded.append("redis")
        else:
            fatal.append("redis")

    if include_config:
        checks["config"] = _run_check(
            "config",
            lambda: _checks_config(app),
            timeout_sec=timeout,
        )
        if not checks["config"]["ok"]:
            fatal.append("config")

    def _models_probe() -> Tuple[bool, str]:
        model_rds = rds if rds is not None else _redis_for_app(app)
        return _checks_models(app, model_rds)

    checks["models"] = _run_check("models", _models_probe, timeout_sec=timeout)
    if not checks["models"]["ok"]:
        fatal.append("models")

    return checks, fatal, degraded


def build_api_health_payload(app: Flask) -> Dict[str, Any]:
    timeout = _dependency_timeout(app, _DEFAULT_API_HEALTH_TIMEOUT_SEC)
    checks, fatal, degraded = collect_health_checks(
        app,
        timeout_sec=timeout,
        include_config=False,
    )
    unhealthy = sorted(set(fatal + degraded))
    return {
        "status": "healthy" if not unhealthy else "degraded",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "checks": checks,
        "degraded": unhealthy,
    }


def register_observability_routes(app: Flask, limiter: Any) -> None:
    """注册 /healthz、/readyz、/metrics（匿名、不限流）。"""

    @app.route("/healthz")
    @limiter.exempt
    def healthz():  # type: ignore[unused-function]
        return jsonify({"status": "live", "component": "ai-security-guardian-web"}), 200

    @app.route("/readyz")
    @limiter.exempt
    def readyz():  # type: ignore[unused-function]
        checks, fatal, degraded = collect_health_checks(app)

        if fatal:
            return (
                jsonify(
                    {
                        "status": "unready",
                        "checks": checks,
                        "fatal": fatal,
                        "degraded": degraded,
                    }
                ),
                503,
            )

        status = "ready" if not degraded else "degraded"
        return jsonify({"status": status, "checks": checks, "degraded": degraded}), 200

    @app.route("/metrics")
    @limiter.exempt
    def metrics():  # type: ignore[unused-function]
        lines: List[str] = []
        rds = _redis_for_app(app)
        snap = read_guardian_redis_snapshot(rds)

        def _num(key: str, default: float = 0.0) -> float:
            return float(snap.get(key, default))

        packets = int(_num("packets_total"))
        dropped = int(_num("packets_dropped_total"))
        lat_sum = _num("detection_latency_sum_ms")
        lat_cnt = int(_num("detection_latency_count"))
        alerts = int(_num("alerts_total"))
        model_ready = int(_num("model_ready"))

        stream_key = os.environ.get("GUARDIAN_ALERT_STREAM", "guardian:alerts")
        group = os.environ.get("GUARDIAN_ALERT_STREAM_GROUP", "guardian:web")
        stream_len = 0
        pending = 0
        group_count = 0
        group_lag = 0
        try:
            stream_len = int(rds.stream_len(stream_key))
            pending = int(rds.stream_pending(stream_key, group))
            groups = rds.stream_info_groups(stream_key)
            group_count = len(groups)
            for item in groups:
                if str(item.get("name")) == group:
                    group_lag = int(item.get("lag") or 0)
                    pending = int(item.get("pending") or pending)
                    break
        except Exception:  # noqa: BLE001
            stream_len = 0
            pending = 0
            group_count = 0
            group_lag = 0

        audit_ok = 1 if get_last_audit_integrity_valid() else 0

        mean_lat = (lat_sum / lat_cnt) if lat_cnt > 0 else 0.0

        lines.append("# HELP guardian_packets_total Packets seen by Guardian pipeline.")
        lines.append("# TYPE guardian_packets_total counter")
        lines.append(f"guardian_packets_total {packets}")
        lines.append("# HELP guardian_packets_dropped_total Dropped or discarded packets (TI filter, queue errors, aggregator discards).")
        lines.append("# TYPE guardian_packets_dropped_total counter")
        lines.append(f"guardian_packets_dropped_total {dropped}")
        lines.append("# HELP guardian_detection_latency_ms_sum Sum of detection+fusion latency in milliseconds.")
        lines.append("# TYPE guardian_detection_latency_ms_sum counter")
        lines.append(f"guardian_detection_latency_ms_sum {lat_sum}")
        lines.append("# HELP guardian_detection_latency_ms_count Detection+fusion latency samples.")
        lines.append("# TYPE guardian_detection_latency_ms_count counter")
        lines.append(f"guardian_detection_latency_ms_count {lat_cnt}")
        lines.append("# HELP guardian_detection_latency_ms Mean detection+fusion latency in milliseconds (derived).")
        lines.append("# TYPE guardian_detection_latency_ms gauge")
        lines.append(f"guardian_detection_latency_ms {mean_lat}")
        lines.append("# HELP guardian_alerts_total Threat alerts emitted by Guardian.")
        lines.append("# TYPE guardian_alerts_total counter")
        lines.append(f"guardian_alerts_total {alerts}")
        lines.append("# HELP guardian_model_ready Count of detection engines reporting ready (from Guardian heartbeat).")
        lines.append("# TYPE guardian_model_ready gauge")
        lines.append(f"guardian_model_ready {model_ready}")
        lines.append("# HELP redis_stream_pending Pending entries in Redis alert stream consumer group.")
        lines.append("# TYPE redis_stream_pending gauge")
        lines.append(f"redis_stream_pending {pending}")
        lines.append("# HELP redis_stream_length Entries currently retained in Redis alert stream.")
        lines.append("# TYPE redis_stream_length gauge")
        lines.append(f"redis_stream_length {stream_len}")
        lines.append("# HELP redis_stream_group_lag Redis-reported lag for the configured alert consumer group.")
        lines.append("# TYPE redis_stream_group_lag gauge")
        lines.append(f"redis_stream_group_lag {group_lag}")
        lines.append("# HELP redis_stream_groups Consumer group count for the alert stream.")
        lines.append("# TYPE redis_stream_groups gauge")
        lines.append(f"redis_stream_groups {group_count}")
        lines.append("# HELP audit_integrity_valid 1 if last audit hash-chain patrol succeeded.")
        lines.append("# TYPE audit_integrity_valid gauge")
        lines.append(f"audit_integrity_valid {audit_ok}")

        body = "\n".join(lines) + "\n"
        return Response(body, mimetype="text/plain; version=0.0.4; charset=utf-8")
