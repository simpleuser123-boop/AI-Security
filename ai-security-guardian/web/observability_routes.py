"""Kubernetes 风格健康检查与 Prometheus 文本指标（不含密钥）。"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from flask import Flask, Response, g, jsonify, request
from sqlalchemy import func, text

from src.observability.guardian_metrics import read_guardian_redis_snapshot
from src.utils.redis_client import RedisClient
from web.audit_integrity_patrol import get_last_audit_integrity_valid
from web.database import db
from web.models import ResponseAction

_DEFAULT_READY_TIMEOUT_SEC = 0.3
_DEFAULT_API_HEALTH_TIMEOUT_SEC = 0.2
_HTTP_DURATION_BUCKETS: Tuple[float, ...] = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.2,
    0.3,
    0.5,
    1.0,
    2.5,
    5.0,
)


class WebRequestMetrics:
    """Process-local HTTP RED metrics for Prometheus scraping."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._count: Dict[Tuple[str, str, str], int] = defaultdict(int)
        self._sum: Dict[Tuple[str, str, str], float] = defaultdict(float)
        self._buckets: Dict[Tuple[str, str, str], List[int]] = defaultdict(
            lambda: [0 for _ in _HTTP_DURATION_BUCKETS]
        )

    def observe(self, *, method: str, route: str, status_class: str, seconds: float) -> None:
        value = max(0.0, float(seconds))
        key = (method.upper(), route, status_class)
        with self._lock:
            self._count[key] += 1
            self._sum[key] += value
            buckets = self._buckets[key]
            for idx, bound in enumerate(_HTTP_DURATION_BUCKETS):
                if value <= bound:
                    buckets[idx] += 1

    def render_prometheus(self) -> List[str]:
        with self._lock:
            rows = [
                (key, self._count[key], self._sum[key], list(self._buckets[key]))
                for key in sorted(self._count)
            ]

        lines: List[str] = [
            "# HELP guardian_http_requests_total Web/API requests served by the Flask process.",
            "# TYPE guardian_http_requests_total counter",
        ]
        for (method, route, status_class), count, _total, _buckets in rows:
            lines.append(
                'guardian_http_requests_total{method="%s",route="%s",status_class="%s"} %d'
                % (_label(method), _label(route), _label(status_class), count)
            )

        lines.extend(
            [
                "# HELP guardian_http_request_duration_seconds Web/API request latency histogram.",
                "# TYPE guardian_http_request_duration_seconds histogram",
            ]
        )
        for (method, route, status_class), count, total, buckets in rows:
            base = (
                'method="%s",route="%s",status_class="%s"'
                % (_label(method), _label(route), _label(status_class))
            )
            for idx, bound in enumerate(_HTTP_DURATION_BUCKETS):
                lines.append(
                    'guardian_http_request_duration_seconds_bucket{%s,le="%s"} %d'
                    % (base, _format_bucket(bound), buckets[idx])
                )
            lines.append(
                'guardian_http_request_duration_seconds_bucket{%s,le="+Inf"} %d'
                % (base, count)
            )
            lines.append(
                "guardian_http_request_duration_seconds_sum{%s} %.6f" % (base, total)
            )
            lines.append(
                "guardian_http_request_duration_seconds_count{%s} %d" % (base, count)
            )
        return lines


def _label(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _format_bucket(value: float) -> str:
    return ("%g" % value)


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
        if int(snap.get("model_ready", 0)) == 1:
            return True, "guardian_model_signal_ok"
        expected = int(snap.get("model_expected_count", 0))
        loaded = int(snap.get("model_loaded_count", 0))
        if expected > 0 and loaded > 0:
            return False, f"guardian_reports_partial_models_loaded_{loaded}_of_{expected}"
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
    request_metrics = app.extensions.get("guardian_web_request_metrics")
    if not isinstance(request_metrics, WebRequestMetrics):
        request_metrics = WebRequestMetrics()
        app.extensions["guardian_web_request_metrics"] = request_metrics

    @app.before_request
    def _observe_request_started():  # type: ignore[unused-function]
        g.guardian_request_started_at = time.perf_counter()

    @app.after_request
    def _observe_request_finished(response):  # type: ignore[unused-function]
        if getattr(g, "guardian_request_metrics_observed", False):
            return response
        started = getattr(g, "guardian_request_started_at", None)
        if started is None:
            return response
        rule = request.url_rule.rule if request.url_rule is not None else request.path
        status_class = f"{int(response.status_code / 100)}xx"
        request_metrics.observe(
            method=request.method,
            route=rule,
            status_class=status_class,
            seconds=time.perf_counter() - float(started),
        )
        return response

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
        started = getattr(g, "guardian_request_started_at", None)
        if started is not None:
            request_metrics.observe(
                method=request.method,
                route="/metrics",
                status_class="2xx",
                seconds=time.perf_counter() - float(started),
            )
            g.guardian_request_metrics_observed = True
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
        model_expected = int(_num("model_expected_count"))
        model_loaded = int(_num("model_loaded_count"))
        model_missing = int(_num("model_missing_count"))
        model_status_updated_ts = _num("model_status_updated_ts")
        redis_writes_ok = int(_num("redis_stream_writes_ok"))
        redis_writes_fail = int(_num("redis_stream_writes_fail"))
        last_detection_ts = _num("last_detection_ts")
        snapshot_updated_ts = _num("updated_ts")

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

        consumer_stats = app.extensions.get("guardian_alert_consumer_stats") or {}
        consumed_total = int(float(consumer_stats.get("consumed_total", 0) or 0))
        consume_failed_total = int(float(consumer_stats.get("failed_total", 0) or 0))
        consume_latency_sum_ms = float(consumer_stats.get("latency_sum_ms", 0.0) or 0.0)
        consume_latency_count = int(float(consumer_stats.get("latency_count", 0) or 0))
        consume_latency_max_ms = float(consumer_stats.get("latency_max_ms", 0.0) or 0.0)
        last_consumed_ts = float(consumer_stats.get("last_consumed_ts", 0.0) or 0.0)

        audit_ok = 1 if get_last_audit_integrity_valid() else 0
        audit_stats = app.extensions.get("audit_integrity_patrol_stats") or {}
        audit_patrol_total = int(float(audit_stats.get("runs_total", 0) or 0))
        audit_patrol_failed = int(float(audit_stats.get("failed_total", 0) or 0))
        audit_last_run_ts = float(audit_stats.get("last_run_ts", 0.0) or 0.0)
        audit_last_success_ts = float(audit_stats.get("last_success_ts", 0.0) or 0.0)

        action_counts = _collect_response_action_status_counts()

        mean_lat = (lat_sum / lat_cnt) if lat_cnt > 0 else 0.0
        model_state_ready = 1 if model_ready == 1 else 0
        model_state_partial = (
            1 if model_expected > 0 and model_loaded > 0 and model_ready == 0 else 0
        )
        model_state_missing = (
            1 if model_ready == 0 and model_state_partial == 0 else 0
        )

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
        lines.append("# HELP guardian_model_ready 1 when all critical Guardian models are ready, otherwise 0.")
        lines.append("# TYPE guardian_model_ready gauge")
        lines.append(f"guardian_model_ready {model_ready}")
        lines.append("# HELP guardian_model_expected Critical Guardian model count expected by the full-chain process.")
        lines.append("# TYPE guardian_model_expected gauge")
        lines.append(f"guardian_model_expected {model_expected}")
        lines.append("# HELP guardian_model_loaded Critical Guardian model count loaded by the full-chain process.")
        lines.append("# TYPE guardian_model_loaded gauge")
        lines.append(f"guardian_model_loaded {model_loaded}")
        lines.append("# HELP guardian_model_missing Critical Guardian model count missing or failed to load.")
        lines.append("# TYPE guardian_model_missing gauge")
        lines.append(f"guardian_model_missing {model_missing}")
        lines.append("# HELP guardian_model_state Guardian model load state as one-hot gauges.")
        lines.append("# TYPE guardian_model_state gauge")
        lines.append(f'guardian_model_state{{state="ready"}} {model_state_ready}')
        lines.append(f'guardian_model_state{{state="partial"}} {model_state_partial}')
        lines.append(f'guardian_model_state{{state="missing"}} {model_state_missing}')
        lines.append("# HELP guardian_model_status_updated_timestamp_seconds Last model readiness update timestamp.")
        lines.append("# TYPE guardian_model_status_updated_timestamp_seconds gauge")
        lines.append(
            f"guardian_model_status_updated_timestamp_seconds {model_status_updated_ts}"
        )
        lines.append("# HELP guardian_metrics_snapshot_updated_timestamp_seconds Last Guardian metrics heartbeat timestamp.")
        lines.append("# TYPE guardian_metrics_snapshot_updated_timestamp_seconds gauge")
        lines.append(f"guardian_metrics_snapshot_updated_timestamp_seconds {snapshot_updated_ts}")
        lines.append("# HELP guardian_last_detection_timestamp_seconds Last non-normal detection timestamp.")
        lines.append("# TYPE guardian_last_detection_timestamp_seconds gauge")
        lines.append(f"guardian_last_detection_timestamp_seconds {last_detection_ts}")
        lines.append("# HELP guardian_redis_stream_writes_total Alert stream write attempts by result.")
        lines.append("# TYPE guardian_redis_stream_writes_total counter")
        lines.append(f'guardian_redis_stream_writes_total{{result="ok"}} {redis_writes_ok}')
        lines.append(f'guardian_redis_stream_writes_total{{result="failed"}} {redis_writes_fail}')
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
        lines.append("# HELP guardian_alert_stream_consumed_total Alert stream messages persisted and acked by Web consumer.")
        lines.append("# TYPE guardian_alert_stream_consumed_total counter")
        lines.append(f"guardian_alert_stream_consumed_total {consumed_total}")
        lines.append("# HELP guardian_alert_stream_consume_failures_total Alert stream messages that failed before ack.")
        lines.append("# TYPE guardian_alert_stream_consume_failures_total counter")
        lines.append(f"guardian_alert_stream_consume_failures_total {consume_failed_total}")
        lines.append("# HELP guardian_alert_consume_latency_ms_sum Sum of alert stream production-to-consumption latency in milliseconds.")
        lines.append("# TYPE guardian_alert_consume_latency_ms_sum counter")
        lines.append(f"guardian_alert_consume_latency_ms_sum {consume_latency_sum_ms}")
        lines.append("# HELP guardian_alert_consume_latency_ms_count Alert consume latency samples.")
        lines.append("# TYPE guardian_alert_consume_latency_ms_count counter")
        lines.append(f"guardian_alert_consume_latency_ms_count {consume_latency_count}")
        lines.append("# HELP guardian_alert_consume_latency_ms_max Maximum observed alert consume latency in this process.")
        lines.append("# TYPE guardian_alert_consume_latency_ms_max gauge")
        lines.append(f"guardian_alert_consume_latency_ms_max {consume_latency_max_ms}")
        lines.append("# HELP guardian_alert_stream_last_consumed_timestamp_seconds Last successfully consumed alert stream timestamp.")
        lines.append("# TYPE guardian_alert_stream_last_consumed_timestamp_seconds gauge")
        lines.append(f"guardian_alert_stream_last_consumed_timestamp_seconds {last_consumed_ts}")
        lines.append("# HELP audit_integrity_valid 1 if last audit hash-chain patrol succeeded.")
        lines.append("# TYPE audit_integrity_valid gauge")
        lines.append(f"audit_integrity_valid {audit_ok}")
        lines.append("# HELP audit_integrity_patrol_runs_total Audit hash-chain patrol runs by result.")
        lines.append("# TYPE audit_integrity_patrol_runs_total counter")
        lines.append(f'audit_integrity_patrol_runs_total{{result="ok"}} {max(0, audit_patrol_total - audit_patrol_failed)}')
        lines.append(f'audit_integrity_patrol_runs_total{{result="failed"}} {audit_patrol_failed}')
        lines.append("# HELP audit_integrity_last_run_timestamp_seconds Last audit patrol run timestamp.")
        lines.append("# TYPE audit_integrity_last_run_timestamp_seconds gauge")
        lines.append(f"audit_integrity_last_run_timestamp_seconds {audit_last_run_ts}")
        lines.append("# HELP audit_integrity_last_success_timestamp_seconds Last successful audit patrol timestamp.")
        lines.append("# TYPE audit_integrity_last_success_timestamp_seconds gauge")
        lines.append(f"audit_integrity_last_success_timestamp_seconds {audit_last_success_ts}")
        lines.append("# HELP guardian_response_actions_total Response actions by type and status from the database.")
        lines.append("# TYPE guardian_response_actions_total gauge")
        for (action_type, status), count in action_counts.items():
            lines.append(
                'guardian_response_actions_total{action_type="%s",status="%s"} %d'
                % (_label(action_type), _label(status), count)
            )
        lines.extend(request_metrics.render_prometheus())

        body = "\n".join(lines) + "\n"
        return Response(body, mimetype="text/plain; version=0.0.4; charset=utf-8")


def _collect_response_action_status_counts() -> Dict[Tuple[str, str], int]:
    counts: Dict[Tuple[str, str], int] = {}
    try:
        rows = (
            db.session.query(
                ResponseAction.action_type,
                ResponseAction.status,
                func.count(ResponseAction.id),
            )
            .group_by(ResponseAction.action_type, ResponseAction.status)
            .all()
        )
        for action_type, status, count in rows:
            counts[(str(action_type or "unknown"), str(status or "unknown"))] = int(count)
    except Exception:  # noqa: BLE001
        try:
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
    return counts
