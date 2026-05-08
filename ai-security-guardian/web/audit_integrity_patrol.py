"""审计日志哈希链完整性巡检：失败时 critical 告警并写入审计。"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

_last_audit_integrity_valid: bool = True
_last_patrol_monotonic: float = 0.0
_last_critical_alert_monotonic: float = 0.0
_patrol_lock = threading.Lock()
_CRITICAL_ALERT_COOLDOWN_SEC: float = 300.0


def get_last_audit_integrity_valid() -> bool:
    return _last_audit_integrity_valid


def run_audit_integrity_patrol_once(app: Any) -> dict:
    """执行一次校验；须在 app.app_context() 内调用（由本模块包装）。"""
    global _last_audit_integrity_valid, _last_critical_alert_monotonic
    from src.audit.security_logger import SecurityLogger
    from web.database import db
    from web.models import Alert, AlertHistory

    log_dir = app.config.get("GUARDIAN_LOG_DIR", "logs")
    integrity_on = bool(app.config.get("LOG_INTEGRITY_ENABLED", True))
    sl = SecurityLogger(log_dir=log_dir, enable_integrity=integrity_on)
    try:
        result = sl.verify_integrity()
    except Exception:
        sl.close()
        raise
    valid = bool(result.get("valid"))
    _last_audit_integrity_valid = valid
    _record_patrol_stats(app, valid)

    if valid:
        sl.close()
        return result

    now_m = time.monotonic()
    invalid_lines = result.get("invalid_lines") or []
    preview = invalid_lines[:8]
    summary = f"invalid_lines={len(invalid_lines)} preview={preview!r}"

    try:
        sl.log_event(
            event_type="audit_integrity",
            level="critical",
            details={
                "message": "security.log 哈希链校验失败",
                "total_lines": result.get("total_lines"),
                "invalid_preview": preview,
                "invalid_count": len(invalid_lines),
            },
            source_ip="",
            confidence=1.0,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("[AuditPatrol] 写入审计失败: %s", exc)
    finally:
        sl.close()

    # 测试环境下禁用冷却，避免跨用例共享模块全局状态导致漏写告警。
    testing = bool(app.config.get("TESTING", False))
    if (not testing) and (
        now_m - _last_critical_alert_monotonic < _CRITICAL_ALERT_COOLDOWN_SEC
    ):
        return result
    _last_critical_alert_monotonic = now_m

    def _persist_critical_alert() -> None:
        aid = uuid.uuid4().hex
        ts_ms = int(time.time() * 1000)
        alert = Alert(
            id=aid,
            # 避免同秒多次巡检触发 UNIQUE 冲突（external_id 全局唯一）
            external_id=f"audit-integrity-{ts_ms}-{aid[:8]}",
            timestamp=datetime.now(timezone.utc),
            source_ip="127.0.0.1",
            threat_type="audit_integrity",
            level="critical",
            confidence=1.0,
            engine="audit-patrol",
            status="open",
            summary="审计日志哈希链完整性校验失败",
            raw_payload=None,
        )
        db.session.add(alert)
        db.session.add(
            AlertHistory(
                alert_id=aid,
                from_status=None,
                to_status="open",
                operator="system",
                note=summary[:2000],
            )
        )
        db.session.commit()

    try:
        from flask import has_app_context

        if has_app_context():
            _persist_critical_alert()
        else:
            with app.app_context():
                _persist_critical_alert()
    except Exception as exc:  # noqa: BLE001
        logger.error("[AuditPatrol] 写入告警表失败: %s", exc)

    return result


def _record_patrol_stats(app: Any, valid: bool) -> None:
    now = time.time()
    stats = dict(app.extensions.get("audit_integrity_patrol_stats") or {})
    stats["runs_total"] = int(stats.get("runs_total", 0) or 0) + 1
    stats["last_run_ts"] = now
    if valid:
        stats["last_success_ts"] = now
    else:
        stats["failed_total"] = int(stats.get("failed_total", 0) or 0) + 1
    stats.setdefault("failed_total", 0)
    stats.setdefault("last_success_ts", 0.0)
    app.extensions["audit_integrity_patrol_stats"] = stats


def _patrol_loop(app: Any, interval_sec: float, stop_event: threading.Event) -> None:
    interval_sec = max(5.0, interval_sec)
    while not stop_event.is_set():
        try:
            with app.app_context():
                run_audit_integrity_patrol_once(app)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[AuditPatrol] 巡检异常: %s", exc)
        if stop_event.wait(timeout=interval_sec):
            break


def start_audit_integrity_patrol(app: Any) -> Optional[threading.Thread]:
    """启动后台巡检线程；测试环境可通过环境变量关闭。"""
    import os

    if os.environ.get("AUDIT_INTEGRITY_PATROL", "true").lower() != "true":
        return None
    # pytest 进程退出阶段会先关闭 stderr/stdout，再清理后台线程。
    # 默认在测试中不启巡检，避免 logging StreamHandler 对 closed file 写入。
    if os.environ.get("PYTEST_CURRENT_TEST") and (
        os.environ.get("AUDIT_INTEGRITY_PATROL_IN_TESTS", "false").lower() != "true"
    ):
        return None
    try:
        interval = float(os.environ.get("AUDIT_INTEGRITY_INTERVAL_SEC", "60"))
    except ValueError:
        interval = 60.0
    interval = max(15.0, interval)

    stop_event = threading.Event()
    app.extensions["audit_integrity_patrol_stop"] = stop_event

    t = threading.Thread(
        target=_patrol_loop,
        args=(app, interval, stop_event),
        name="audit-integrity-patrol",
        daemon=True,
    )
    app.extensions["audit_integrity_patrol_thread"] = t
    t.start()
    return t


def stop_audit_integrity_patrol(app: Any, join_timeout_sec: float = 2.0) -> None:
    """停止后台巡检线程，避免进程退出后后台线程继续写日志。"""
    stop_event = app.extensions.get("audit_integrity_patrol_stop")
    t = app.extensions.get("audit_integrity_patrol_thread")
    if stop_event is None:
        return
    try:
        stop_event.set()
    except Exception:  # noqa: BLE001
        return
    if isinstance(t, threading.Thread) and t.is_alive():
        t.join(timeout=max(0.1, float(join_timeout_sec)))
