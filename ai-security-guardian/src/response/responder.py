"""
防护响应引擎（R4：通知、FirewallManager、调度、持久化与审计）。
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from src.detectors.base import DetectionResult
from src.response.firewall import FirewallManager, firewall_manager_from_env
from src.response.host_isolation import (
    HostIsolationProvider,
    NullHostIsolationProvider,
    host_isolation_from_env,
)
from src.response.ip_policy import check_real_ban_eligibility
from src.response.ip_validate import validate_ip
from src.response.notifier import AlertNotifier
from src.response.persistence import ResponsePersistence, create_response_persistence_from_env
from src.response.scheduler import ResponseScheduler

logger = logging.getLogger(__name__)

_HIGH_BAN_DURATION = timedelta(hours=1)
_CRITICAL_BAN_DURATION = timedelta(days=1)
_SYSTEM_OPERATOR = "security_responder"
_DETECTION_TRIGGER = "detection"
_SCHEDULER_TRIGGER = "scheduler"
_MANUAL_TRIGGER = "manual"

RESPONSE_STRATEGY = {
    "low": "audit_only",
    "medium": "audit_and_notify",
    "high": "audit_notify_temporary_ban",
    "critical": "audit_notify_temporary_ban_and_isolation",
}


class SecurityResponder:
    """分级响应：high/critical 走可审计、可回滚、可降级路径。"""

    def __init__(
        self,
        dry_run: bool = True,
        *,
        firewall: Optional[FirewallManager] = None,
        notifier: Optional[AlertNotifier] = None,
        isolation: Optional[HostIsolationProvider] = None,
        persistence: Optional[ResponsePersistence] = None,
        scheduler: Optional[ResponseScheduler] = None,
        security_logger: Optional[Any] = None,
        alert_id_from_result: Optional[Callable[[DetectionResult], Optional[str]]] = None,
    ) -> None:
        self.dry_run = dry_run
        self._firewall = firewall or firewall_manager_from_env()
        self._notifier = notifier if notifier is not None else AlertNotifier.from_env()
        self._isolation = isolation if isolation is not None else host_isolation_from_env()
        self._persistence = persistence or create_response_persistence_from_env()
        self._scheduler = scheduler or ResponseScheduler(self._persistence)
        self._security_logger = security_logger
        self._alert_id_from_result = alert_id_from_result

        self._banned_ips: Dict[str, datetime] = {}
        self._response_actions: List[Dict[str, Any]] = []

    @property
    def scheduler(self) -> ResponseScheduler:
        return self._scheduler

    @property
    def response_actions(self) -> List[Dict[str, Any]]:
        return list(self._response_actions)

    def _alert_id(self, result: DetectionResult) -> Optional[str]:
        if self._alert_id_from_result:
            return self._alert_id_from_result(result)
        raw = result.raw_data or {}
        if isinstance(raw, dict):
            aid = raw.get("alert_id")
            if isinstance(aid, str) and aid.strip():
                return aid.strip()
        return None

    def _append_memory_action(self, action: Dict[str, Any]) -> None:
        row = dict(action)
        row.setdefault("recorded_at", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        row.setdefault("status", "pending")
        row.setdefault("reason", "")
        row.setdefault("operator", _SYSTEM_OPERATOR)
        row.setdefault("trigger_source", _DETECTION_TRIGGER)
        self._response_actions.append(row)

    def _persist_action(
        self,
        *,
        alert_id: Optional[str],
        action_type: str,
        target: Optional[str],
        status: str,
        dry_run: bool,
        error: Optional[str] = None,
        scheduled_unblock_at: Optional[datetime] = None,
        meta: Optional[Dict[str, Any]] = None,
        reason: str = "",
        operator: str = _SYSTEM_OPERATOR,
        trigger_source: str = _DETECTION_TRIGGER,
    ) -> int:
        persisted_meta = dict(meta or {})
        persisted_meta.setdefault("reason", reason)
        persisted_meta.setdefault("operator", operator)
        persisted_meta.setdefault("trigger_source", trigger_source)
        rid = self._persistence.save_response_action(
            alert_id=alert_id,
            action_type=action_type,
            target=target,
            status=status,
            dry_run=dry_run,
            error=error,
            scheduled_unblock_at=scheduled_unblock_at,
            meta=persisted_meta,
            reason=reason,
            operator=operator,
            trigger_source=trigger_source,
        )
        self._persistence.append_audit_db_event(
            event_type=f"response_{action_type}_{status}",
            resource_id=alert_id,
            actor=operator,
            ip_address=target if validate_ip(target) else None,
            payload={
                "action_type": action_type,
                "target": target,
                "status": status,
                "dry_run": dry_run,
                "reason": reason,
                "trigger_source": trigger_source,
                "error": error,
                "meta": persisted_meta,
            },
        )
        return rid

    def _audit(
        self,
        action: str,
        target: str,
        result: str,
        *,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        if self._security_logger is None:
            return
        try:
            msg = result
            if extra:
                msg = f"{result}|{extra!r}"
            self._security_logger.log_response(action, target, msg[:2000])
        except Exception as exc:  # noqa: BLE001
            logger.error("[响应] 审计日志写入失败: %s", exc)

    def respond(self, result: DetectionResult) -> None:
        if result.threat_type == "normal":
            return

        level = (result.threat_level or "").lower()
        logger.warning(
            "[响应] %s - %s (置信度: %s)",
            level.upper(),
            result.details,
            result.confidence,
        )

        if level == "low":
            self._log_only(result)
        elif level == "medium":
            self._log_only(result)
            self._notify(result, subject_prefix="[MEDIUM]")
        elif level == "high":
            self._log_only(result)
            self._notify(result, subject_prefix="[HIGH]")
            self._ban_for_level(result, duration=_HIGH_BAN_DURATION, level_label="high")
        elif level == "critical":
            self._log_only(result)
            self._notify(result, subject_prefix="[CRITICAL]")
            self._ban_for_level(result, duration=_CRITICAL_BAN_DURATION, level_label="critical")
            self._isolate_for_critical(result)
        else:
            logger.warning("[响应] 未知威胁等级: %r，按 low 处理", level)
            self._log_only(result)

    def _log_only(self, result: DetectionResult) -> None:
        logger.info(
            "[安全事件] type=%s level=%s ip=%s confidence=%s detail=%s",
            result.threat_type,
            result.threat_level,
            result.source_ip,
            result.confidence,
            result.details,
        )
        reason = f"{(result.threat_level or 'unknown').lower()}_audit_only"
        self._append_memory_action(
            {
                "action": "audit_event",
                "source_ip": result.source_ip,
                "dry_run": self.dry_run,
                "status": "applied",
                "reason": reason,
                "strategy": RESPONSE_STRATEGY.get(
                    (result.threat_level or "").lower(), RESPONSE_STRATEGY["low"]
                ),
            }
        )
        self._persist_action(
            alert_id=self._alert_id(result),
            action_type="audit_event",
            target=result.source_ip,
            status="applied",
            dry_run=self.dry_run,
            reason=reason,
            meta={
                "threat_type": result.threat_type,
                "threat_level": result.threat_level,
                "confidence": float(result.confidence),
                "details": result.details,
            },
        )

    def _notify(self, result: DetectionResult, *, subject_prefix: str) -> None:
        subject = f"{subject_prefix} {result.threat_type} / {result.threat_level}"
        body = (
            f"threat_type={result.threat_type}\n"
            f"level={result.threat_level}\n"
            f"source_ip={result.source_ip}\n"
            f"confidence={result.confidence}\n"
            f"details={result.details}\n"
        )
        meta = {
            "threat_type": result.threat_type,
            "threat_level": result.threat_level,
            "confidence": float(result.confidence),
        }
        attempts = self._notifier.notify_all(subject, body, meta=meta)
        aid = self._alert_id(result)
        any_ok = any(a.ok for a in attempts)
        dry = self.dry_run
        if any_ok:
            self._append_memory_action(
                {
                    "action": "notify",
                    "source_ip": result.source_ip,
                    "dry_run": dry,
                    "status": "applied",
                    "reason": "notification_sent",
                    "channels": [a.channel for a in attempts if a.ok],
                }
            )
            pid = self._persist_action(
                alert_id=aid,
                action_type="notify",
                target=result.source_ip,
                status="applied",
                dry_run=dry,
                reason="notification_sent",
                meta={"attempts": [{"c": x.channel, "ok": x.ok, "d": x.detail} for x in attempts]},
            )
            _ = pid
            self._audit("notify", result.source_ip or "", "ok", extra={"attempts": len(attempts)})
        else:
            self._append_memory_action(
                {
                    "action": "notify",
                    "source_ip": result.source_ip,
                    "dry_run": dry,
                    "status": "failed",
                    "reason": "all_notification_channels_failed",
                    "channels": [
                        {"channel": a.channel, "ok": a.ok, "detail": a.detail} for a in attempts
                    ],
                }
            )
            self._persist_action(
                alert_id=aid,
                action_type="notify",
                target=result.source_ip,
                status="failed",
                dry_run=dry,
                error=";".join(f"{a.channel}:{a.detail}" for a in attempts[-3:]),
                reason="all_notification_channels_failed",
                meta={"attempts": [{"c": x.channel, "ok": x.ok, "d": x.detail} for x in attempts]},
            )
            self._audit(
                "notify",
                result.source_ip or "",
                "failed",
                extra={"last": attempts[-1].detail if attempts else ""},
            )
            self._persistence.append_audit_db_event(
                event_type="notify_failed",
                resource_id=aid,
                actor=_SYSTEM_OPERATOR,
                ip_address=result.source_ip if validate_ip(result.source_ip) else None,
                payload={"detail": [a.detail for a in attempts]},
            )
            self._scheduler.schedule_notify_retry(
                run_at=datetime.now(timezone.utc) + timedelta(seconds=15),
                alert_id=aid,
                subject=subject,
                body=body,
                meta=meta,
            )

    def _ban_for_level(
        self,
        result: DetectionResult,
        *,
        duration: timedelta,
        level_label: str,
        operator: str = _SYSTEM_OPERATOR,
        trigger_source: str = _DETECTION_TRIGGER,
        reason_override: Optional[str] = None,
    ) -> None:
        ip = result.source_ip if isinstance(result.source_ip, str) else ""
        aid = self._alert_id(result)
        if not validate_ip(ip):
            skip_reason = (
                "missing_source_ip"
                if not (isinstance(ip, str) and ip.strip())
                else "invalid_ipv4_format"
            )
            logger.warning(
                "[响应][降级] 无法自动封禁：%s (%r)。",
                skip_reason,
                ip,
            )
            self._append_memory_action(
                {
                    "action": "ban_ip",
                    "source_ip": ip.strip() if isinstance(ip, str) else "",
                    "dry_run": self.dry_run,
                    "status": "skipped",
                    "reason": skip_reason,
                    "operator": operator,
                    "trigger_source": trigger_source,
                }
            )
            self._persist_action(
                alert_id=aid,
                action_type="ban_ip",
                target=ip,
                status="skipped",
                dry_run=self.dry_run,
                error=skip_reason,
                reason=skip_reason,
                operator=operator,
                trigger_source=trigger_source,
                meta={"level": level_label},
            )
            self._audit("ban_ip", ip, f"skipped:{skip_reason}")
            return

        ip = ip.strip()
        eligibility = check_real_ban_eligibility(ip)
        if eligibility.rejection_reason in {
            "business_whitelist",
            "private_ip_whitelist",
            "reserved_or_localhost",
        }:
            reason = f"whitelist_or_local_protected:{eligibility.rejection_reason}"
            logger.warning("[响应][保护] 跳过自动封禁: ip=%s reason=%s", ip, reason)
            self._append_memory_action(
                {
                    "action": "ban_ip",
                    "source_ip": ip,
                    "dry_run": self.dry_run,
                    "status": "skipped",
                    "reason": reason,
                    "operator": operator,
                    "trigger_source": trigger_source,
                }
            )
            self._persist_action(
                alert_id=aid,
                action_type="ban_ip",
                target=ip,
                status="skipped",
                dry_run=self.dry_run,
                error=reason,
                reason=reason,
                operator=operator,
                trigger_source=trigger_source,
                meta={"level": level_label, "policy": eligibility.rejection_reason},
            )
            self._audit("ban_ip", ip, f"skipped:{reason}")
            return
        effective_firewall_dry = self.dry_run
        ban_status = "applied"
        policy_note = ""
        if self.dry_run:
            effective_firewall_dry = True
            ban_status = "dry_run_simulated"
        elif not eligibility.allowed:
            effective_firewall_dry = True
            ban_status = "dry_run_simulated"
            policy_note = eligibility.rejection_reason

        if ip in self._banned_ips:
            logger.info("[防火墙] IP 已在封禁列表中，跳过: %s", ip)
            self._append_memory_action(
                {
                    "action": "ban_ip",
                    "source_ip": ip,
                    "dry_run": self.dry_run,
                    "status": "skipped",
                    "reason": "already_banned",
                    "operator": operator,
                    "trigger_source": trigger_source,
                }
            )
            self._persist_action(
                alert_id=aid,
                action_type="ban_ip",
                target=ip,
                status="skipped",
                dry_run=self.dry_run,
                reason="already_banned",
                operator=operator,
                trigger_source=trigger_source,
                meta={"level": level_label},
            )
            self._audit("ban_ip", ip, "skipped:already_banned")
            return

        fw_res = self._firewall.ban_input_drop(ip, dry_run=effective_firewall_dry)
        until = datetime.now(timezone.utc) + duration

        if not fw_res.ok:
            logger.error("[防火墙] 封禁失败: %s", fw_res.message)
            self._append_memory_action(
                {
                    "action": "ban_ip",
                    "source_ip": ip,
                    "dry_run": effective_firewall_dry,
                    "status": "failed",
                    "reason": fw_res.message,
                    "operator": operator,
                    "trigger_source": trigger_source,
                }
            )
            self._persist_action(
                alert_id=aid,
                action_type="ban_ip",
                target=ip,
                status="failed",
                dry_run=effective_firewall_dry,
                error=fw_res.message,
                scheduled_unblock_at=until,
                reason=fw_res.message,
                operator=operator,
                trigger_source=trigger_source,
                meta={"level": level_label, "command": fw_res.command},
            )
            self._audit("ban_ip", ip, f"failed:{fw_res.message}")
            return

        self._banned_ips[ip] = until
        if effective_firewall_dry:
            logger.info(
                "[DRY RUN] 封禁为演练/降级模拟，非生产iptables成功: ip=%s msg=%s",
                ip,
                fw_res.message,
            )

        self._append_memory_action(
            {
                "action": "ban_ip",
                "source_ip": ip,
                "dry_run": effective_firewall_dry,
                "status": ban_status,
                "reason": reason_override or policy_note or f"{level_label}_temporary_ban",
                "operator": operator,
                "trigger_source": trigger_source,
                "duration_sec": int(duration.total_seconds()),
                "iptables_cmd": fw_res.command,
                "policy_note": policy_note,
            }
        )
        rid = self._persist_action(
            alert_id=aid,
            action_type="ban_ip",
            target=ip,
            status=ban_status,
            dry_run=effective_firewall_dry,
            scheduled_unblock_at=until,
            reason=reason_override or policy_note or f"{level_label}_temporary_ban",
            operator=operator,
            trigger_source=trigger_source,
            meta={
                "level": level_label,
                "command": fw_res.command,
                "simulated_reason": policy_note or None,
            },
        )
        self._audit(
            "ban_ip",
            ip,
            "DRY_RUN_SIMULATED" if ban_status == "dry_run_simulated" else "applied",
            extra={"dry_run": effective_firewall_dry, "status": ban_status},
        )

        self._scheduler.schedule_unblock(
            ip=ip,
            run_at=until if until.tzinfo else until.replace(tzinfo=timezone.utc),
            dry_run=effective_firewall_dry,
            alert_id=aid,
            related_response_action_id=rid or None,
        )

    def _isolate_for_critical(self, result: DetectionResult) -> None:
        ip = result.source_ip if isinstance(result.source_ip, str) else ""
        aid = self._alert_id(result)
        if not validate_ip(ip):
            logger.warning("[响应][降级] 隔离跳过：非法 IP %r", ip)
            return
        ip = ip.strip()
        if isinstance(self._isolation, NullHostIsolationProvider):
            self._append_memory_action(
                {
                    "action": "isolation_manual_pending",
                    "source_ip": ip,
                    "dry_run": self.dry_run,
                    "status": "pending",
                    "reason": "host_isolation_provider_unconfigured",
                }
            )
            self._persist_action(
                alert_id=aid,
                action_type="isolation_manual_pending",
                target=ip,
                status="pending",
                dry_run=self.dry_run,
                reason="host_isolation_provider_unconfigured",
                meta={"reason": "host_isolation_provider_unconfigured"},
            )
            self._audit(
                "isolate_host",
                ip,
                "manual_todo:provider_unconfigured",
            )
            self._persistence.append_audit_db_event(
                event_type="isolation_manual_pending",
                resource_id=aid,
                actor=_SYSTEM_OPERATOR,
                ip_address=ip,
                payload={"ip": ip},
            )
            return

        iso = self._isolation.isolate(ip, dry_run=self.dry_run)
        self._append_memory_action(
            {
                "action": "isolate_host",
                "source_ip": ip,
                "dry_run": self.dry_run,
                "status": "applied" if iso.success else "failed",
                "reason": "critical_host_isolation" if iso.success else iso.message,
                "message": iso.message,
            }
        )
        self._persist_action(
            alert_id=aid,
            action_type="isolate_host",
            target=ip,
            status="applied" if iso.success else "failed",
            dry_run=self.dry_run,
            error=None if iso.success else iso.message,
            reason="critical_host_isolation" if iso.success else iso.message,
            meta={"message": iso.message},
        )
        self._audit("isolate_host", ip, iso.message)

    def _ban_ip(self, ip: str, duration: timedelta) -> None:
        """兼容旧测试：单 IP 封禁入口。"""
        self._ban_for_level(
            DetectionResult(
                threat_type="legacy_test",
                threat_level="high",
                confidence=1.0,
                details="legacy _ban_ip",
                source_ip=ip,
                raw_data={},
            ),
            duration=duration,
            level_label="legacy",
        )

    def _isolate_host(self, ip: str) -> None:
        """兼容旧测试：隔离入口。"""
        self._isolate_for_critical(
            DetectionResult(
                threat_type="legacy_test",
                threat_level="critical",
                confidence=1.0,
                details="legacy _isolate_host",
                source_ip=ip,
                raw_data={},
            )
        )

    def request_ban_approval(
        self,
        ip: str,
        *,
        operator: str = _SYSTEM_OPERATOR,
        reason: str = "approval_required",
        alert_id: Optional[str] = None,
    ) -> None:
        """记录人工审批待办，不执行防火墙动作。"""
        status = "pending"
        normalized_ip = ip.strip() if isinstance(ip, str) else ""
        if not validate_ip(normalized_ip):
            status = "skipped"
            reason = "invalid_ipv4_format"
        elif check_real_ban_eligibility(normalized_ip).rejection_reason in {
            "business_whitelist",
            "private_ip_whitelist",
            "reserved_or_localhost",
        }:
            status = "skipped"
            reason = "whitelist_or_local_protected"
        self._append_memory_action(
            {
                "action": "ban_ip_approval",
                "source_ip": normalized_ip,
                "dry_run": True,
                "status": status,
                "reason": reason,
                "operator": operator,
                "trigger_source": _MANUAL_TRIGGER,
            }
        )
        self._persist_action(
            alert_id=alert_id,
            action_type="ban_ip_approval",
            target=normalized_ip,
            status=status,
            dry_run=True,
            reason=reason,
            operator=operator,
            trigger_source=_MANUAL_TRIGGER,
            meta={"approved": False},
        )

    def approve_and_ban_ip(
        self,
        ip: str,
        *,
        operator: str,
        reason: str,
        duration: timedelta = _HIGH_BAN_DURATION,
        alert_id: Optional[str] = None,
    ) -> None:
        """审批后封禁入口；若 responder 仍是 dry_run=True，则只做演练封禁。"""
        self._ban_for_level(
            DetectionResult(
                threat_type="manual_approval",
                threat_level="high",
                confidence=1.0,
                details=reason,
                source_ip=ip,
                raw_data={"alert_id": alert_id} if alert_id else {},
            ),
            duration=duration,
            level_label="approved",
            operator=operator.strip() or "unknown_operator",
            trigger_source=_MANUAL_TRIGGER,
            reason_override=f"approved:{reason.strip() or 'no_reason'}",
        )

    def unban_ip(
        self,
        ip: str,
        *,
        operator: str = _SYSTEM_OPERATOR,
        reason: str = "manual_unban",
        trigger_source: str = _MANUAL_TRIGGER,
    ) -> None:
        if not validate_ip(ip):
            logger.error("[防火墙] 无效的 IP 地址，拒绝解封: %r", ip)
            self._append_memory_action(
                {
                    "action": "unban_ip",
                    "source_ip": ip if isinstance(ip, str) else "",
                    "dry_run": self.dry_run,
                    "status": "skipped",
                    "reason": "invalid_ipv4_format",
                    "operator": operator,
                    "trigger_source": trigger_source,
                }
            )
            return
        ip = ip.strip()
        fw = self._firewall.unban_input_drop(ip, dry_run=self.dry_run)
        if not fw.ok and not self.dry_run:
            logger.error("[防火墙] 解封失败: %s", fw.message)
        self._banned_ips.pop(ip, None)
        status = "applied" if fw.ok else "failed"
        self._append_memory_action(
            {
                "action": "unban_ip",
                "source_ip": ip,
                "dry_run": self.dry_run,
                "status": status,
                "reason": reason,
                "operator": operator,
                "trigger_source": trigger_source,
                "iptables_cmd": fw.command,
            }
        )
        self._persist_action(
            alert_id=None,
            action_type="unban_ip",
            target=ip,
            status=status,
            dry_run=self.dry_run,
            error=None if fw.ok else fw.message,
            reason=reason,
            operator=operator,
            trigger_source=trigger_source,
            meta={"command": fw.command},
        )
        self._audit(
            "unban_ip",
            ip,
            f"{status}:{reason}",
            extra={"operator": operator, "trigger_source": trigger_source},
        )

    def manual_unban_ip(self, ip: str, *, operator: str, reason: str) -> None:
        """人工解封入口：用于误封回滚，强制记录操作者和原因。"""
        self.unban_ip(
            ip,
            operator=operator.strip() or "unknown_operator",
            reason=reason.strip() or "manual_unban",
            trigger_source=_MANUAL_TRIGGER,
        )

    def rollback_ban(self, ip: str, *, operator: str, reason: str) -> None:
        """封禁回滚路径：语义化包装，底层复用人工解封。"""
        self.unban_ip(
            ip,
            operator=operator.strip() or "unknown_operator",
            reason=f"rollback:{reason.strip() or 'no_reason'}",
            trigger_source=_MANUAL_TRIGGER,
        )

    def execute_scheduled_unblock(
        self,
        ip: str,
        *,
        dry_run: bool,
        alert_id: Optional[str],
        schedule_task_id: int,
    ) -> None:
        if not validate_ip(ip):
            logger.error("[scheduler] 无效 IP，跳过解封: %r", ip)
            return
        ip = ip.strip()
        fw = self._firewall.unban_input_drop(ip, dry_run=dry_run)
        self._banned_ips.pop(ip, None)
        st = "applied" if fw.ok else "failed"
        self._persist_action(
            alert_id=alert_id,
            action_type="unban_ip",
            target=ip,
            status=st,
            dry_run=dry_run,
            error=None if fw.ok else fw.message,
            reason="scheduled_unblock",
            trigger_source=_SCHEDULER_TRIGGER,
            meta={"schedule_task_id": schedule_task_id, "command": fw.command},
        )
        self._append_memory_action(
            {
                "action": "unban_ip",
                "source_ip": ip,
                "dry_run": dry_run,
                "status": st,
                "reason": "scheduled_unblock",
                "trigger_source": _SCHEDULER_TRIGGER,
                "schedule_task_id": schedule_task_id,
            }
        )
        prefix = "DRY_RUN_" if dry_run else ""
        self._audit(
            "unban_ip",
            ip,
            f"{prefix}{st}:{fw.message}",
            extra={"schedule_task_id": schedule_task_id},
        )

    def execute_notify_retry(
        self,
        *,
        subject: str,
        body: str,
        meta: Dict[str, Any],
        alert_id: Optional[str],
        schedule_task_id: int,
        attempt: int,
        max_attempts: int,
    ) -> bool:
        attempts = self._notifier.notify_all(subject, body, meta=meta)
        ok = any(a.ok for a in attempts)
        self._persist_action(
            alert_id=alert_id,
            action_type="notify_retry",
            target=None,
            status="applied" if ok else "failed",
            dry_run=self.dry_run,
            error=None if ok else ";".join(x.detail for x in attempts[-3:]),
            reason="scheduled_notify_retry",
            trigger_source=_SCHEDULER_TRIGGER,
            meta={
                "schedule_task_id": schedule_task_id,
                "attempt": attempt,
                "max_attempts": max_attempts,
                "attempts": [{"c": x.channel, "ok": x.ok, "d": x.detail} for x in attempts],
            },
        )
        self._audit(
            "notify_retry",
            "",
            "ok" if ok else "failed",
            extra={"schedule_task_id": schedule_task_id},
        )
        if not ok:
            self._persistence.append_audit_db_event(
                event_type="notify_retry_failed",
                resource_id=alert_id,
                actor=_SYSTEM_OPERATOR,
                payload={"schedule_task_id": schedule_task_id, "attempt": attempt},
            )
        return ok

    @property
    def banned_ips(self) -> Dict[str, datetime]:
        return dict(self._banned_ips)

    def is_banned(self, ip: str) -> bool:
        return ip in self._banned_ips
