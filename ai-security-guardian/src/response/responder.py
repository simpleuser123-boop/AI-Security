"""
防护响应引擎（R4：通知、FirewallManager、调度、持久化与审计）。
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from src.detectors.base import DetectionResult
from src.response.firewall import (
    FirewallManager,
    approved_response_execution,
    firewall_manager_from_env,
)
from src.response.host_isolation import (
    HostIsolationProvider,
    NullHostIsolationProvider,
    host_isolation_from_env,
)
from src.response.ip_policy import check_real_ban_eligibility, is_whitelist_rejection
from src.response.ip_validate import validate_ip
from src.response.notifier import AlertNotifier
from src.response.persistence import ResponsePersistence, create_response_persistence_from_env
from src.response.real_enforcement_gate import (
    real_enforcement_env_failures,
    first_failure_code,
)
from src.response.scheduler import ResponseScheduler

logger = logging.getLogger(__name__)

_HIGH_BAN_DURATION = timedelta(hours=1)
_CRITICAL_BAN_DURATION = timedelta(days=1)
_SYSTEM_OPERATOR = "security_responder"
_DETECTION_TRIGGER = "detection"
_SCHEDULER_TRIGGER = "scheduler"
_MANUAL_TRIGGER = "manual"
_REAL_ENFORCEMENT_GATE_ENV = "REAL_ENFORCEMENT_GATE"
_REAL_ENFORCEMENT_GATE_VALUE = "real-enforcement"
STATUS_PENDING_APPROVAL = "pending_approval"
STATUS_APPROVED = "approved"
STATUS_EXECUTED = "executed"
STATUS_SCHEDULED_UNBLOCKED = "scheduled_unblocked"
STATUS_MANUAL_UNBLOCKED = "manual_unblocked"
STATUS_REVIEWED = "reviewed"
STATUS_REJECTED = "rejected"

RESPONSE_STRATEGY = {
    "low": "audit_only",
    "medium": "audit_and_notify",
    "high": "audit_notify_temporary_ban",
    "critical": "audit_notify_temporary_ban_and_isolation",
}


def _looks_like_missing_firewall_rule(message: str) -> bool:
    msg = (message or "").strip().lower()
    return any(
        token in msg
        for token in (
            "not_found",
            "not found",
            "not exist",
            "does not exist",
            "no such rule",
            "rule_not_found",
            "called_process_error",
        )
    )


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
        real_enforcement_gate: Optional[str] = None,
    ) -> None:
        self.dry_run = dry_run
        self._real_enforcement_gate_explicit = real_enforcement_gate is not None
        self._real_enforcement_gate = (
            real_enforcement_gate
            if real_enforcement_gate is not None
            else os.environ.get(_REAL_ENFORCEMENT_GATE_ENV, "")
        )
        self._firewall = firewall or firewall_manager_from_env()
        self._notifier = notifier if notifier is not None else AlertNotifier.from_env()
        self._isolation = isolation if isolation is not None else host_isolation_from_env()
        self._persistence = persistence or create_response_persistence_from_env()
        self._scheduler = scheduler or ResponseScheduler(self._persistence)
        self._security_logger = security_logger
        self._alert_id_from_result = alert_id_from_result

        self._banned_ips: Dict[str, datetime] = {}
        self._response_actions: List[Dict[str, Any]] = []

    def _real_enforcement_gate_open(self) -> bool:
        return (
            isinstance(self._real_enforcement_gate, str)
            and self._real_enforcement_gate.strip().lower() == _REAL_ENFORCEMENT_GATE_VALUE
        )

    def _host_isolation_provider_meta(self) -> Dict[str, Any]:
        provider = getattr(self._isolation, "provider_name", self._isolation.__class__.__name__)
        meta: Dict[str, Any] = {"provider": provider}
        config = getattr(self._isolation, "config", None)
        if config is not None and hasattr(config, "safe_meta"):
            meta["provider_config"] = config.safe_meta()
        return meta

    def _host_isolation_recovery_hint(self) -> str:
        recovery = getattr(self._isolation, "recovery_hint", None)
        if callable(recovery):
            try:
                return str(recovery("isolate_host"))
            except TypeError:
                return str(recovery())
        return "create EDR unisolate/recover task and verify endpoint telemetry resumes"

    def _host_isolation_gate_failures(self, context: Dict[str, Any]) -> List[str]:
        failures: List[str] = []
        if not self._real_enforcement_gate_open():
            failures.append("real_enforcement_gate_required")
        elif (
            not self._real_enforcement_gate_explicit
            or os.environ.get("DRY_RUN", "").strip().lower() == "false"
        ):
            failures.extend(
                str(item.get("code") or item.get("name") or "real_enforcement_env_required")
                for item in real_enforcement_env_failures(
                    gate_value=self._real_enforcement_gate,
                    include_gate=False,
                )
            )

        requested_by = str(context.get("requested_by") or _SYSTEM_OPERATOR).strip()
        approved_by = str(context.get("approved_by") or "").strip()
        delivery_confirmed = bool(context.get("delivery_confirmed"))
        two_person_approval = bool(approved_by and approved_by != requested_by)
        if not (two_person_approval or delivery_confirmed):
            failures.append("two_person_approval_or_delivery_confirmation_required")

        config = getattr(self._isolation, "config", None)
        provider_test_passed = bool(context.get("provider_test_passed"))
        recovery_drill_passed = bool(context.get("recovery_drill_passed"))
        if config is not None:
            provider_test_passed = provider_test_passed or bool(
                getattr(config, "provider_test_passed", False)
            )
            recovery_drill_passed = recovery_drill_passed or bool(
                getattr(config, "recovery_drill_passed", False)
            )
        if not recovery_drill_passed:
            failures.append("recovery_drill_required")
        if not provider_test_passed:
            failures.append("provider_test_required")
        return failures

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
        approval_granted: bool = False,
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
        if is_whitelist_rejection(eligibility.rejection_reason) or eligibility.rejection_reason == "reserved_or_localhost":
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
                meta={
                    "level": level_label,
                    "policy": eligibility.rejection_reason,
                    "whitelist_id": eligibility.matched_whitelist_id,
                    "whitelist_scope": eligibility.matched_whitelist_scope,
                },
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

        approval_reason = reason_override or policy_note or f"{level_label}_temporary_ban"
        if not approval_granted:
            self._append_memory_action(
                {
                    "action": "ban_ip",
                    "source_ip": ip,
                    "dry_run": self.dry_run,
                    "status": STATUS_PENDING_APPROVAL,
                    "reason": approval_reason,
                    "operator": operator,
                    "trigger_source": trigger_source,
                    "duration_sec": int(duration.total_seconds()),
                }
            )
            self._persist_action(
                alert_id=aid,
                action_type="ban_ip",
                target=ip,
                status=STATUS_PENDING_APPROVAL,
                dry_run=self.dry_run,
                scheduled_unblock_at=datetime.now(timezone.utc) + duration,
                reason=approval_reason,
                operator=operator,
                trigger_source=trigger_source,
                meta={"level": level_label, "approved": False},
            )
            self._audit("ban_ip", ip, f"{STATUS_PENDING_APPROVAL}:{approval_reason}")
            if not self.dry_run:
                return
            self._append_memory_action(
                {
                    "action": "ban_ip",
                    "source_ip": ip,
                    "dry_run": True,
                    "status": STATUS_APPROVED,
                    "reason": "dry_run_auto_approval",
                    "operator": operator,
                    "trigger_source": trigger_source,
                }
            )
            self._persist_action(
                alert_id=aid,
                action_type="ban_ip",
                target=ip,
                status=STATUS_APPROVED,
                dry_run=True,
                reason="dry_run_auto_approval",
                operator=operator,
                trigger_source=trigger_source,
                meta={"level": level_label, "approved": True, "dry_run_only": True},
            )
            approval_granted = True

        if not effective_firewall_dry and not self._real_enforcement_gate_open():
            reject_reason = "real_enforcement_gate_required"
            logger.error(
                "[响应][保护] 拒绝真实封禁：DRY_RUN=false 但缺少 %s=%s: ip=%s",
                _REAL_ENFORCEMENT_GATE_ENV,
                _REAL_ENFORCEMENT_GATE_VALUE,
                ip,
            )
            self._append_memory_action(
                {
                    "action": "ban_ip",
                    "source_ip": ip,
                    "dry_run": False,
                    "status": "rejected",
                    "reason": reject_reason,
                    "operator": operator,
                    "trigger_source": trigger_source,
                    "required_gate": _REAL_ENFORCEMENT_GATE_VALUE,
                }
            )
            self._persist_action(
                alert_id=aid,
                action_type="ban_ip",
                target=ip,
                status="rejected",
                dry_run=False,
                error=reject_reason,
                scheduled_unblock_at=datetime.now(timezone.utc) + duration,
                reason=reject_reason,
                operator=operator,
                trigger_source=trigger_source,
                meta={
                    "level": level_label,
                    "gate": self._real_enforcement_gate,
                    "required_gate": _REAL_ENFORCEMENT_GATE_VALUE,
                    "execution_mode": "blocked_before_real_provider",
                },
            )
            self._audit(
                "ban_ip",
                ip,
                f"rejected:{reject_reason}",
                extra={"required_gate": _REAL_ENFORCEMENT_GATE_VALUE},
            )
            return

        if (
            not effective_firewall_dry
            and (
                not self._real_enforcement_gate_explicit
                or os.environ.get("DRY_RUN", "").strip().lower() == "false"
            )
        ):
            env_failures = real_enforcement_env_failures(
                gate_value=self._real_enforcement_gate,
                include_gate=False,
            )
            if env_failures:
                reject_reason = first_failure_code(
                    env_failures,
                    "real_enforcement_admission_required",
                )
                logger.error(
                    "[响应][保护] 拒绝真实封禁：real-enforcement 准入环境变量未完成: ip=%s missing=%s",
                    ip,
                    env_failures,
                )
                self._append_memory_action(
                    {
                        "action": "ban_ip",
                        "source_ip": ip,
                        "dry_run": False,
                        "status": "rejected",
                        "reason": reject_reason,
                        "operator": operator,
                        "trigger_source": trigger_source,
                        "missing_prerequisites": env_failures,
                    }
                )
                self._persist_action(
                    alert_id=aid,
                    action_type="ban_ip",
                    target=ip,
                    status="rejected",
                    dry_run=False,
                    error=reject_reason,
                    scheduled_unblock_at=datetime.now(timezone.utc) + duration,
                    reason=reject_reason,
                    operator=operator,
                    trigger_source=trigger_source,
                    meta={
                        "level": level_label,
                        "gate": self._real_enforcement_gate,
                        "required_gate": _REAL_ENFORCEMENT_GATE_VALUE,
                        "missing_prerequisites": env_failures,
                        "execution_mode": "blocked_before_real_provider",
                    },
                )
                self._audit(
                    "ban_ip",
                    ip,
                    f"rejected:{reject_reason}",
                    extra={"missing_prerequisites": env_failures},
                )
                return

        with approved_response_execution():
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
                meta={
                    "level": level_label,
                    "command": fw_res.command,
                    "provider": (fw_res.meta or {}).get("plan", {}).get("provider"),
                    "provider_result": fw_res.meta or {},
                },
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
                "status": STATUS_EXECUTED,
                "reason": reason_override or policy_note or f"{level_label}_temporary_ban",
                "operator": operator,
                "trigger_source": trigger_source,
                "duration_sec": int(duration.total_seconds()),
                "iptables_cmd": fw_res.command,
                "provider_result": fw_res.meta,
                "policy_note": policy_note,
                "execution_mode": "dry_run" if effective_firewall_dry else "real",
                "legacy_status": ban_status,
            }
        )
        rid = self._persist_action(
            alert_id=aid,
            action_type="ban_ip",
            target=ip,
            status=STATUS_EXECUTED,
            dry_run=effective_firewall_dry,
            scheduled_unblock_at=until,
            reason=reason_override or policy_note or f"{level_label}_temporary_ban",
            operator=operator,
            trigger_source=trigger_source,
            meta={
                "level": level_label,
                "command": fw_res.command,
                "provider": (fw_res.meta or {}).get("plan", {}).get("provider"),
                "provider_result": fw_res.meta or {},
                "simulated_reason": policy_note or None,
                "execution_mode": "dry_run" if effective_firewall_dry else "real",
                "legacy_status": ban_status,
            },
        )
        self._audit(
            "ban_ip",
            ip,
            "DRY_RUN_SIMULATED" if ban_status == "dry_run_simulated" else "applied",
            extra={"dry_run": effective_firewall_dry, "status": ban_status},
        )

        try:
            schedule_task_id = self._scheduler.schedule_unblock(
                ip=ip,
                run_at=until if until.tzinfo else until.replace(tzinfo=timezone.utc),
                dry_run=effective_firewall_dry,
                alert_id=aid,
                related_response_action_id=rid or None,
            )
        except Exception as exc:  # noqa: BLE001
            err = f"scheduled_unblock_create_failed:{exc}"
            logger.exception("[响应][保护] 封禁成功后创建定时解封失败: ip=%s", ip)
            self._persistence.append_audit_db_event(
                event_type="response.ban_ip.schedule_unblock_failed",
                resource_id=str(rid or ""),
                actor=operator,
                ip_address=ip,
                payload={
                    "target": ip,
                    "dry_run": effective_firewall_dry,
                    "scheduled_unblock_at": until.isoformat(),
                    "error": err,
                    "recovery": "rollback_ban",
                },
            )
            if not effective_firewall_dry:
                with approved_response_execution():
                    rollback_fw = self._firewall.unban_input_drop(ip, dry_run=False)
                self._banned_ips.pop(ip, None)
                rollback_status = STATUS_MANUAL_UNBLOCKED if rollback_fw.ok else "failed"
                self._persist_action(
                    alert_id=aid,
                    action_type="unban_ip",
                    target=ip,
                    status=rollback_status,
                    dry_run=False,
                    error=None if rollback_fw.ok else rollback_fw.message,
                    reason="rollback:scheduled_unblock_create_failed",
                    operator=operator,
                    trigger_source=_SCHEDULER_TRIGGER,
                    meta={
                        "related_response_action_id": rid,
                        "scheduled_unblock_at": until.isoformat(),
                        "schedule_error": err,
                        "command": rollback_fw.command,
                        "provider_result": rollback_fw.meta or {},
                    },
                )
            return
        self._persistence.append_audit_db_event(
            event_type="response.ban_ip.scheduled_unblock_created",
            resource_id=str(rid or ""),
            actor=operator,
            ip_address=ip,
            payload={
                "target": ip,
                "dry_run": effective_firewall_dry,
                "scheduled_unblock_at": until.isoformat(),
                "schedule_task_id": schedule_task_id,
            },
        )

    def _isolate_for_critical(
        self,
        result: DetectionResult,
        *,
        approval_granted: bool = False,
        requested_by: str = _SYSTEM_OPERATOR,
        approved_by: Optional[str] = None,
        delivery_confirmed: bool = False,
        recovery_drill_passed: bool = False,
        provider_test_passed: bool = False,
        trigger_source: str = _DETECTION_TRIGGER,
        reason_override: Optional[str] = None,
    ) -> None:
        ip = result.source_ip if isinstance(result.source_ip, str) else ""
        aid = self._alert_id(result)
        if not validate_ip(ip):
            logger.warning("[响应][降级] 隔离跳过：非法 IP %r", ip)
            return
        ip = ip.strip()
        provider_meta = self._host_isolation_provider_meta()
        recovery_hint = self._host_isolation_recovery_hint()
        if isinstance(self._isolation, NullHostIsolationProvider):
            self._append_memory_action(
                {
                    "action": "isolation_manual_pending",
                    "source_ip": ip,
                    "dry_run": self.dry_run,
                    "status": "pending",
                    "reason": "host_isolation_provider_unconfigured",
                    "operator": requested_by,
                    "trigger_source": trigger_source,
                    "provider": provider_meta.get("provider"),
                    "recovery_hint": recovery_hint,
                }
            )
            self._persist_action(
                alert_id=aid,
                action_type="isolation_manual_pending",
                target=ip,
                status="pending",
                dry_run=self.dry_run,
                reason="host_isolation_provider_unconfigured",
                operator=requested_by,
                trigger_source=trigger_source,
                meta={
                    "reason": "host_isolation_provider_unconfigured",
                    "provider": provider_meta.get("provider"),
                    "requested_by": requested_by,
                    "target": ip,
                    "recovery_hint": recovery_hint,
                },
            )
            self._audit(
                "isolate_host",
                ip,
                "manual_todo:provider_unconfigured",
            )
            self._persistence.append_audit_db_event(
                event_type="isolation_manual_pending",
                resource_id=aid,
                actor=requested_by,
                ip_address=ip,
                payload={
                    "target": ip,
                    "provider": provider_meta.get("provider"),
                    "requested_by": requested_by,
                    "recovery_hint": recovery_hint,
                },
            )
            return

        reason = reason_override or "critical_host_isolation"
        if not approval_granted:
            self._append_memory_action(
                {
                    "action": "isolate_host",
                    "source_ip": ip,
                    "dry_run": self.dry_run,
                    "status": STATUS_PENDING_APPROVAL,
                    "reason": reason,
                    "operator": requested_by,
                    "trigger_source": trigger_source,
                    "provider": provider_meta.get("provider"),
                    "recovery_hint": recovery_hint,
                }
            )
            self._persist_action(
                alert_id=aid,
                action_type="isolate_host",
                target=ip,
                status=STATUS_PENDING_APPROVAL,
                dry_run=self.dry_run,
                reason=reason,
                operator=requested_by,
                trigger_source=trigger_source,
                meta={
                    "approved": False,
                    "provider": provider_meta.get("provider"),
                    "requested_by": requested_by,
                    "target": ip,
                    "recovery_hint": recovery_hint,
                },
            )
            if not self.dry_run:
                return
            self._append_memory_action(
                {
                    "action": "isolate_host",
                    "source_ip": ip,
                    "dry_run": True,
                    "status": STATUS_APPROVED,
                    "reason": "dry_run_auto_approval",
                    "operator": requested_by,
                    "trigger_source": trigger_source,
                    "provider": provider_meta.get("provider"),
                    "recovery_hint": recovery_hint,
                }
            )
            self._persist_action(
                alert_id=aid,
                action_type="isolate_host",
                target=ip,
                status=STATUS_APPROVED,
                dry_run=True,
                reason="dry_run_auto_approval",
                operator=requested_by,
                trigger_source=trigger_source,
                meta={
                    "approved": True,
                    "dry_run_only": True,
                    "provider": provider_meta.get("provider"),
                    "requested_by": requested_by,
                    "target": ip,
                    "recovery_hint": recovery_hint,
                },
            )
            approval_granted = True

        context = {
            "alert_id": aid,
            "target": ip,
            "requested_by": requested_by,
            "approved_by": approved_by,
            "delivery_confirmed": delivery_confirmed,
            "recovery_drill_passed": recovery_drill_passed,
            "provider_test_passed": provider_test_passed,
            "recovery_hint": recovery_hint,
        }
        if not self.dry_run:
            gate_failures = self._host_isolation_gate_failures(context)
            if gate_failures:
                reject_reason = ",".join(gate_failures)
                self._append_memory_action(
                    {
                        "action": "isolate_host",
                        "source_ip": ip,
                        "dry_run": False,
                        "status": STATUS_REJECTED,
                        "reason": reject_reason,
                        "operator": requested_by,
                        "approved_by": approved_by,
                        "trigger_source": trigger_source,
                        "provider": provider_meta.get("provider"),
                        "recovery_hint": recovery_hint,
                    }
                )
                self._persist_action(
                    alert_id=aid,
                    action_type="isolate_host",
                    target=ip,
                    status=STATUS_REJECTED,
                    dry_run=False,
                    reason=reject_reason,
                    operator=requested_by,
                    trigger_source=trigger_source,
                    meta={
                        **provider_meta,
                        "requested_by": requested_by,
                        "approved_by": approved_by,
                        "target": ip,
                        "gate_failures": gate_failures,
                        "delivery_confirmed": delivery_confirmed,
                        "recovery_hint": recovery_hint,
                    },
                )
                self._audit(
                    "isolate_host",
                    ip,
                    f"rejected:{reject_reason}",
                    extra={"provider": provider_meta.get("provider")},
                )
                return

        with approved_response_execution():
            iso = self._isolation.isolate(ip, dry_run=self.dry_run, context=context)
        provider = iso.provider or provider_meta.get("provider")
        self._append_memory_action(
            {
                "action": "isolate_host",
                "source_ip": ip,
                "dry_run": self.dry_run,
                "status": STATUS_EXECUTED if iso.success else "failed",
                "reason": reason if iso.success else iso.message,
                "message": iso.message,
                "operator": requested_by,
                "approved_by": approved_by,
                "trigger_source": trigger_source,
                "provider": provider,
                "recovery_hint": iso.recovery_hint or recovery_hint,
            }
        )
        self._persist_action(
            alert_id=aid,
            action_type="isolate_host",
            target=ip,
            status=STATUS_EXECUTED if iso.success else "failed",
            dry_run=self.dry_run,
            error=None if iso.success else iso.message,
            reason=reason if iso.success else iso.message,
            operator=requested_by,
            trigger_source=trigger_source,
            meta={
                **provider_meta,
                "message": iso.message,
                "provider": provider,
                "provider_result": iso.meta,
                "requested_by": requested_by,
                "approved_by": approved_by,
                "target": ip,
                "recovery_hint": iso.recovery_hint or recovery_hint,
            },
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
            trigger_source="legacy",
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

    def approve_host_isolation(
        self,
        ip: str,
        *,
        requested_by: str,
        approved_by: str,
        reason: str,
        alert_id: Optional[str] = None,
        delivery_confirmed: bool = False,
        recovery_drill_passed: bool = False,
        provider_test_passed: bool = False,
    ) -> None:
        """Record host isolation approval only; provider execution is separate."""
        normalized_ip = ip.strip() if isinstance(ip, str) else ""
        requester = requested_by.strip() or "unknown_requester"
        approver = approved_by.strip() or "unknown_approver"
        approval_reason = reason.strip() or "host_isolation_approved"
        provider_meta = self._host_isolation_provider_meta()
        recovery_hint = self._host_isolation_recovery_hint()
        self._append_memory_action(
            {
                "action": "isolate_host",
                "source_ip": normalized_ip,
                "dry_run": self.dry_run,
                "status": STATUS_APPROVED,
                "reason": approval_reason,
                "operator": requester,
                "approved_by": approver,
                "trigger_source": _MANUAL_TRIGGER,
                "provider": provider_meta.get("provider"),
                "delivery_confirmed": delivery_confirmed,
                "recovery_hint": recovery_hint,
            }
        )
        self._persist_action(
            alert_id=alert_id,
            action_type="isolate_host",
            target=normalized_ip,
            status=STATUS_APPROVED,
            dry_run=self.dry_run,
            reason=approval_reason,
            operator=requester,
            trigger_source=_MANUAL_TRIGGER,
            meta={
                **provider_meta,
                "approved": True,
                "requested_by": requester,
                "approved_by": approver,
                "target": normalized_ip,
                "delivery_confirmed": delivery_confirmed,
                "recovery_drill_passed": recovery_drill_passed,
                "provider_test_passed": provider_test_passed,
                "recovery_hint": recovery_hint,
                "approval_only": True,
            },
        )

    def execute_approved_host_isolation(
        self,
        ip: str,
        *,
        requested_by: str,
        approved_by: str,
        reason: str,
        alert_id: Optional[str] = None,
        delivery_confirmed: bool = False,
        recovery_drill_passed: bool = False,
        provider_test_passed: bool = False,
    ) -> None:
        """Execute an approved critical host isolation through the C6 gate."""
        normalized_ip = ip.strip() if isinstance(ip, str) else ""
        requester = requested_by.strip() if isinstance(requested_by, str) else ""
        approver = approved_by.strip() if isinstance(approved_by, str) else ""
        if not requester or not approver or not reason.strip():
            reject_reason = "requester_approver_and_reason_required"
            self._append_memory_action(
                {
                    "action": "isolate_host",
                    "source_ip": normalized_ip,
                    "dry_run": self.dry_run,
                    "status": STATUS_REJECTED,
                    "reason": reject_reason,
                    "operator": requester or "unknown_requester",
                    "approved_by": approver or "unknown_approver",
                    "trigger_source": _MANUAL_TRIGGER,
                }
            )
            self._persist_action(
                alert_id=alert_id,
                action_type="isolate_host",
                target=normalized_ip,
                status=STATUS_REJECTED,
                dry_run=self.dry_run,
                reason=reject_reason,
                operator=requester or "unknown_requester",
                trigger_source=_MANUAL_TRIGGER,
                meta={"required": ["requested_by", "approved_by", "reason"]},
            )
            return
        approved_exists = any(
            a.get("action") == "isolate_host"
            and a.get("source_ip") == normalized_ip
            and a.get("status") == STATUS_APPROVED
            for a in self._response_actions
        )
        if not approved_exists:
            self.approve_host_isolation(
                normalized_ip,
                requested_by=requester,
                approved_by=approver,
                reason=reason,
                alert_id=alert_id,
                delivery_confirmed=delivery_confirmed,
                recovery_drill_passed=recovery_drill_passed,
                provider_test_passed=provider_test_passed,
            )
        self._isolate_for_critical(
            DetectionResult(
                threat_type="manual_approval",
                threat_level="critical",
                confidence=1.0,
                details=reason.strip(),
                source_ip=normalized_ip,
                raw_data={"alert_id": alert_id} if alert_id else {},
            ),
            approval_granted=True,
            requested_by=requester,
            approved_by=approver,
            delivery_confirmed=delivery_confirmed,
            recovery_drill_passed=recovery_drill_passed,
            provider_test_passed=provider_test_passed,
            trigger_source=_MANUAL_TRIGGER,
            reason_override=f"approved:{reason.strip()}",
        )

    def recover_host_isolation(
        self,
        ip: str,
        *,
        operator: str,
        reason: str = "manual_host_recovery",
        alert_id: Optional[str] = None,
    ) -> None:
        """Draft recovery path for host isolation: unisolate/recover via provider."""
        normalized_ip = ip.strip() if isinstance(ip, str) else ""
        operator_name = operator.strip() or "unknown_operator"
        provider_meta = self._host_isolation_provider_meta()
        with approved_response_execution():
            result = self._isolation.unisolate(
                normalized_ip,
                dry_run=self.dry_run,
                context={
                    "alert_id": alert_id,
                    "requested_by": operator_name,
                    "reason": reason,
                },
            )
        status = STATUS_MANUAL_UNBLOCKED if result.success else "failed"
        self._append_memory_action(
            {
                "action": "unisolate_host",
                "source_ip": normalized_ip,
                "dry_run": self.dry_run,
                "status": status,
                "reason": reason,
                "operator": operator_name,
                "trigger_source": _MANUAL_TRIGGER,
                "provider": result.provider or provider_meta.get("provider"),
                "recovery_hint": result.recovery_hint,
            }
        )
        self._persist_action(
            alert_id=alert_id,
            action_type="unisolate_host",
            target=normalized_ip,
            status=status,
            dry_run=self.dry_run,
            error=None if result.success else result.message,
            reason=reason,
            operator=operator_name,
            trigger_source=_MANUAL_TRIGGER,
            meta={
                **provider_meta,
                "provider": result.provider or provider_meta.get("provider"),
                "provider_result": result.meta,
                "message": result.message,
                "target": normalized_ip,
                "recovery_hint": result.recovery_hint,
            },
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
        status = STATUS_PENDING_APPROVAL
        normalized_ip = ip.strip() if isinstance(ip, str) else ""
        if not validate_ip(normalized_ip):
            status = "skipped"
            reason = "invalid_ipv4_format"
        else:
            approval_eligibility = check_real_ban_eligibility(normalized_ip)
            if is_whitelist_rejection(approval_eligibility.rejection_reason) or approval_eligibility.rejection_reason == "reserved_or_localhost":
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
        """兼容旧入口：只授予审批，不执行 provider。"""
        self.approve_ban_ip(
            ip,
            operator=operator,
            reason=reason,
            duration=duration,
            alert_id=alert_id,
        )

    def approve_ban_ip(
        self,
        ip: str,
        *,
        operator: str,
        reason: str,
        duration: timedelta = _HIGH_BAN_DURATION,
        alert_id: Optional[str] = None,
    ) -> None:
        """授予一次封禁审批；不会调用防火墙 provider。"""
        normalized_ip = ip.strip() if isinstance(ip, str) else ""
        operator_name = operator.strip() or "unknown_operator"
        approval_reason = reason.strip() or "approved"
        pending_exists = any(
            a.get("action") in {"ban_ip", "ban_ip_approval"}
            and a.get("source_ip") == normalized_ip
            and a.get("status") == STATUS_PENDING_APPROVAL
            for a in self._response_actions
        )
        if not pending_exists:
            self._append_memory_action(
                {
                    "action": "ban_ip",
                    "source_ip": normalized_ip,
                    "dry_run": self.dry_run,
                    "status": STATUS_PENDING_APPROVAL,
                    "reason": approval_reason,
                    "operator": operator_name,
                    "trigger_source": _MANUAL_TRIGGER,
                    "duration_sec": int(duration.total_seconds()),
                }
            )
            self._persist_action(
                alert_id=alert_id,
                action_type="ban_ip",
                target=normalized_ip,
                status=STATUS_PENDING_APPROVAL,
                dry_run=self.dry_run,
                scheduled_unblock_at=datetime.now(timezone.utc) + duration,
                reason=approval_reason,
                operator=operator_name,
                trigger_source=_MANUAL_TRIGGER,
                meta={"approved": False},
            )
        self._append_memory_action(
            {
                "action": "ban_ip",
                "source_ip": normalized_ip,
                "dry_run": self.dry_run,
                "status": STATUS_APPROVED,
                "reason": approval_reason,
                "operator": operator_name,
                "trigger_source": _MANUAL_TRIGGER,
                "duration_sec": int(duration.total_seconds()),
            }
        )
        self._persist_action(
            alert_id=alert_id,
            action_type="ban_ip",
            target=normalized_ip,
            status=STATUS_APPROVED,
            dry_run=self.dry_run,
            scheduled_unblock_at=datetime.now(timezone.utc) + duration,
            reason=approval_reason,
            operator=operator_name,
            trigger_source=_MANUAL_TRIGGER,
            meta={"approved": True, "approval_only": True},
        )

    def execute_approved_ban_ip(
        self,
        ip: str,
        *,
        operator: str,
        reason: str,
        duration: timedelta = _HIGH_BAN_DURATION,
        alert_id: Optional[str] = None,
    ) -> None:
        """执行已审批封禁；真实执行必须由此类人工动作触发。"""
        normalized_ip = ip.strip() if isinstance(ip, str) else ""
        operator_name = operator.strip() if isinstance(operator, str) else ""
        execution_reason = reason.strip() if isinstance(reason, str) else ""
        if not operator_name or not execution_reason:
            reject_reason = "operator_and_reason_required"
            self._append_memory_action(
                {
                    "action": "ban_ip",
                    "source_ip": normalized_ip,
                    "dry_run": self.dry_run,
                    "status": "rejected",
                    "reason": reject_reason,
                    "operator": operator_name or "unknown_operator",
                    "trigger_source": _MANUAL_TRIGGER,
                }
            )
            self._persist_action(
                alert_id=alert_id,
                action_type="ban_ip",
                target=normalized_ip,
                status="rejected",
                dry_run=self.dry_run,
                reason=reject_reason,
                operator=operator_name or "unknown_operator",
                trigger_source=_MANUAL_TRIGGER,
                meta={"required": ["operator", "reason"]},
            )
            return
        approved_exists = any(
            a.get("action") == "ban_ip"
            and a.get("source_ip") == normalized_ip
            and a.get("status") == STATUS_APPROVED
            for a in self._response_actions
        )
        if not approved_exists:
            reject_reason = "approval_required"
            self._append_memory_action(
                {
                    "action": "ban_ip",
                    "source_ip": normalized_ip,
                    "dry_run": self.dry_run,
                    "status": "rejected",
                    "reason": reject_reason,
                    "operator": operator_name,
                    "trigger_source": _MANUAL_TRIGGER,
                }
            )
            self._persist_action(
                alert_id=alert_id,
                action_type="ban_ip",
                target=normalized_ip,
                status="rejected",
                dry_run=self.dry_run,
                reason=reject_reason,
                operator=operator_name,
                trigger_source=_MANUAL_TRIGGER,
                meta={"required_previous_status": STATUS_APPROVED},
            )
            return
        self._ban_for_level(
            DetectionResult(
                threat_type="manual_approval",
                threat_level="high",
                confidence=1.0,
                details=execution_reason,
                source_ip=ip,
                raw_data={"alert_id": alert_id} if alert_id else {},
            ),
            duration=duration,
            level_label="approved",
            operator=operator_name,
            trigger_source=_MANUAL_TRIGGER,
            reason_override=f"approved:{execution_reason}",
            approval_granted=True,
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
            self._persist_action(
                alert_id=None,
                action_type="unban_ip",
                target=ip if isinstance(ip, str) else "",
                status="skipped",
                dry_run=self.dry_run,
                error="invalid_ipv4_format",
                reason="invalid_ipv4_format",
                operator=operator,
                trigger_source=trigger_source,
                meta={"requested_by": operator},
            )
            return
        ip = ip.strip()
        if ip not in self._banned_ips:
            self._append_memory_action(
                {
                    "action": "unban_ip",
                    "source_ip": ip,
                    "dry_run": self.dry_run,
                    "status": "skipped",
                    "reason": "unblock_requires_executed",
                    "operator": operator,
                    "trigger_source": trigger_source,
                }
            )
            self._persist_action(
                alert_id=None,
                action_type="unban_ip",
                target=ip,
                status="skipped",
                dry_run=self.dry_run,
                reason="unblock_requires_executed",
                operator=operator,
                trigger_source=trigger_source,
                meta={"required_previous_status": STATUS_EXECUTED},
            )
            return
        with approved_response_execution():
            fw = self._firewall.unban_input_drop(ip, dry_run=self.dry_run)
        if not fw.ok and not self.dry_run:
            logger.error("[防火墙] 解封失败: %s", fw.message)
        self._banned_ips.pop(ip, None)
        status = STATUS_MANUAL_UNBLOCKED if fw.ok else "failed"
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
                "provider_result": fw.meta,
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
            meta={
                "command": fw.command,
                "provider": (fw.meta or {}).get("plan", {}).get("provider"),
                "provider_result": fw.meta or {},
            },
        )
        self._audit(
            "unban_ip",
            ip,
            f"{status}:{reason}",
            extra={"operator": operator, "trigger_source": trigger_source},
        )

    def manual_unban_ip(self, ip: str, *, operator: str, reason: str) -> None:
        """人工解封入口：用于误封回滚，强制记录操作者和原因。"""
        operator_name = operator.strip() or "unknown_operator"
        unban_reason = reason.strip() or "manual_unban"
        self._persistence.append_audit_db_event(
            event_type="response.manual_unban.requested",
            actor=operator_name,
            ip_address=ip.strip() if validate_ip(ip) else None,
            payload={"target": ip, "reason": unban_reason},
        )
        self.unban_ip(
            ip,
            operator=operator_name,
            reason=unban_reason,
            trigger_source=_MANUAL_TRIGGER,
        )

    def rollback_ban(self, ip: str, *, operator: str, reason: str) -> None:
        """封禁回滚路径：语义化包装，底层复用人工解封。"""
        operator_name = operator.strip() or "unknown_operator"
        rollback_reason = f"rollback:{reason.strip() or 'no_reason'}"
        self._persistence.append_audit_db_event(
            event_type="response.rollback_ban.requested",
            actor=operator_name,
            ip_address=ip.strip() if validate_ip(ip) else None,
            payload={"target": ip, "reason": rollback_reason},
        )
        self.unban_ip(
            ip,
            operator=operator_name,
            reason=rollback_reason,
            trigger_source=_MANUAL_TRIGGER,
        )

    def mark_response_reviewed(
        self,
        target: str,
        *,
        operator: str,
        reason: str = "post_execution_review",
        alert_id: Optional[str] = None,
    ) -> bool:
        """Post-execution review; it never grants approval or execution."""
        normalized_target = target.strip() if isinstance(target, str) else ""
        prior_executed = any(
            a.get("source_ip") == normalized_target
            and a.get("status") in {STATUS_EXECUTED, STATUS_SCHEDULED_UNBLOCKED, STATUS_MANUAL_UNBLOCKED}
            for a in self._response_actions
        )
        status = STATUS_REVIEWED if prior_executed else "skipped"
        review_reason = reason.strip() or "post_execution_review"
        if not prior_executed:
            review_reason = "review_requires_executed"
        self._append_memory_action(
            {
                "action": "response_review",
                "source_ip": normalized_target,
                "dry_run": self.dry_run,
                "status": status,
                "reason": review_reason,
                "operator": operator.strip() or "unknown_operator",
                "trigger_source": _MANUAL_TRIGGER,
            }
        )
        self._persist_action(
            alert_id=alert_id,
            action_type="response_review",
            target=normalized_target,
            status=status,
            dry_run=self.dry_run,
            reason=review_reason,
            operator=operator.strip() or "unknown_operator",
            trigger_source=_MANUAL_TRIGGER,
            meta={"required_previous_status": STATUS_EXECUTED},
        )
        return prior_executed

    def execute_scheduled_unblock(
        self,
        ip: str,
        *,
        dry_run: bool,
        alert_id: Optional[str],
        schedule_task_id: int,
        related_response_action_id: Optional[int] = None,
    ) -> Optional[str]:
        if not validate_ip(ip):
            logger.error("[scheduler] 无效 IP，跳过解封: %r", ip)
            return None
        ip = ip.strip()
        if ip not in self._banned_ips and related_response_action_id is None:
            self._persist_action(
                alert_id=alert_id,
                action_type="unban_ip",
                target=ip,
                status="skipped",
                dry_run=dry_run,
                reason="scheduled_unblock_requires_executed",
                trigger_source=_SCHEDULER_TRIGGER,
                meta={
                    "schedule_task_id": schedule_task_id,
                    "required_previous_status": STATUS_EXECUTED,
                },
            )
            self._append_memory_action(
                {
                    "action": "unban_ip",
                    "source_ip": ip,
                    "dry_run": dry_run,
                    "status": "skipped",
                    "reason": "scheduled_unblock_requires_executed",
                    "trigger_source": _SCHEDULER_TRIGGER,
                    "schedule_task_id": schedule_task_id,
                }
            )
            return None
        with approved_response_execution():
            fw = self._firewall.unban_input_drop(ip, dry_run=dry_run)
        if fw.ok:
            self._banned_ips.pop(ip, None)
            st = STATUS_SCHEDULED_UNBLOCKED
        elif _looks_like_missing_firewall_rule(fw.message):
            self._banned_ips.pop(ip, None)
            st = "skipped"
        else:
            st = "failed"
        self._persist_action(
            alert_id=alert_id,
            action_type="unban_ip",
            target=ip,
            status=st,
            dry_run=dry_run,
            error=None if st != "failed" else fw.message,
            reason="scheduled_unblock" if st != "skipped" else "scheduled_unblock_rule_absent",
            trigger_source=_SCHEDULER_TRIGGER,
            meta={
                "schedule_task_id": schedule_task_id,
                "related_response_action_id": related_response_action_id,
                "command": fw.command,
                "provider": (fw.meta or {}).get("plan", {}).get("provider"),
                "provider_result": fw.meta or {},
            },
        )
        self._append_memory_action(
            {
                "action": "unban_ip",
                "source_ip": ip,
                "dry_run": dry_run,
                "status": st,
                "reason": "scheduled_unblock" if st != "skipped" else "scheduled_unblock_rule_absent",
                "trigger_source": _SCHEDULER_TRIGGER,
                "schedule_task_id": schedule_task_id,
                "related_response_action_id": related_response_action_id,
            }
        )
        prefix = "DRY_RUN_" if dry_run else ""
        self._audit(
            "unban_ip",
            ip,
            f"{prefix}{st}:{fw.message}",
            extra={"schedule_task_id": schedule_task_id},
        )
        if st == "failed":
            self._persistence.append_audit_db_event(
                event_type="response.scheduled_unblock.failed",
                resource_id=str(related_response_action_id or ""),
                actor=_SYSTEM_OPERATOR,
                ip_address=ip,
                payload={
                    "schedule_task_id": schedule_task_id,
                    "message": fw.message,
                    "will_retry": True,
                },
            )
            return fw.message or "scheduled_unblock_failed"
        return None

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
