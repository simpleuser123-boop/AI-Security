"""商业计量：套餐、订阅、配额、周期用量与超额策略。"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session


METRIC_USERS = "users"
METRIC_ALERTS = "alerts"
METRIC_RULES = "rules"
METRIC_IOCS = "iocs"
METRIC_API_CALLS = "api_calls"
METRIC_NOTIFICATIONS = "notifications"
METRIC_RESPONSE_ACTIONS = "response_actions"
METRIC_RETENTION_DAYS = "retention_days"

METERED_METRICS = {
    METRIC_USERS,
    METRIC_ALERTS,
    METRIC_RULES,
    METRIC_IOCS,
    METRIC_API_CALLS,
    METRIC_NOTIFICATIONS,
    METRIC_RESPONSE_ACTIONS,
    METRIC_RETENTION_DAYS,
}

DEFAULT_PLAN_CODE = "mvp-default"
DEFAULT_PLAN_LIMITS: Dict[str, Optional[int]] = {
    METRIC_USERS: 25,
    METRIC_ALERTS: 10_000,
    METRIC_RULES: 100,
    METRIC_IOCS: 1_000,
    METRIC_API_CALLS: 50_000,
    METRIC_NOTIFICATIONS: 10_000,
    METRIC_RESPONSE_ACTIONS: 2_000,
    METRIC_RETENTION_DAYS: 30,
}

DEFAULT_WARNING_THRESHOLDS = (0.8, 1.0)
OVERAGE_POLICY_REJECT = "reject"
OVERAGE_POLICY_DEGRADE = "degrade"
OVERAGE_POLICY_READ_ONLY = "read_only"
OVERAGE_POLICY_ALERT = "alert"
OVERAGE_POLICIES = {
    OVERAGE_POLICY_REJECT,
    OVERAGE_POLICY_DEGRADE,
    OVERAGE_POLICY_READ_ONLY,
    OVERAGE_POLICY_ALERT,
}


@dataclass(frozen=True)
class QuotaSnapshot:
    tenant_id: str
    metric: str
    limit: Optional[int]
    used: int
    remaining: Optional[int]
    period: str = "current"
    warning_thresholds: tuple[float, ...] = DEFAULT_WARNING_THRESHOLDS
    overage_policy: str = OVERAGE_POLICY_REJECT
    action: str = "allow"

    @property
    def exceeded(self) -> bool:
        return self.limit is not None and self.used > self.limit

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "metric": self.metric,
            "limit": self.limit,
            "used": self.used,
            "remaining": self.remaining,
            "exceeded": self.exceeded,
            "period": self.period,
            "warning_thresholds": list(self.warning_thresholds),
            "overage_policy": self.overage_policy,
            "action": self.action,
        }


class QuotaExceededError(RuntimeError):
    """Raised when a tenant operation would exceed a quota."""

    def __init__(self, snapshot: QuotaSnapshot, *, requested: int = 1, status_code: int = 402) -> None:
        self.snapshot = snapshot
        self.requested = requested
        self.status_code = status_code
        limit = "unlimited" if snapshot.limit is None else str(snapshot.limit)
        super().__init__(
            f"租户 {snapshot.tenant_id} 的 {snapshot.metric} 配额不足："
            f"当前 {snapshot.used}，请求新增 {requested}，上限 {limit}"
        )

    def to_error_payload(self) -> Dict[str, Any]:
        return {
            "error": "quota_exceeded",
            "code": "quota_exceeded",
            "message": str(self),
            "quota": self.snapshot.to_dict(),
            "requested": self.requested,
        }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def usage_period(value: Optional[datetime] = None) -> str:
    """Return the commercial monthly usage bucket key, e.g. 2026-05."""
    now = (value or _utc_now()).astimezone(timezone.utc)
    return f"{now.year:04d}-{now.month:02d}"


def _period_bounds(period: str) -> tuple[Optional[datetime], Optional[datetime]]:
    if period == "current":
        return None, None
    try:
        year_s, month_s = period.split("-", 1)
        year = int(year_s)
        month = int(month_s)
        start = datetime(year, month, 1, tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None, None
    if month == 12:
        end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(year, month + 1, 1, tzinfo=timezone.utc)
    return start, end


def _counter_row(session: Session, tenant_id: str, metric: str, period: str = "current"):
    from web.models import UsageMeter

    row = (
        session.query(UsageMeter)
        .filter(
            UsageMeter.tenant_id == tenant_id,
            UsageMeter.metric == metric,
            UsageMeter.period == period,
        )
        .one_or_none()
    )
    if row is None:
        period_start, period_end = _period_bounds(period)
        row = UsageMeter(
            tenant_id=tenant_id,
            metric=metric,
            period=period,
            period_start=period_start,
            period_end=period_end,
            used=0,
        )
        session.add(row)
        session.flush()
    return row


def _quota_row(session: Session, tenant_id: str, metric: str):
    from web.models import Quota

    return (
        session.query(Quota)
        .filter(Quota.tenant_id == tenant_id, Quota.metric == metric)
        .one_or_none()
    )


def _normalize_warning_thresholds(raw: Any) -> tuple[float, ...]:
    if not isinstance(raw, (list, tuple)):
        return DEFAULT_WARNING_THRESHOLDS
    values: list[float] = []
    for item in raw:
        try:
            value = float(item)
        except (TypeError, ValueError):
            continue
        if 0 < value <= 1:
            values.append(round(value, 4))
    return tuple(sorted(set(values))) or DEFAULT_WARNING_THRESHOLDS


def _quota_config(session: Session, tenant_id: str, metric: str) -> tuple[tuple[float, ...], str]:
    row = _quota_row(session, tenant_id, metric)
    if row is None:
        return DEFAULT_WARNING_THRESHOLDS, OVERAGE_POLICY_REJECT
    thresholds = _normalize_warning_thresholds(row.warning_thresholds)
    policy = str(row.overage_policy or OVERAGE_POLICY_REJECT)
    if policy not in OVERAGE_POLICIES:
        policy = OVERAGE_POLICY_REJECT
    return thresholds, policy


def _active_subscription(session: Session, tenant_id: str):
    from web.models import Subscription

    now = _utc_now()
    return (
        session.query(Subscription)
        .filter(
            Subscription.tenant_id == tenant_id,
            Subscription.status == "active",
            (Subscription.ends_at.is_(None)) | (Subscription.ends_at > now),
        )
        .order_by(Subscription.created_at.desc())
        .first()
    )


def effective_limits(session: Session, tenant_id: str) -> Dict[str, Optional[int]]:
    """Return the tenant's active plan/license limits."""
    from web.models import Plan, Quota

    limits: Dict[str, Optional[int]] = dict(DEFAULT_PLAN_LIMITS)
    sub = _active_subscription(session, tenant_id)
    if sub is not None:
        if sub.plan_id:
            plan = session.get(Plan, sub.plan_id)
            if plan is not None and plan.status == "active":
                limits.update(dict(plan.limits or {}))
        if sub.license_key is not None and sub.license_key.status == "active":
            expires_at = _aware_utc(sub.license_key.expires_at)
            if expires_at is None or expires_at > _utc_now():
                limits.update(dict(sub.license_key.limits or {}))

    for row in session.query(Quota).filter(Quota.tenant_id == tenant_id).all():
        if row.metric in METERED_METRICS:
            if row.source != "plan":
                limits[row.metric] = row.limit
    return limits


def sync_quota_rows(session: Session, tenant_id: str) -> None:
    """Materialize current effective limits into ``quotas`` for inspection."""
    from web.models import Quota

    limits = effective_limits_without_quota_overrides(session, tenant_id)
    existing = {
        row.metric: row
        for row in session.query(Quota).filter(Quota.tenant_id == tenant_id).all()
    }
    for metric, limit in limits.items():
        if metric not in METERED_METRICS:
            continue
        row = existing.get(metric)
        if row is None:
            session.add(
                Quota(
                    tenant_id=tenant_id,
                    metric=metric,
                    limit=limit,
                    source="plan",
                )
            )
        elif row.source == "plan":
            row.limit = limit


def effective_limits_without_quota_overrides(
    session: Session, tenant_id: str
) -> Dict[str, Optional[int]]:
    from web.models import Plan

    limits: Dict[str, Optional[int]] = dict(DEFAULT_PLAN_LIMITS)
    sub = _active_subscription(session, tenant_id)
    if sub is not None:
        if sub.plan_id:
            plan = session.get(Plan, sub.plan_id)
            if plan is not None and plan.status == "active":
                limits.update(dict(plan.limits or {}))
        if sub.license_key is not None and sub.license_key.status == "active":
            expires_at = _aware_utc(sub.license_key.expires_at)
            if expires_at is None or expires_at > _utc_now():
                limits.update(dict(sub.license_key.limits or {}))
    return limits


def current_usage(session: Session, tenant_id: str, metric: str) -> int:
    from web.models import Alert, IOC, Membership, ResponseAction, Rule, UsageMeter

    if metric == METRIC_USERS:
        return int(
            session.query(func.count(func.distinct(Membership.user_id)))
            .filter(Membership.tenant_id == tenant_id, Membership.status == "active")
            .scalar()
            or 0
        )
    if metric == METRIC_RULES:
        return int(
            session.query(func.count(Rule.id))
            .filter(Rule.tenant_id == tenant_id)
            .scalar()
            or 0
        )
    if metric == METRIC_IOCS:
        now = _utc_now()
        return int(
            session.query(func.count(IOC.id))
            .filter(
                IOC.tenant_id == tenant_id,
                (IOC.expires_at.is_(None)) | (IOC.expires_at > now),
            )
            .scalar()
            or 0
        )
    if metric == METRIC_ALERTS:
        return int(
            session.query(func.count(Alert.id))
            .filter(Alert.tenant_id == tenant_id)
            .scalar()
            or 0
        )
    if metric == METRIC_RESPONSE_ACTIONS:
        return int(
            session.query(func.count(ResponseAction.id))
            .filter(ResponseAction.tenant_id == tenant_id)
            .scalar()
            or 0
        )
    if metric == METRIC_RETENTION_DAYS:
        limits = effective_limits(session, tenant_id)
        return int(limits.get(METRIC_RETENTION_DAYS) or 0)
    row = session.query(UsageMeter).filter_by(
        tenant_id=tenant_id, metric=metric, period="current"
    ).one_or_none()
    return int(row.used if row is not None else 0)


def usage_bucket(
    session: Session, tenant_id: str, metric: str, period: Optional[str] = None
) -> int:
    from web.models import UsageMeter

    bucket = period or usage_period()
    row = session.query(UsageMeter).filter_by(
        tenant_id=tenant_id, metric=metric, period=bucket
    ).one_or_none()
    return int(row.used if row is not None else 0)


def usage_buckets(
    session: Session,
    tenant_id: str,
    *,
    metric: Optional[str] = None,
    period: Optional[str] = None,
):
    from web.models import UsageMeter

    query = session.query(UsageMeter).filter(UsageMeter.tenant_id == tenant_id)
    if metric:
        query = query.filter(UsageMeter.metric == metric)
    if period:
        query = query.filter(UsageMeter.period == period)
    return query.order_by(UsageMeter.period.desc(), UsageMeter.metric.asc()).all()


def quota_snapshot(
    session: Session,
    tenant_id: str,
    metric: str,
    *,
    used: Optional[int] = None,
    period: str = "current",
    action: str = "allow",
) -> QuotaSnapshot:
    if metric not in METERED_METRICS:
        raise ValueError(f"unknown metered metric: {metric}")
    limits = effective_limits(session, tenant_id)
    limit = limits.get(metric)
    warning_thresholds, overage_policy = _quota_config(session, tenant_id, metric)
    used_v = current_usage(session, tenant_id, metric) if used is None else int(used)
    remaining = None if limit is None else max(int(limit) - used_v, 0)
    return QuotaSnapshot(
        tenant_id=tenant_id,
        metric=metric,
        limit=None if limit is None else int(limit),
        used=used_v,
        remaining=remaining,
        period=period,
        warning_thresholds=warning_thresholds,
        overage_policy=overage_policy,
        action=action,
    )


def _emit_overage_event(
    session: Session,
    snapshot: QuotaSnapshot,
    *,
    requested: int,
    action: str,
    actor: Optional[str] = None,
) -> None:
    from web.models import AuditEvent

    session.add(
        AuditEvent(
            tenant_id=snapshot.tenant_id,
            event_type="usage_quota.overage",
            actor=(actor or "system")[:128],
            resource_type="quota",
            resource_id=f"{snapshot.metric}:{snapshot.period}"[:255],
            payload={
                "metric": snapshot.metric,
                "period": snapshot.period,
                "used": snapshot.used,
                "limit": snapshot.limit,
                "requested": int(requested),
                "policy": snapshot.overage_policy,
                "action": action,
            },
        )
    )


def ensure_quota(
    session: Session,
    tenant_id: str,
    metric: str,
    *,
    requested: int = 1,
    current: Optional[int] = None,
    operation: str = "write",
    actor: Optional[str] = None,
) -> QuotaSnapshot:
    used_after = (current_usage(session, tenant_id, metric) if current is None else current) + requested
    snapshot = quota_snapshot(session, tenant_id, metric, used=used_after)
    if snapshot.exceeded:
        policy = snapshot.overage_policy
        if policy == OVERAGE_POLICY_ALERT:
            snapshot = quota_snapshot(session, tenant_id, metric, used=used_after, action="alert")
            _emit_overage_event(session, snapshot, requested=requested, action="alert", actor=actor)
            return snapshot
        if policy == OVERAGE_POLICY_DEGRADE:
            snapshot = quota_snapshot(session, tenant_id, metric, used=used_after, action="degrade")
            _emit_overage_event(session, snapshot, requested=requested, action="degrade", actor=actor)
            return snapshot
        if policy == OVERAGE_POLICY_READ_ONLY and operation == "read":
            snapshot = quota_snapshot(session, tenant_id, metric, used=used_after, action="read_only")
            _emit_overage_event(session, snapshot, requested=requested, action="read_only", actor=actor)
            return snapshot
        action = "read_only_block" if policy == OVERAGE_POLICY_READ_ONLY else "reject"
        snapshot = quota_snapshot(session, tenant_id, metric, used=used_after, action=action)
        _emit_overage_event(session, snapshot, requested=requested, action=action, actor=actor)
        status_code = 403 if policy == OVERAGE_POLICY_READ_ONLY else 402
        raise QuotaExceededError(snapshot, requested=requested, status_code=status_code)
    return snapshot


def _emit_warning_events(
    session: Session,
    snapshot: QuotaSnapshot,
    *,
    previous_used: int,
    actor: Optional[str],
    resource_type: Optional[str],
    resource_id: Optional[str],
) -> None:
    if snapshot.limit is None or snapshot.limit <= 0:
        return
    from web.models import AuditEvent

    previous_ratio = previous_used / snapshot.limit
    current_ratio = snapshot.used / snapshot.limit
    for threshold in snapshot.warning_thresholds:
        if previous_ratio >= threshold or current_ratio < threshold:
            continue
        threshold_key = f"{threshold:.4f}"
        existing = (
            session.query(AuditEvent)
            .filter(
                AuditEvent.tenant_id == snapshot.tenant_id,
                AuditEvent.event_type == "usage_quota.warning",
                AuditEvent.resource_type == "quota",
                AuditEvent.resource_id == f"{snapshot.metric}:{snapshot.period}:{threshold_key}",
            )
            .one_or_none()
        )
        if existing is not None:
            continue
        session.add(
            AuditEvent(
                tenant_id=snapshot.tenant_id,
                event_type="usage_quota.warning",
                actor=(actor or "system")[:128],
                resource_type="quota",
                resource_id=f"{snapshot.metric}:{snapshot.period}:{threshold_key}",
                payload={
                    "metric": snapshot.metric,
                    "period": snapshot.period,
                    "threshold": threshold,
                    "used": snapshot.used,
                    "previous_used": previous_used,
                    "limit": snapshot.limit,
                    "usage_ratio": round(current_ratio, 4),
                    "source_resource_type": resource_type,
                    "source_resource_id": resource_id,
                },
            )
        )


def record_usage(
    session: Session,
    tenant_id: str,
    metric: str,
    *,
    delta: int = 1,
    actor: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    audit: bool = True,
) -> QuotaSnapshot:
    if metric not in METERED_METRICS:
        raise ValueError(f"unknown metered metric: {metric}")
    row = _counter_row(session, tenant_id, metric)
    previous_used = int(row.used or 0)
    row.used = max(0, int(row.used or 0) + int(delta))
    row.updated_at = _utc_now()
    bucket_period = usage_period()
    bucket = _counter_row(session, tenant_id, metric, bucket_period)
    bucket_previous_used = int(bucket.used or 0)
    bucket.used = max(0, int(bucket.used or 0) + int(delta))
    bucket.updated_at = _utc_now()
    snapshot = quota_snapshot(session, tenant_id, metric, used=row.used, period=bucket_period)
    _emit_warning_events(
        session,
        snapshot,
        previous_used=previous_used,
        actor=actor,
        resource_type=resource_type,
        resource_id=resource_id,
    )
    bucket_snapshot = quota_snapshot(session, tenant_id, metric, used=bucket.used, period=bucket_period)
    _emit_warning_events(
        session,
        bucket_snapshot,
        previous_used=bucket_previous_used,
        actor=actor,
        resource_type=resource_type,
        resource_id=resource_id,
    )
    if audit:
        from web.models import AuditEvent

        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                event_type="usage_meter.changed",
                actor=(actor or "system")[:128],
                resource_type=(resource_type or metric)[:64],
                resource_id=(resource_id or "")[:255] or None,
                payload={
                    "metric": metric,
                    "delta": int(delta),
                    "used": snapshot.used,
                    "limit": snapshot.limit,
                    "remaining": snapshot.remaining,
                    "period": bucket_period,
                    "period_used": bucket.used,
                },
            )
        )
    return snapshot


def quota_error_response(exc: QuotaExceededError):
    from flask import jsonify

    return jsonify(exc.to_error_payload()), exc.status_code
