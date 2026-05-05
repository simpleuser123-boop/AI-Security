"""Web 控制台持久化 ORM 模型（生产 v1.0 数据面）。

业务真源为数据库表：告警、流转历史、规则、IOC、设置、封禁等；进程内
``_ServerState`` 仅作缓存/推送兼容，不得作为唯一数据源。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from web.database import db


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Alert(db.Model):
    """告警主表。"""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_status_ts", "status", "timestamp"),
        UniqueConstraint("external_id", name="uq_alerts_external_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    external_id: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, default="")
    target_ip: Mapped[Optional[str]] = mapped_column(String(45))
    threat_type: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    level: Mapped[str] = mapped_column(String(32), nullable=False, default="low")
    confidence: Mapped[Optional[float]] = mapped_column(Float)
    engine: Mapped[Optional[str]] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    summary: Mapped[Optional[str]] = mapped_column(Text)
    raw_payload: Mapped[Optional[str]] = mapped_column(Text)
    model_version: Mapped[Optional[str]] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    histories: Mapped[List["AlertHistory"]] = relationship(
        "AlertHistory",
        back_populates="alert",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    response_actions: Mapped[List["ResponseAction"]] = relationship(
        "ResponseAction",
        back_populates="alert",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class AlertHistory(db.Model):
    """告警状态流转历史。"""

    __tablename__ = "alert_histories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    from_status: Mapped[Optional[str]] = mapped_column(String(32))
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    operator: Mapped[Optional[str]] = mapped_column(String(128))
    note: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

    alert: Mapped["Alert"] = relationship("Alert", back_populates="histories")


class ResponseAction(db.Model):
    """针对告警的响应动作记录（封禁、解封、演练等）。"""

    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[Optional[str]] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    meta: Mapped[Optional[Any]] = mapped_column(JSON)
    error: Mapped[Optional[str]] = mapped_column(Text)
    scheduled_unblock_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True)
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    alert: Mapped[Optional["Alert"]] = relationship("Alert", back_populates="response_actions")


class ResponseScheduleTask(db.Model):
    """响应调度任务：定时解封、通知重试等（可恢复）。"""

    __tablename__ = "response_schedule_tasks"
    __table_args__ = (Index("ix_response_schedule_run", "status", "run_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    alert_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        ForeignKey("alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    payload: Mapped[Optional[Any]] = mapped_column(JSON)
    run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    related_response_action_id: Mapped[Optional[int]] = mapped_column(Integer, index=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )


class Rule(db.Model):
    """检测规则（与 Phase 7 规则 API 语义对齐，供后续迁移）。"""

    __tablename__ = "rules"
    __table_args__ = (Index("ix_rules_enabled_priority", "enabled", "priority"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    rule_type: Mapped[str] = mapped_column("type", String(32), nullable=False)
    pattern: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    level: Mapped[str] = mapped_column(String(32), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    description: Mapped[Optional[str]] = mapped_column(String(400))
    hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )


class IOC(db.Model):
    """威胁情报 IOC 条目（生产化：TTL、多源合并、过期窗口）。"""

    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint("ioc_type", "value", name="uq_iocs_type_value"),
        Index("ix_iocs_value", "value"),
        Index("ix_iocs_expires_at", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    ioc_type: Mapped[str] = mapped_column("ioc_type", String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    sources: Mapped[Optional[Any]] = mapped_column(JSON)
    reason: Mapped[Optional[str]] = mapped_column(String(200))
    note: Mapped[Optional[str]] = mapped_column(String(400))
    score: Mapped[Optional[int]] = mapped_column(Integer)
    ttl_seconds: Mapped[Optional[int]] = mapped_column(Integer)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    ioc_meta: Mapped[Optional[Any]] = mapped_column("ioc_meta", JSON)
    hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )


class Setting(db.Model):
    """键值型系统设置（JSON 值）。"""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[Optional[Any]] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )


class BannedIp(db.Model):
    """手工/API 封禁的 IP 列表（持久化）。"""

    __tablename__ = "banned_ips"

    ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    reason: Mapped[str] = mapped_column(String(200), nullable=False, default="manual")
    operator: Mapped[Optional[str]] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )


class AuditEvent(db.Model):
    """安全审计事件。"""

    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_created", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor: Mapped[Optional[str]] = mapped_column(String(128))
    resource_type: Mapped[Optional[str]] = mapped_column(String(64))
    resource_id: Mapped[Optional[str]] = mapped_column(String(255))
    payload: Mapped[Optional[Any]] = mapped_column(JSON)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )


class ModelVersion(db.Model):
    """已登记/部署的模型版本元数据。"""

    __tablename__ = "model_versions"
    __table_args__ = (UniqueConstraint("version", name="uq_model_versions_version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_uri: Mapped[Optional[str]] = mapped_column(String(512))
    checksum: Mapped[Optional[str]] = mapped_column(String(128))
    deployed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    notes: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
