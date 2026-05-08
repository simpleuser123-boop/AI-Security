"""Web 控制台持久化 ORM 模型（生产 v1.0 数据面）。

业务真源为数据库表：告警、流转历史、规则、IOC、设置、封禁等；进程内
``_ServerState`` 仅作缓存/推送兼容，不得作为唯一数据源。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List, Optional

from sqlalchemy import (
    CheckConstraint,
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


DEFAULT_TENANT_ID = "tenant_default"
DEFAULT_ORGANIZATION_ID = "org_default"
DEFAULT_ROLE_ID = "role_owner"
DEFAULT_SYSTEM_USER_ID = "user_system"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Tenant(db.Model):
    """租户边界：所有需要隔离的业务数据最终都归属到租户。"""

    __tablename__ = "tenants"
    __table_args__ = (
        UniqueConstraint("slug", name="uq_tenants_slug"),
        Index("ix_tenants_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    plan: Mapped[Optional[str]] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    organizations: Mapped[List["Organization"]] = relationship(
        "Organization", back_populates="tenant", cascade="all, delete-orphan"
    )
    roles: Mapped[List["Role"]] = relationship(
        "Role", back_populates="tenant", cascade="all, delete-orphan"
    )
    memberships: Mapped[List["Membership"]] = relationship(
        "Membership", back_populates="tenant", cascade="all, delete-orphan"
    )
    api_keys: Mapped[List["APIKey"]] = relationship(
        "APIKey", back_populates="tenant", cascade="all, delete-orphan"
    )
    response_approvals: Mapped[List["ResponseApproval"]] = relationship(
        "ResponseApproval", back_populates="tenant", cascade="all, delete-orphan"
    )
    response_whitelist_entries: Mapped[List["ResponseWhitelistEntry"]] = relationship(
        "ResponseWhitelistEntry", back_populates="tenant", cascade="all, delete-orphan"
    )
    response_provider_configs: Mapped[List["ResponseProviderConfig"]] = relationship(
        "ResponseProviderConfig", back_populates="tenant", cascade="all, delete-orphan"
    )
    response_drills: Mapped[List["ResponseDrill"]] = relationship(
        "ResponseDrill", back_populates="tenant", cascade="all, delete-orphan"
    )


class Organization(db.Model):
    """租户下的组织/企业单元。"""

    __tablename__ = "organizations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "slug", name="uq_organizations_tenant_slug"),
        Index("ix_organizations_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="organizations")
    memberships: Mapped[List["Membership"]] = relationship(
        "Membership", back_populates="organization", cascade="all, delete-orphan"
    )


class User(db.Model):
    """平台用户身份。邮箱保持全局唯一，授权通过 membership 落到租户/组织。"""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email", name="uq_users_email"),
        Index("ix_users_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    username: Mapped[Optional[str]] = mapped_column(String(128))
    display_name: Mapped[Optional[str]] = mapped_column(String(160))
    password_hash: Mapped[Optional[str]] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    memberships: Mapped[List["Membership"]] = relationship(
        "Membership", back_populates="user", cascade="all, delete-orphan"
    )
    api_keys: Mapped[List["APIKey"]] = relationship("APIKey", back_populates="user")


class Role(db.Model):
    """租户内角色定义。"""

    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_roles_tenant_name"),
        Index("ix_roles_tenant_scope", "tenant_id", "scope"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(400))
    scope: Mapped[str] = mapped_column(String(32), nullable=False, default="tenant")
    permissions: Mapped[Optional[Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="roles")
    memberships: Mapped[List["Membership"]] = relationship(
        "Membership", back_populates="role"
    )


class Membership(db.Model):
    """用户在租户/组织中的成员关系。"""

    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "organization_id", "user_id", name="uq_memberships_tenant_org_user"
        ),
        Index("ix_memberships_user_status", "user_id", "status"),
        Index("ix_memberships_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    invited_by_user_id: Mapped[Optional[str]] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="memberships")
    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="memberships"
    )
    user: Mapped["User"] = relationship("User", back_populates="memberships")
    role: Mapped["Role"] = relationship("Role", back_populates="memberships")


class APIKey(db.Model):
    """API 调用凭证，仅保存哈希和短前缀。"""

    __tablename__ = "api_keys"
    __table_args__ = (
        UniqueConstraint("key_prefix", name="uq_api_keys_prefix"),
        UniqueConstraint("key_hash", name="uq_api_keys_hash"),
        Index("ix_api_keys_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("organizations.id", ondelete="SET NULL")
    )
    user_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="SET NULL")
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(32), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="viewer")
    scopes: Mapped[Optional[Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="api_keys")
    user: Mapped[Optional["User"]] = relationship("User", back_populates="api_keys")


class Plan(db.Model):
    """商业套餐定义：配额上限与数据保留期。"""

    __tablename__ = "plans"
    __table_args__ = (
        UniqueConstraint("code", name="uq_plans_code"),
        Index("ix_plans_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    limits: Mapped[Any] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )


class LicenseKey(db.Model):
    """离线/销售发放 License，可覆盖或替代套餐限制。"""

    __tablename__ = "license_keys"
    __table_args__ = (
        UniqueConstraint("key_hash", name="uq_license_keys_hash"),
        Index("ix_license_keys_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    key_prefix: Mapped[str] = mapped_column(String(32), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    limits: Mapped[Optional[Any]] = mapped_column(JSON)
    issued_to: Mapped[Optional[str]] = mapped_column(String(160))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )


class Subscription(db.Model):
    """租户当前订阅：绑定套餐或 License。"""

    __tablename__ = "subscriptions"
    __table_args__ = (Index("ix_subscriptions_tenant_status", "tenant_id", "status"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    plan_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("plans.id", ondelete="SET NULL")
    )
    license_key_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("license_keys.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    starts_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    ends_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    plan: Mapped[Optional["Plan"]] = relationship("Plan")
    license_key: Mapped[Optional["LicenseKey"]] = relationship("LicenseKey")


class Quota(db.Model):
    """租户配额快照，支持套餐默认值之上的显式覆盖。"""

    __tablename__ = "quotas"
    __table_args__ = (
        UniqueConstraint("tenant_id", "metric", name="uq_quotas_tenant_metric"),
        Index("ix_quotas_tenant_metric", "tenant_id", "metric"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    metric: Mapped[str] = mapped_column(String(64), nullable=False)
    limit: Mapped[Optional[int]] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="plan")
    warning_thresholds: Mapped[Optional[Any]] = mapped_column(JSON)
    overage_policy: Mapped[str] = mapped_column(String(32), nullable=False, default="reject")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )


class UsageMeter(db.Model):
    """租户用量计数器。period=current 表示当前总量，YYYY-MM 表示月度 bucket。"""

    __tablename__ = "usage_meters"
    __table_args__ = (
        UniqueConstraint("tenant_id", "metric", "period", name="uq_usage_tenant_metric_period"),
        Index("ix_usage_tenant_metric", "tenant_id", "metric"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    metric: Mapped[str] = mapped_column(String(64), nullable=False)
    period: Mapped[str] = mapped_column(String(32), nullable=False, default="current")
    period_start: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    period_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )


class Alert(db.Model):
    """告警主表。"""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_status_ts", "status", "timestamp"),
        Index("ix_alerts_tenant_status_ts", "tenant_id", "status", "timestamp"),
        Index("ix_alerts_tenant_timestamp", "tenant_id", "timestamp"),
        Index("ix_alerts_tenant_threat_type", "tenant_id", "threat_type"),
        Index("ix_alerts_tenant_level", "tenant_id", "level"),
        UniqueConstraint("tenant_id", "external_id", name="uq_alerts_tenant_external_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
        index=True,
    )
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
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
        index=True,
    )
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
    __table_args__ = (
        CheckConstraint(
            "dry_run OR action_type != 'ban_ip' OR status != 'executed' "
            "OR scheduled_unblock_at IS NOT NULL",
            name="ck_response_actions_real_ban_has_unblock_at",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
        index=True,
    )
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
    approvals: Mapped[List["ResponseApproval"]] = relationship(
        "ResponseApproval", back_populates="response_action"
    )
    drills: Mapped[List["ResponseDrill"]] = relationship(
        "ResponseDrill", back_populates="response_action"
    )


class ResponseScheduleTask(db.Model):
    """响应调度任务：定时解封、通知重试等（可恢复）。"""

    __tablename__ = "response_schedule_tasks"
    __table_args__ = (
        Index("ix_response_schedule_run", "status", "run_at"),
        Index("ix_response_schedule_tenant_run", "tenant_id", "status", "run_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
        index=True,
    )
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


class ResponseApproval(db.Model):
    """真实响应审批单：授权一次受控响应动作，不替代 ResponseAction 执行记录。"""

    __tablename__ = "response_approvals"
    __table_args__ = (
        CheckConstraint(
            "action_type IN ('ban_ip', 'unban_ip', 'isolate_host', 'release_host', "
            "'cloud_security_group_block', 'cloud_security_group_unblock')",
            name="ck_response_approvals_action_type",
        ),
        CheckConstraint(
            "target_type IN ('ip', 'cidr', 'asset', 'host', 'security_group_rule', 'tag')",
            name="ck_response_approvals_target_type",
        ),
        CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'executing', 'executed', "
            "'failed', 'cancelled', 'expired', 'reviewed')",
            name="ck_response_approvals_status",
        ),
        CheckConstraint("ttl_seconds IS NULL OR ttl_seconds > 0", name="ck_response_approvals_ttl"),
        Index("ix_response_approvals_tenant_status", "tenant_id", "status"),
        Index("ix_response_approvals_tenant_target", "tenant_id", "target_type", "target"),
        Index("ix_response_approvals_alert", "tenant_id", "alert_id"),
        Index("ix_response_approvals_action", "tenant_id", "response_action_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    alert_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("alerts.id", ondelete="SET NULL")
    )
    response_action_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("response_actions.id", ondelete="SET NULL")
    )
    provider_config_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("response_provider_configs.id", ondelete="SET NULL")
    )
    gate_id: Mapped[Optional[str]] = mapped_column(String(128))
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False, default="ip")
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    provider: Mapped[Optional[str]] = mapped_column(String(80))
    ttl_seconds: Mapped[Optional[int]] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(128))
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    rejected_by: Mapped[Optional[str]] = mapped_column(String(128))
    rejected_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text)
    executed_by: Mapped[Optional[str]] = mapped_column(String(128))
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(128))
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    evidence: Mapped[Optional[Any]] = mapped_column(JSON)
    rollback_plan: Mapped[Optional[Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="response_approvals")
    response_action: Mapped[Optional["ResponseAction"]] = relationship(
        "ResponseAction", back_populates="approvals"
    )
    provider_config: Mapped[Optional["ResponseProviderConfig"]] = relationship(
        "ResponseProviderConfig", back_populates="approvals"
    )


class ResponseWhitelistEntry(db.Model):
    """真实响应业务保护白名单，支持 IP、CIDR、资产标识和标签。"""

    __tablename__ = "response_whitelist_entries"
    __table_args__ = (
        CheckConstraint(
            "value_type IN ('ip', 'cidr', 'asset', 'tag')",
            name="ck_response_whitelist_value_type",
        ),
        CheckConstraint(
            "scope IN ('business', 'private', 'control_plane', 'office', 'monitoring')",
            name="ck_response_whitelist_scope",
        ),
        CheckConstraint(
            "status IN ('pending', 'active', 'disabled', 'expired')",
            name="ck_response_whitelist_status",
        ),
        UniqueConstraint(
            "tenant_id",
            "scope",
            "value_type",
            "value",
            "environment",
            name="uq_response_whitelist_tenant_scope_value_env",
        ),
        Index("ix_response_whitelist_tenant_status", "tenant_id", "status"),
        Index("ix_response_whitelist_lookup", "tenant_id", "value_type", "value", "status"),
        Index("ix_response_whitelist_expires", "tenant_id", "expires_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scope: Mapped[str] = mapped_column(String(32), nullable=False)
    value_type: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), nullable=False, default="production")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    owner: Mapped[Optional[str]] = mapped_column(String(128))
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(128))
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    evidence: Mapped[Optional[Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="response_whitelist_entries")


class ResponseProviderConfig(db.Model):
    """真实响应 provider 配置元数据；仅保存凭证引用和指纹，不保存明文密钥。"""

    __tablename__ = "response_provider_configs"
    __table_args__ = (
        CheckConstraint(
            "provider_type IN ('iptables', 'cloud_security_group', 'edr')",
            name="ck_response_provider_configs_type",
        ),
        CheckConstraint(
            "status IN ('draft', 'active', 'disabled', 'validation_failed', 'revoked')",
            name="ck_response_provider_configs_status",
        ),
        UniqueConstraint(
            "tenant_id",
            "provider_type",
            "provider_name",
            "environment",
            name="uq_response_provider_tenant_type_name_env",
        ),
        Index("ix_response_provider_tenant_status", "tenant_id", "status"),
        Index("ix_response_provider_lookup", "tenant_id", "provider_type", "environment"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_name: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), nullable=False, default="production")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    config_ref: Mapped[Optional[str]] = mapped_column(String(512))
    credential_ref: Mapped[Optional[str]] = mapped_column(String(512))
    secret_fingerprint: Mapped[Optional[str]] = mapped_column(String(128))
    config_metadata: Mapped[Optional[Any]] = mapped_column(JSON)
    capabilities: Mapped[Optional[Any]] = mapped_column(JSON)
    last_validated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_validation_result: Mapped[Optional[Any]] = mapped_column(JSON)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    updated_by: Mapped[Optional[str]] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="response_provider_configs")
    approvals: Mapped[List["ResponseApproval"]] = relationship(
        "ResponseApproval", back_populates="provider_config"
    )
    drills: Mapped[List["ResponseDrill"]] = relationship(
        "ResponseDrill", back_populates="provider_config"
    )


class ResponseDrill(db.Model):
    """客户侧恢复演练记录，证明真实响应具备可回滚和可恢复能力。"""

    __tablename__ = "response_drills"
    __table_args__ = (
        CheckConstraint(
            "drill_type IN ('dry_run_ban_unblock', 'real_ban_unblock', "
            "'edr_isolate_release', 'provider_rollback', 'misblock_recovery')",
            name="ck_response_drills_type",
        ),
        CheckConstraint(
            "target_type IN ('ip', 'cidr', 'asset', 'host', 'security_group_rule', 'tag')",
            name="ck_response_drills_target_type",
        ),
        CheckConstraint(
            "status IN ('planned', 'running', 'passed', 'failed', 'cancelled')",
            name="ck_response_drills_status",
        ),
        CheckConstraint("rto_seconds IS NULL OR rto_seconds >= 0", name="ck_response_drills_rto"),
        Index("ix_response_drills_tenant_status", "tenant_id", "status"),
        Index("ix_response_drills_tenant_env", "tenant_id", "environment", "started_at"),
        Index("ix_response_drills_action", "tenant_id", "response_action_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_config_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("response_provider_configs.id", ondelete="SET NULL")
    )
    response_action_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("response_actions.id", ondelete="SET NULL")
    )
    approval_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("response_approvals.id", ondelete="SET NULL")
    )
    environment: Mapped[str] = mapped_column(String(64), nullable=False, default="preprod")
    drill_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="planned")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    rto_seconds: Mapped[Optional[int]] = mapped_column(Integer)
    result: Mapped[Optional[str]] = mapped_column(Text)
    participants: Mapped[Optional[Any]] = mapped_column(JSON)
    evidence: Mapped[Optional[Any]] = mapped_column(JSON)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="response_drills")
    provider_config: Mapped[Optional["ResponseProviderConfig"]] = relationship(
        "ResponseProviderConfig", back_populates="drills"
    )
    response_action: Mapped[Optional["ResponseAction"]] = relationship(
        "ResponseAction", back_populates="drills"
    )


class Rule(db.Model):
    """检测规则（与 Phase 7 规则 API 语义对齐，供后续迁移）。"""

    __tablename__ = "rules"
    __table_args__ = (
        Index("ix_rules_enabled_priority", "enabled", "priority"),
        Index("ix_rules_tenant_enabled_priority", "tenant_id", "enabled", "priority"),
        Index("ix_rules_tenant_priority_updated", "tenant_id", "priority", "updated_at"),
        Index("ix_rules_tenant_type_enabled_priority", "tenant_id", "type", "enabled", "priority"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
        index=True,
    )
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
        UniqueConstraint("tenant_id", "ioc_type", "value", name="uq_iocs_tenant_type_value"),
        Index("ix_iocs_tenant_type_value", "tenant_id", "ioc_type", "value"),
        Index("ix_iocs_value", "value"),
        Index("ix_iocs_expires_at", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
        index=True,
    )
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
    __table_args__ = (Index("ix_settings_tenant_key", "tenant_id", "key"),)

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
        primary_key=True,
        index=True,
    )
    value: Mapped[Optional[Any]] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )


class BannedIp(db.Model):
    """手工/API 封禁的 IP 列表（持久化）。"""

    __tablename__ = "banned_ips"
    __table_args__ = (Index("ix_banned_ips_tenant_ip", "tenant_id", "ip"),)

    ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
        primary_key=True,
        index=True,
    )
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
    __table_args__ = (
        Index("ix_audit_created", "created_at"),
        Index("ix_audit_tenant_created", "tenant_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
        index=True,
    )
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
    __table_args__ = (
        UniqueConstraint("tenant_id", "version", name="uq_model_versions_tenant_version"),
        Index("ix_model_versions_tenant_created", "tenant_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
        index=True,
    )
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_uri: Mapped[Optional[str]] = mapped_column(String(512))
    checksum: Mapped[Optional[str]] = mapped_column(String(128))
    deployed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    notes: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
