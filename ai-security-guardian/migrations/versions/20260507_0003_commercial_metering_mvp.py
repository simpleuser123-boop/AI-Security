"""Commercial metering MVP.

Revision ID: 20260507_0003
Revises: 20260507_0002
Create Date: 2026-05-07
"""
from __future__ import annotations

from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "20260507_0003"
down_revision = "20260507_0002"
branch_labels = None
depends_on = None

DEFAULT_PLAN_LIMITS = {
    "users": 25,
    "alerts": 10000,
    "rules": 100,
    "iocs": 1000,
    "api_calls": 50000,
    "notifications": 10000,
    "response_actions": 2000,
    "retention_days": 30,
}


def upgrade() -> None:
    op.create_table(
        "plans",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("limits", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code", name="uq_plans_code"),
    )
    op.create_index("ix_plans_status", "plans", ["status"], unique=False)

    op.create_table(
        "license_keys",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("key_prefix", sa.String(length=32), nullable=False),
        sa.Column("key_hash", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("limits", sa.JSON(), nullable=True),
        sa.Column("issued_to", sa.String(length=160), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_hash", name="uq_license_keys_hash"),
    )
    op.create_index(
        "ix_license_keys_tenant_status",
        "license_keys",
        ["tenant_id", "status"],
        unique=False,
    )

    op.create_table(
        "subscriptions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("plan_id", sa.String(length=64), nullable=True),
        sa.Column("license_key_id", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["license_key_id"], ["license_keys.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["plan_id"], ["plans.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_subscriptions_tenant_status",
        "subscriptions",
        ["tenant_id", "status"],
        unique=False,
    )

    op.create_table(
        "quotas",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("metric", sa.String(length=64), nullable=False),
        sa.Column("limit", sa.Integer(), nullable=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "metric", name="uq_quotas_tenant_metric"),
    )
    op.create_index("ix_quotas_tenant_metric", "quotas", ["tenant_id", "metric"], unique=False)

    op.create_table(
        "usage_meters",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("metric", sa.String(length=64), nullable=False),
        sa.Column("period", sa.String(length=32), nullable=False),
        sa.Column("used", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "metric", "period", name="uq_usage_tenant_metric_period"
        ),
    )
    op.create_index(
        "ix_usage_tenant_metric", "usage_meters", ["tenant_id", "metric"], unique=False
    )

    stamp = datetime.now(timezone.utc)
    op.bulk_insert(
        sa.table(
            "plans",
            sa.column("id", sa.String),
            sa.column("code", sa.String),
            sa.column("name", sa.String),
            sa.column("status", sa.String),
            sa.column("limits", sa.JSON),
            sa.column("created_at", sa.DateTime(timezone=True)),
            sa.column("updated_at", sa.DateTime(timezone=True)),
        ),
        [
            {
                "id": "plan_default_mvp",
                "code": "mvp-default",
                "name": "Default MVP",
                "status": "active",
                "limits": DEFAULT_PLAN_LIMITS,
                "created_at": stamp,
                "updated_at": stamp,
            }
        ],
    )
    op.bulk_insert(
        sa.table(
            "subscriptions",
            sa.column("id", sa.String),
            sa.column("tenant_id", sa.String),
            sa.column("plan_id", sa.String),
            sa.column("status", sa.String),
            sa.column("starts_at", sa.DateTime(timezone=True)),
            sa.column("created_at", sa.DateTime(timezone=True)),
            sa.column("updated_at", sa.DateTime(timezone=True)),
        ),
        [
            {
                "id": "sub_default_mvp",
                "tenant_id": "tenant_default",
                "plan_id": "plan_default_mvp",
                "status": "active",
                "starts_at": stamp,
                "created_at": stamp,
                "updated_at": stamp,
            }
        ],
    )
    quota_table = sa.table(
        "quotas",
        sa.column("tenant_id", sa.String),
        sa.column("metric", sa.String),
        sa.column("limit", sa.Integer),
        sa.column("source", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(
        quota_table,
        [
            {
                "tenant_id": "tenant_default",
                "metric": metric,
                "limit": limit,
                "source": "plan",
                "created_at": stamp,
                "updated_at": stamp,
            }
            for metric, limit in DEFAULT_PLAN_LIMITS.items()
        ],
    )


def downgrade() -> None:
    op.drop_index("ix_usage_tenant_metric", table_name="usage_meters")
    op.drop_table("usage_meters")
    op.drop_index("ix_quotas_tenant_metric", table_name="quotas")
    op.drop_table("quotas")
    op.drop_index("ix_subscriptions_tenant_status", table_name="subscriptions")
    op.drop_table("subscriptions")
    op.drop_index("ix_license_keys_tenant_status", table_name="license_keys")
    op.drop_table("license_keys")
    op.drop_index("ix_plans_status", table_name="plans")
    op.drop_table("plans")
