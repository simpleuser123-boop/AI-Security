"""Phase B1 multitenant data model.

Revision ID: 20260507_0002
Revises: 20260506_0001
Create Date: 2026-05-07
"""
from __future__ import annotations

from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "20260507_0002"
down_revision = "20260506_0001"
branch_labels = None
depends_on = None

DEFAULT_TENANT_ID = "tenant_default"
DEFAULT_ORGANIZATION_ID = "org_default"
DEFAULT_ROLE_ID = "role_owner"
DEFAULT_SYSTEM_USER_ID = "user_system"

ISOLATED_TABLES = (
    "alerts",
    "alert_histories",
    "response_actions",
    "response_schedule_tasks",
    "rules",
    "iocs",
    "settings",
    "banned_ips",
    "audit_events",
    "model_versions",
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("slug", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("plan", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug", name="uq_tenants_slug"),
    )
    op.create_index("ix_tenants_status", "tenants", ["status"], unique=False)

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=True),
        sa.Column("display_name", sa.String(length=160), nullable=True),
        sa.Column("password_hash", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_status", "users", ["status"], unique=False)

    op.create_table(
        "organizations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("slug", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "slug", name="uq_organizations_tenant_slug"),
    )
    op.create_index(
        "ix_organizations_tenant_status",
        "organizations",
        ["tenant_id", "status"],
        unique=False,
    )

    op.create_table(
        "roles",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("description", sa.String(length=400), nullable=True),
        sa.Column("scope", sa.String(length=32), nullable=False),
        sa.Column("permissions", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_roles_tenant_name"),
    )
    op.create_index("ix_roles_tenant_scope", "roles", ["tenant_id", "scope"], unique=False)

    op.create_table(
        "memberships",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("role_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("invited_by_user_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "organization_id", "user_id", name="uq_memberships_tenant_org_user"
        ),
    )
    op.create_index(
        "ix_memberships_tenant_status",
        "memberships",
        ["tenant_id", "status"],
        unique=False,
    )
    op.create_index(
        "ix_memberships_user_status",
        "memberships",
        ["user_id", "status"],
        unique=False,
    )

    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.String(length=64), nullable=True),
        sa.Column("user_id", sa.String(length=64), nullable=True),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("key_prefix", sa.String(length=32), nullable=False),
        sa.Column("key_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_hash", name="uq_api_keys_hash"),
        sa.UniqueConstraint("key_prefix", name="uq_api_keys_prefix"),
    )
    op.create_index(
        "ix_api_keys_tenant_status",
        "api_keys",
        ["tenant_id", "status"],
        unique=False,
    )

    stamp = _now()
    op.bulk_insert(
        sa.table(
            "tenants",
            sa.column("id", sa.String),
            sa.column("name", sa.String),
            sa.column("slug", sa.String),
            sa.column("status", sa.String),
            sa.column("plan", sa.String),
            sa.column("created_at", sa.DateTime(timezone=True)),
            sa.column("updated_at", sa.DateTime(timezone=True)),
        ),
        [
            {
                "id": DEFAULT_TENANT_ID,
                "name": "Default Tenant",
                "slug": "default",
                "status": "active",
                "plan": "legacy-single-tenant",
                "created_at": stamp,
                "updated_at": stamp,
            }
        ],
    )
    op.bulk_insert(
        sa.table(
            "organizations",
            sa.column("id", sa.String),
            sa.column("tenant_id", sa.String),
            sa.column("name", sa.String),
            sa.column("slug", sa.String),
            sa.column("status", sa.String),
            sa.column("created_at", sa.DateTime(timezone=True)),
            sa.column("updated_at", sa.DateTime(timezone=True)),
        ),
        [
            {
                "id": DEFAULT_ORGANIZATION_ID,
                "tenant_id": DEFAULT_TENANT_ID,
                "name": "Default Organization",
                "slug": "default",
                "status": "active",
                "created_at": stamp,
                "updated_at": stamp,
            }
        ],
    )
    op.bulk_insert(
        sa.table(
            "users",
            sa.column("id", sa.String),
            sa.column("email", sa.String),
            sa.column("username", sa.String),
            sa.column("display_name", sa.String),
            sa.column("status", sa.String),
            sa.column("created_at", sa.DateTime(timezone=True)),
            sa.column("updated_at", sa.DateTime(timezone=True)),
        ),
        [
            {
                "id": DEFAULT_SYSTEM_USER_ID,
                "email": "system@local.guardian",
                "username": "system",
                "display_name": "System",
                "status": "active",
                "created_at": stamp,
                "updated_at": stamp,
            }
        ],
    )
    op.bulk_insert(
        sa.table(
            "roles",
            sa.column("id", sa.String),
            sa.column("tenant_id", sa.String),
            sa.column("name", sa.String),
            sa.column("description", sa.String),
            sa.column("scope", sa.String),
            sa.column("permissions", sa.JSON),
            sa.column("created_at", sa.DateTime(timezone=True)),
            sa.column("updated_at", sa.DateTime(timezone=True)),
        ),
        [
            {
                "id": DEFAULT_ROLE_ID,
                "tenant_id": DEFAULT_TENANT_ID,
                "name": "owner",
                "description": "Legacy single-enterprise owner role",
                "scope": "tenant",
                "permissions": ["*"],
                "created_at": stamp,
                "updated_at": stamp,
            }
        ],
    )
    op.bulk_insert(
        sa.table(
            "memberships",
            sa.column("id", sa.String),
            sa.column("tenant_id", sa.String),
            sa.column("organization_id", sa.String),
            sa.column("user_id", sa.String),
            sa.column("role_id", sa.String),
            sa.column("status", sa.String),
            sa.column("created_at", sa.DateTime(timezone=True)),
            sa.column("updated_at", sa.DateTime(timezone=True)),
        ),
        [
            {
                "id": "membership_default_owner",
                "tenant_id": DEFAULT_TENANT_ID,
                "organization_id": DEFAULT_ORGANIZATION_ID,
                "user_id": DEFAULT_SYSTEM_USER_ID,
                "role_id": DEFAULT_ROLE_ID,
                "status": "active",
                "created_at": stamp,
                "updated_at": stamp,
            }
        ],
    )

    for table_name in ISOLATED_TABLES:
        op.add_column(
            table_name,
            sa.Column(
                "tenant_id",
                sa.String(length=64),
                nullable=False,
                server_default=DEFAULT_TENANT_ID,
            ),
        )
        op.create_index(f"ix_{table_name}_tenant_id", table_name, ["tenant_id"], unique=False)

    op.create_index(
        "ix_alerts_tenant_status_ts",
        "alerts",
        ["tenant_id", "status", "timestamp"],
        unique=False,
    )
    op.create_index(
        "ix_response_schedule_tenant_run",
        "response_schedule_tasks",
        ["tenant_id", "status", "run_at"],
        unique=False,
    )
    op.create_index(
        "ix_rules_tenant_enabled_priority",
        "rules",
        ["tenant_id", "enabled", "priority"],
        unique=False,
    )
    op.create_index(
        "ix_iocs_tenant_type_value",
        "iocs",
        ["tenant_id", "ioc_type", "value"],
        unique=False,
    )
    op.create_index(
        "ix_audit_tenant_created",
        "audit_events",
        ["tenant_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_model_versions_tenant_created",
        "model_versions",
        ["tenant_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_model_versions_tenant_created", table_name="model_versions")
    op.drop_index("ix_audit_tenant_created", table_name="audit_events")
    op.drop_index("ix_iocs_tenant_type_value", table_name="iocs")
    op.drop_index("ix_rules_tenant_enabled_priority", table_name="rules")
    op.drop_index("ix_response_schedule_tenant_run", table_name="response_schedule_tasks")
    op.drop_index("ix_alerts_tenant_status_ts", table_name="alerts")

    for table_name in reversed(ISOLATED_TABLES):
        op.drop_index(f"ix_{table_name}_tenant_id", table_name=table_name)
        op.drop_column(table_name, "tenant_id")

    op.drop_index("ix_api_keys_tenant_status", table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_index("ix_memberships_user_status", table_name="memberships")
    op.drop_index("ix_memberships_tenant_status", table_name="memberships")
    op.drop_table("memberships")
    op.drop_index("ix_roles_tenant_scope", table_name="roles")
    op.drop_table("roles")
    op.drop_index("ix_organizations_tenant_status", table_name="organizations")
    op.drop_table("organizations")
    op.drop_index("ix_users_status", table_name="users")
    op.drop_table("users")
    op.drop_index("ix_tenants_status", table_name="tenants")
    op.drop_table("tenants")
