"""Phase C6 real response controlled release models.

Revision ID: 20260507_0004
Revises: 20260507_0003
Create Date: 2026-05-07
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260507_0004"
down_revision = "20260507_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "response_provider_configs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("provider_type", sa.String(length=64), nullable=False),
        sa.Column("provider_name", sa.String(length=128), nullable=False),
        sa.Column("environment", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("config_ref", sa.String(length=512), nullable=True),
        sa.Column("credential_ref", sa.String(length=512), nullable=True),
        sa.Column("secret_fingerprint", sa.String(length=128), nullable=True),
        sa.Column("config_metadata", sa.JSON(), nullable=True),
        sa.Column("capabilities", sa.JSON(), nullable=True),
        sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_validation_result", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("updated_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "provider_type IN ('iptables', 'cloud_security_group', 'edr')",
            name="ck_response_provider_configs_type",
        ),
        sa.CheckConstraint(
            "status IN ('draft', 'active', 'disabled', 'validation_failed', 'revoked')",
            name="ck_response_provider_configs_status",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "provider_type",
            "provider_name",
            "environment",
            name="uq_response_provider_tenant_type_name_env",
        ),
    )
    op.create_index(
        "ix_response_provider_lookup",
        "response_provider_configs",
        ["tenant_id", "provider_type", "environment"],
        unique=False,
    )
    op.create_index(
        "ix_response_provider_tenant_status",
        "response_provider_configs",
        ["tenant_id", "status"],
        unique=False,
    )
    op.create_index(
        "ix_response_provider_configs_tenant_id",
        "response_provider_configs",
        ["tenant_id"],
        unique=False,
    )

    op.create_table(
        "response_approvals",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("alert_id", sa.String(length=64), nullable=True),
        sa.Column("response_action_id", sa.Integer(), nullable=True),
        sa.Column("provider_config_id", sa.Integer(), nullable=True),
        sa.Column("gate_id", sa.String(length=128), nullable=True),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=False),
        sa.Column("provider", sa.String(length=80), nullable=True),
        sa.Column("ttl_seconds", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("requested_by", sa.String(length=128), nullable=False),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejected_by", sa.String(length=128), nullable=True),
        sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("executed_by", sa.String(length=128), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by", sa.String(length=128), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("rollback_plan", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "action_type IN ('ban_ip', 'unban_ip', 'isolate_host', 'release_host', "
            "'cloud_security_group_block', 'cloud_security_group_unblock')",
            name="ck_response_approvals_action_type",
        ),
        sa.CheckConstraint(
            "target_type IN ('ip', 'cidr', 'asset', 'host', 'security_group_rule', 'tag')",
            name="ck_response_approvals_target_type",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'executing', 'executed', "
            "'failed', 'cancelled', 'expired', 'reviewed')",
            name="ck_response_approvals_status",
        ),
        sa.CheckConstraint(
            "ttl_seconds IS NULL OR ttl_seconds > 0",
            name="ck_response_approvals_ttl",
        ),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["provider_config_id"], ["response_provider_configs.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["response_action_id"], ["response_actions.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_response_approvals_action",
        "response_approvals",
        ["tenant_id", "response_action_id"],
        unique=False,
    )
    op.create_index(
        "ix_response_approvals_alert",
        "response_approvals",
        ["tenant_id", "alert_id"],
        unique=False,
    )
    op.create_index(
        "ix_response_approvals_tenant_status",
        "response_approvals",
        ["tenant_id", "status"],
        unique=False,
    )
    op.create_index(
        "ix_response_approvals_tenant_target",
        "response_approvals",
        ["tenant_id", "target_type", "target"],
        unique=False,
    )
    op.create_index("ix_response_approvals_tenant_id", "response_approvals", ["tenant_id"], unique=False)

    op.create_table(
        "response_whitelist_entries",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("scope", sa.String(length=32), nullable=False),
        sa.Column("value_type", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("environment", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("owner", sa.String(length=128), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "scope IN ('business', 'private', 'control_plane', 'office', 'monitoring')",
            name="ck_response_whitelist_scope",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'active', 'disabled', 'expired')",
            name="ck_response_whitelist_status",
        ),
        sa.CheckConstraint(
            "value_type IN ('ip', 'cidr', 'asset', 'tag')",
            name="ck_response_whitelist_value_type",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "scope",
            "value_type",
            "value",
            "environment",
            name="uq_response_whitelist_tenant_scope_value_env",
        ),
    )
    op.create_index(
        "ix_response_whitelist_expires",
        "response_whitelist_entries",
        ["tenant_id", "expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_response_whitelist_lookup",
        "response_whitelist_entries",
        ["tenant_id", "value_type", "value", "status"],
        unique=False,
    )
    op.create_index(
        "ix_response_whitelist_tenant_status",
        "response_whitelist_entries",
        ["tenant_id", "status"],
        unique=False,
    )
    op.create_index(
        "ix_response_whitelist_entries_tenant_id",
        "response_whitelist_entries",
        ["tenant_id"],
        unique=False,
    )

    op.create_table(
        "response_drills",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("provider_config_id", sa.Integer(), nullable=True),
        sa.Column("response_action_id", sa.Integer(), nullable=True),
        sa.Column("approval_id", sa.Integer(), nullable=True),
        sa.Column("environment", sa.String(length=64), nullable=False),
        sa.Column("drill_type", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rto_seconds", sa.Integer(), nullable=True),
        sa.Column("result", sa.Text(), nullable=True),
        sa.Column("participants", sa.JSON(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "drill_type IN ('dry_run_ban_unblock', 'real_ban_unblock', "
            "'edr_isolate_release', 'provider_rollback', 'misblock_recovery')",
            name="ck_response_drills_type",
        ),
        sa.CheckConstraint(
            "rto_seconds IS NULL OR rto_seconds >= 0",
            name="ck_response_drills_rto",
        ),
        sa.CheckConstraint(
            "status IN ('planned', 'running', 'passed', 'failed', 'cancelled')",
            name="ck_response_drills_status",
        ),
        sa.CheckConstraint(
            "target_type IN ('ip', 'cidr', 'asset', 'host', 'security_group_rule', 'tag')",
            name="ck_response_drills_target_type",
        ),
        sa.ForeignKeyConstraint(["approval_id"], ["response_approvals.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["provider_config_id"], ["response_provider_configs.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["response_action_id"], ["response_actions.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_response_drills_action",
        "response_drills",
        ["tenant_id", "response_action_id"],
        unique=False,
    )
    op.create_index(
        "ix_response_drills_tenant_env",
        "response_drills",
        ["tenant_id", "environment", "started_at"],
        unique=False,
    )
    op.create_index(
        "ix_response_drills_tenant_status",
        "response_drills",
        ["tenant_id", "status"],
        unique=False,
    )
    op.create_index("ix_response_drills_tenant_id", "response_drills", ["tenant_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_response_drills_tenant_id", table_name="response_drills")
    op.drop_index("ix_response_drills_tenant_status", table_name="response_drills")
    op.drop_index("ix_response_drills_tenant_env", table_name="response_drills")
    op.drop_index("ix_response_drills_action", table_name="response_drills")
    op.drop_table("response_drills")

    op.drop_index(
        "ix_response_whitelist_entries_tenant_id",
        table_name="response_whitelist_entries",
    )
    op.drop_index("ix_response_whitelist_tenant_status", table_name="response_whitelist_entries")
    op.drop_index("ix_response_whitelist_lookup", table_name="response_whitelist_entries")
    op.drop_index("ix_response_whitelist_expires", table_name="response_whitelist_entries")
    op.drop_table("response_whitelist_entries")

    op.drop_index("ix_response_approvals_tenant_id", table_name="response_approvals")
    op.drop_index("ix_response_approvals_tenant_target", table_name="response_approvals")
    op.drop_index("ix_response_approvals_tenant_status", table_name="response_approvals")
    op.drop_index("ix_response_approvals_alert", table_name="response_approvals")
    op.drop_index("ix_response_approvals_action", table_name="response_approvals")
    op.drop_table("response_approvals")

    op.drop_index("ix_response_provider_configs_tenant_id", table_name="response_provider_configs")
    op.drop_index("ix_response_provider_tenant_status", table_name="response_provider_configs")
    op.drop_index("ix_response_provider_lookup", table_name="response_provider_configs")
    op.drop_table("response_provider_configs")
