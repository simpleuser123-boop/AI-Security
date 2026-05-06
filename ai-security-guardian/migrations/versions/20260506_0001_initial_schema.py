"""Initial schema for existing ORM models.

Revision ID: 20260506_0001
Revises:
Create Date: 2026-05-06
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260506_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=False),
        sa.Column("target_ip", sa.String(length=45), nullable=True),
        sa.Column("threat_type", sa.String(length=128), nullable=False),
        sa.Column("level", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("engine", sa.String(length=128), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("raw_payload", sa.Text(), nullable=True),
        sa.Column("model_version", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("external_id", name="uq_alerts_external_id"),
    )
    op.create_index("ix_alerts_external_id", "alerts", ["external_id"], unique=False)
    op.create_index("ix_alerts_status_ts", "alerts", ["status", "timestamp"], unique=False)

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=True),
        sa.Column("resource_type", sa.String(length=64), nullable=True),
        sa.Column("resource_id", sa.String(length=255), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_created", "audit_events", ["created_at"], unique=False)
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"], unique=False)

    op.create_table(
        "banned_ips",
        sa.Column("ip", sa.String(length=45), nullable=False),
        sa.Column("reason", sa.String(length=200), nullable=False),
        sa.Column("operator", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("ip"),
    )

    op.create_table(
        "iocs",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("ioc_type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("sources", sa.JSON(), nullable=True),
        sa.Column("reason", sa.String(length=200), nullable=True),
        sa.Column("note", sa.String(length=400), nullable=True),
        sa.Column("score", sa.Integer(), nullable=True),
        sa.Column("ttl_seconds", sa.Integer(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ioc_meta", sa.JSON(), nullable=True),
        sa.Column("hits", sa.Integer(), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ioc_type", "value", name="uq_iocs_type_value"),
    )
    op.create_index("ix_iocs_expires_at", "iocs", ["expires_at"], unique=False)
    op.create_index("ix_iocs_value", "iocs", ["value"], unique=False)

    op.create_table(
        "model_versions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("artifact_uri", sa.String(length=512), nullable=True),
        sa.Column("checksum", sa.String(length=128), nullable=True),
        sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("version", name="uq_model_versions_version"),
    )

    op.create_table(
        "rules",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("pattern", sa.Text(), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("level", sa.String(length=32), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("description", sa.String(length=400), nullable=True),
        sa.Column("hits", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_rules_enabled_priority", "rules", ["enabled", "priority"], unique=False)

    op.create_table(
        "settings",
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("value", sa.JSON(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )

    op.create_table(
        "alert_histories",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("from_status", sa.String(length=32), nullable=True),
        sa.Column("to_status", sa.String(length=32), nullable=False),
        sa.Column("operator", sa.String(length=128), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_histories_alert_id", "alert_histories", ["alert_id"], unique=False)

    op.create_table(
        "response_actions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.String(length=64), nullable=True),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("dry_run", sa.Boolean(), nullable=False),
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("scheduled_unblock_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_response_actions_alert_id", "response_actions", ["alert_id"], unique=False)

    op.create_table(
        "response_schedule_tasks",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("task_type", sa.String(length=64), nullable=False),
        sa.Column("alert_id", sa.String(length=64), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("related_response_action_id", sa.Integer(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_response_schedule_run", "response_schedule_tasks", ["status", "run_at"], unique=False)
    op.create_index("ix_response_schedule_tasks_alert_id", "response_schedule_tasks", ["alert_id"], unique=False)
    op.create_index("ix_response_schedule_tasks_related_response_action_id", "response_schedule_tasks", ["related_response_action_id"], unique=False)
    op.create_index("ix_response_schedule_tasks_run_at", "response_schedule_tasks", ["run_at"], unique=False)
    op.create_index("ix_response_schedule_tasks_task_type", "response_schedule_tasks", ["task_type"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_response_schedule_tasks_task_type", table_name="response_schedule_tasks")
    op.drop_index("ix_response_schedule_tasks_run_at", table_name="response_schedule_tasks")
    op.drop_index("ix_response_schedule_tasks_related_response_action_id", table_name="response_schedule_tasks")
    op.drop_index("ix_response_schedule_tasks_alert_id", table_name="response_schedule_tasks")
    op.drop_index("ix_response_schedule_run", table_name="response_schedule_tasks")
    op.drop_table("response_schedule_tasks")
    op.drop_index("ix_response_actions_alert_id", table_name="response_actions")
    op.drop_table("response_actions")
    op.drop_index("ix_alert_histories_alert_id", table_name="alert_histories")
    op.drop_table("alert_histories")
    op.drop_table("settings")
    op.drop_index("ix_rules_enabled_priority", table_name="rules")
    op.drop_table("rules")
    op.drop_table("model_versions")
    op.drop_index("ix_iocs_value", table_name="iocs")
    op.drop_index("ix_iocs_expires_at", table_name="iocs")
    op.drop_table("iocs")
    op.drop_table("banned_ips")
    op.drop_index("ix_audit_events_event_type", table_name="audit_events")
    op.drop_index("ix_audit_created", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index("ix_alerts_status_ts", table_name="alerts")
    op.drop_index("ix_alerts_external_id", table_name="alerts")
    op.drop_table("alerts")
