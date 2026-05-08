"""Require scheduled unblock timestamp for real executed bans.

Revision ID: 20260507_0005
Revises: 20260507_0004
Create Date: 2026-05-07
"""
from __future__ import annotations

from alembic import op

revision = "20260507_0005"
down_revision = "20260507_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("response_actions") as batch_op:
        batch_op.create_check_constraint(
            "ck_response_actions_real_ban_has_unblock_at",
            "dry_run OR action_type != 'ban_ip' OR status != 'executed' "
            "OR scheduled_unblock_at IS NOT NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("response_actions") as batch_op:
        batch_op.drop_constraint(
            "ck_response_actions_real_ban_has_unblock_at",
            type_="check",
        )
