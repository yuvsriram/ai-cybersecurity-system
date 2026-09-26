"""create investigation runs

Revision ID: e6f4b2a9c7d1
Revises: c2f4a7b91d03
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "e6f4b2a9c7d1"

down_revision: str | Sequence[str] | None = (
    "c2f4a7b91d03"
)

branch_labels: str | Sequence[str] | None = None

depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "investigation_runs",
        sa.Column(
            "id",
            sa.String(length=36),
            nullable=False,
        ),
        sa.Column(
            "alert_id",
            sa.String(length=36),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "provider",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "model",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "prompt_version",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
        ),
        sa.Column(
            "started_at",
            sa.DateTime(),
            nullable=True,
        ),
        sa.Column(
            "completed_at",
            sa.DateTime(),
            nullable=True,
        ),
        sa.Column(
            "result",
            postgresql.JSONB(
                astext_type=sa.Text()
            ),
            nullable=True,
        ),
        sa.Column(
            "error_message",
            sa.Text(),
            nullable=True,
        ),
        sa.CheckConstraint(
            "status IN "
            "('queued', 'running', 'completed', 'failed')",
            name=(
                "ck_investigation_runs_status"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "id"
        ),
    )

    op.create_index(
        "ix_investigation_runs_alert_id",
        "investigation_runs",
        ["alert_id"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_runs_status",
        "investigation_runs",
        ["status"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_runs_created_at",
        "investigation_runs",
        ["created_at"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_runs_alert_created_at",
        "investigation_runs",
        [
            "alert_id",
            "created_at",
        ],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_investigation_runs_alert_created_at",
        table_name="investigation_runs",
    )

    op.drop_index(
        "ix_investigation_runs_created_at",
        table_name="investigation_runs",
    )

    op.drop_index(
        "ix_investigation_runs_status",
        table_name="investigation_runs",
    )

    op.drop_index(
        "ix_investigation_runs_alert_id",
        table_name="investigation_runs",
    )

    op.drop_table(
        "investigation_runs"
    )