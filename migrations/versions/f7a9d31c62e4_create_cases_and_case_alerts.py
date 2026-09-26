"""create cases and case alerts

Revision ID: f7a9d31c62e4
Revises: e6f4b2a9c7d1
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "f7a9d31c62e4"

down_revision: str | Sequence[str] | None = (
    "e6f4b2a9c7d1"
)

branch_labels: str | Sequence[str] | None = None

depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column(
            "id",
            sa.String(length=36),
            nullable=False,
        ),
        sa.Column(
            "title",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "summary",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "severity",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "creation_source",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
        ),
        sa.Column(
            "closed_at",
            sa.DateTime(),
            nullable=True,
        ),
        sa.CheckConstraint(
            "status IN "
            "('open', 'investigating', "
            "'resolved', 'closed')",
            name="ck_cases_status",
        ),
        sa.CheckConstraint(
            "severity IN "
            "('low', 'medium', 'high', 'critical')",
            name="ck_cases_severity",
        ),
        sa.PrimaryKeyConstraint(
            "id"
        ),
    )

    op.create_index(
        "ix_cases_status",
        "cases",
        ["status"],
        unique=False,
    )

    op.create_index(
        "ix_cases_severity",
        "cases",
        ["severity"],
        unique=False,
    )

    op.create_index(
        "ix_cases_created_at",
        "cases",
        ["created_at"],
        unique=False,
    )

    op.create_table(
        "case_alerts",
        sa.Column(
            "case_id",
            sa.String(length=36),
            nullable=False,
        ),
        sa.Column(
            "alert_id",
            sa.String(length=36),
            nullable=False,
        ),
        sa.Column(
            "added_at",
            sa.DateTime(),
            nullable=False,
        ),
        sa.Column(
            "correlation_reason",
            sa.String(length=500),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "case_id",
            "alert_id",
        ),
    )

    op.create_index(
        "ix_case_alerts_alert_id",
        "case_alerts",
        ["alert_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_case_alerts_alert_id",
        table_name="case_alerts",
    )

    op.drop_table(
        "case_alerts"
    )

    op.drop_index(
        "ix_cases_created_at",
        table_name="cases",
    )

    op.drop_index(
        "ix_cases_severity",
        table_name="cases",
    )

    op.drop_index(
        "ix_cases_status",
        table_name="cases",
    )

    op.drop_table(
        "cases"
    )