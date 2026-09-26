"""add alert evidence fingerprints

Revision ID: c2f4a7b91d03
Revises: ba49397ea8e6
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "c2f4a7b91d03"
down_revision: str | Sequence[str] | None = (
    "ba49397ea8e6"
)
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "alerts",
        sa.Column(
            "evidence_event_fingerprints",
            postgresql.ARRAY(
                sa.String(length=64)
            ),
            server_default=sa.text(
                "'{}'::character varying[]"
            ),
            nullable=False,
        ),
    )

    op.alter_column(
        "alerts",
        "evidence_event_fingerprints",
        server_default=None,
    )


def downgrade() -> None:
    op.drop_column(
        "alerts",
        "evidence_event_fingerprints",
    )