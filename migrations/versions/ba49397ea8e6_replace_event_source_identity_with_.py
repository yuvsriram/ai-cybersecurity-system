"""replace event source identity with fingerprint

Revision ID: ba49397ea8e6
Revises: 918c2c0ef316
Create Date: 2026-09-23 12:33:00.436090
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "ba49397ea8e6"
down_revision: str | Sequence[str] | None = "918c2c0ef316"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "security_events",
        sa.Column(
            "event_fingerprint",
            sa.String(length=64),
            nullable=True,
        ),
    )

    connection = op.get_bind()

    rows = connection.execute(
        sa.text(
            """
            SELECT
                id,
                source_dataset,
                raw_event
            FROM security_events
            ORDER BY id
            """
        )
    ).mappings()

    for row in rows:
        payload = "\x1f".join(
            (
                row["source_dataset"] or "",
                row["raw_event"],
            )
        )

        fingerprint = hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()

        connection.execute(
            sa.text(
                """
                UPDATE security_events
                SET event_fingerprint = :fingerprint
                WHERE id = :event_id
                """
            ),
            {
                "fingerprint": fingerprint,
                "event_id": row["id"],
            },
        )

    missing_fingerprints = connection.execute(
        sa.text(
            """
            SELECT COUNT(*)
            FROM security_events
            WHERE event_fingerprint IS NULL
            """
        )
    ).scalar_one()

    if missing_fingerprints != 0:
        raise RuntimeError(
            "Failed to backfill all event fingerprints"
        )

    duplicate_fingerprints = connection.execute(
        sa.text(
            """
            SELECT COUNT(*)
            FROM (
                SELECT event_fingerprint
                FROM security_events
                GROUP BY event_fingerprint
                HAVING COUNT(*) > 1
            ) AS duplicate_groups
            """
        )
    ).scalar_one()

    if duplicate_fingerprints != 0:
        raise RuntimeError(
            "Existing security events contain duplicate "
            "fingerprints"
        )

    op.alter_column(
        "security_events",
        "event_fingerprint",
        existing_type=sa.String(length=64),
        nullable=False,
    )

    op.drop_constraint(
        "uq_security_events_source_identity",
        "security_events",
        type_="unique",
    )

    op.create_unique_constraint(
        "uq_security_events_event_fingerprint",
        "security_events",
        ["event_fingerprint"],
    )


def downgrade() -> None:
    connection = op.get_bind()

    conflicting_source_identities = connection.execute(
        sa.text(
            """
            SELECT COUNT(*)
            FROM (
                SELECT
                    source_dataset,
                    source_channel,
                    host_name,
                    source_record_id
                FROM security_events
                WHERE
                    source_dataset IS NOT NULL
                    AND source_channel IS NOT NULL
                    AND host_name IS NOT NULL
                    AND source_record_id IS NOT NULL
                GROUP BY
                    source_dataset,
                    source_channel,
                    host_name,
                    source_record_id
                HAVING COUNT(*) > 1
            ) AS conflicts
            """
        )
    ).scalar_one()

    if conflicting_source_identities != 0:
        raise RuntimeError(
            "Cannot downgrade because current event data "
            "contains source-identity collisions that the "
            "previous uniqueness constraint cannot represent"
        )

    op.drop_constraint(
        "uq_security_events_event_fingerprint",
        "security_events",
        type_="unique",
    )

    op.create_unique_constraint(
        "uq_security_events_source_identity",
        "security_events",
        [
            "source_dataset",
            "source_channel",
            "host_name",
            "source_record_id",
        ],
    )

    op.drop_column(
        "security_events",
        "event_fingerprint",
    )