from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "a8c4f09b7e21"
down_revision = "f7a9d31c62e4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column(
            "id",
            sa.Integer(),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=False,
        ),
        sa.Column(
            "actor_name",
            sa.String(
                length=255
            ),
            nullable=False,
        ),
        sa.Column(
            "actor_role",
            sa.String(
                length=32
            ),
            nullable=False,
        ),
        sa.Column(
            "action",
            sa.String(
                length=255
            ),
            nullable=False,
        ),
        sa.Column(
            "resource_type",
            sa.String(
                length=64
            ),
            nullable=False,
        ),
        sa.Column(
            "resource_id",
            sa.String(
                length=255
            ),
            nullable=True,
        ),
        sa.Column(
            "outcome",
            sa.String(
                length=32
            ),
            nullable=False,
        ),
        sa.Column(
            "detail",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "attributes",
            postgresql.JSONB(
                astext_type=sa.Text()
            ),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint(
            "id"
        ),
    )

    op.create_index(
        "ix_audit_events_created_at",
        "audit_events",
        ["created_at"],
    )

    op.create_index(
        "ix_audit_events_actor_name",
        "audit_events",
        ["actor_name"],
    )

    op.create_index(
        "ix_audit_events_action",
        "audit_events",
        ["action"],
    )

    op.create_index(
        "ix_audit_events_resource_type",
        "audit_events",
        ["resource_type"],
    )

    op.create_index(
        "ix_audit_events_resource_id",
        "audit_events",
        ["resource_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_audit_events_resource_id",
        table_name="audit_events",
    )

    op.drop_index(
        "ix_audit_events_resource_type",
        table_name="audit_events",
    )

    op.drop_index(
        "ix_audit_events_action",
        table_name="audit_events",
    )

    op.drop_index(
        "ix_audit_events_actor_name",
        table_name="audit_events",
    )

    op.drop_index(
        "ix_audit_events_created_at",
        table_name="audit_events",
    )

    op.drop_table(
        "audit_events"
    )