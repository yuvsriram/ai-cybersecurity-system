"""add persistence deduplication

Revision ID: 4a89e6322e50
Revises: 1c1e8aa9d19a
Create Date: 2026-09-22 14:31:44.488397

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
revision: str = '4a89e6322e50'
down_revision: Union[str, Sequence[str], None] = '1c1e8aa9d19a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('alerts', sa.Column('dedupe_key', sa.String(length=64), nullable=False))
    op.create_unique_constraint(None, 'alerts', ['dedupe_key'])
    op.create_unique_constraint('uq_security_events_source_record', 'security_events', ['source_dataset', 'source_record_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint('uq_security_events_source_record', 'security_events', type_='unique')
    op.drop_constraint(None, 'alerts', type_='unique')
    op.drop_column('alerts', 'dedupe_key')
