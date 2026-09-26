from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from cybersec.db.base import Base


class AuditEventModel(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(
            timezone.utc
        ),
        index=True,
    )

    actor_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    actor_role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    action: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    resource_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    resource_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    outcome: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    detail: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    attributes: Mapped[
        dict[str, object]
    ] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )