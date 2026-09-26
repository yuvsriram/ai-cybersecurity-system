from __future__ import annotations

from datetime import datetime

from sqlalchemy import String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from cybersec.db.base import Base


class EventModel(Base):
    __tablename__ = "security_events"

    __table_args__ = (
        UniqueConstraint(
            "event_fingerprint",
            name="uq_security_events_event_fingerprint",
        ),
    )

    id: Mapped[int] = mapped_column(
        primary_key=True,
    )

    event_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    schema_version: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    occurred_at: Mapped[datetime] = mapped_column(
        nullable=False,
        index=True,
    )

    event_code: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    category: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    outcome: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    source_provider: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    source_channel: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    source_dataset: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    source_record_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    host_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    user_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    user_domain: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    user_sid: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    source_host: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    destination_host: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    destination_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    raw_event: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    attributes: Mapped[dict[str, str]] = mapped_column(
        JSONB,
        nullable=False,
    )