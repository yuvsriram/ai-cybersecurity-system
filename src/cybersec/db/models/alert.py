from __future__ import annotations

from datetime import datetime

from sqlalchemy import String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from cybersec.db.base import Base


class AlertModel(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
    )

    dedupe_key: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
    )

    rule_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    rule_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        nullable=False,
        index=True,
    )

    first_seen_at: Mapped[datetime] = mapped_column(
        nullable=False,
    )

    last_seen_at: Mapped[datetime] = mapped_column(
        nullable=False,
    )

    user_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    source_host: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    destination_host: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    evidence_record_ids: Mapped[list[str]] = mapped_column(
        ARRAY(String(255)),
        nullable=False,
        default=list,
    )

    evidence_event_fingerprints: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)),
        nullable=False,
        default=list,
    )

    evidence_event_codes: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)),
        nullable=False,
        default=list,
    )

    mitre_techniques: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)),
        nullable=False,
        default=list,
    )