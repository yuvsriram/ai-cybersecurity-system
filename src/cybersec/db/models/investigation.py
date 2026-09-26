from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from cybersec.db.base import Base


class InvestigationRunModel(Base):
    __tablename__ = "investigation_runs"

    __table_args__ = (
        CheckConstraint(
            "status IN "
            "('queued', 'running', 'completed', 'failed')",
            name=(
                "ck_investigation_runs_status"
            ),
        ),
        Index(
            "ix_investigation_runs_alert_created_at",
            "alert_id",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
    )

    alert_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey(
            "alerts.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    provider: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    model: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    prompt_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        nullable=False,
        index=True,
    )

    started_at: Mapped[
        datetime | None
    ] = mapped_column(
        nullable=True,
    )

    completed_at: Mapped[
        datetime | None
    ] = mapped_column(
        nullable=True,
    )

    result: Mapped[
        dict | None
    ] = mapped_column(
        JSONB,
        nullable=True,
    )

    error_message: Mapped[
        str | None
    ] = mapped_column(
        Text,
        nullable=True,
    )