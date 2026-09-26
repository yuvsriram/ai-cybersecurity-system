from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from cybersec.db.base import Base


class CaseModel(Base):
    __tablename__ = "cases"

    __table_args__ = (
        CheckConstraint(
            "status IN "
            "('open', 'investigating', "
            "'resolved', 'closed')",
            name="ck_cases_status",
        ),
        CheckConstraint(
            "severity IN "
            "('low', 'medium', 'high', 'critical')",
            name="ck_cases_severity",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    creation_source: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        nullable=False,
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        nullable=False,
    )

    closed_at: Mapped[
        datetime | None
    ] = mapped_column(
        nullable=True,
    )


class CaseAlertModel(Base):
    __tablename__ = "case_alerts"

    __table_args__ = (
        Index(
            "ix_case_alerts_alert_id",
            "alert_id",
        ),
    )

    case_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey(
            "cases.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )

    alert_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey(
            "alerts.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )

    added_at: Mapped[datetime] = mapped_column(
        nullable=False,
    )

    correlation_reason: Mapped[
        str | None
    ] = mapped_column(
        String(500),
        nullable=True,
    )