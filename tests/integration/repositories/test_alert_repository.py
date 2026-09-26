from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from cybersec.db.repositories.alerts import (
    AlertRepository,
)
from cybersec.domain.alerts import Alert


def _make_alert(
    *,
    alert_id: str,
) -> Alert:
    occurred_at = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
    )

    return Alert(
        id=alert_id,
        rule_id="TEST-001",
        rule_version="1.0",
        title="Repository test alert",
        description=(
            "Alert repository integration test"
        ),
        severity="medium",
        created_at=occurred_at,
        first_seen_at=occurred_at,
        last_seen_at=occurred_at,
        user_name="repository-user",
        source_ip="192.0.2.10",
        source_host="SOURCE-HOST",
        destination_host="DESTINATION-HOST",
        evidence_record_ids=(
            "record-001",
        ),
        evidence_event_fingerprints=(
            "a" * 64,
        ),
        evidence_event_codes=(
            "9999",
        ),
        mitre_techniques=(),
    )


def test_add_many_returning_ids_returns_only_new_alerts(
    db_session: Session,
) -> None:
    repository = AlertRepository(
        db_session
    )

    alert = _make_alert(
        alert_id=(
            "00000000-0000-0000-"
            "0000-000000000401"
        )
    )

    first_insert = (
        repository
        .add_many_returning_ids(
            [alert]
        )
    )

    second_insert = (
        repository
        .add_many_returning_ids(
            [alert]
        )
    )

    assert first_insert == [
        alert.id
    ]

    assert second_insert == []