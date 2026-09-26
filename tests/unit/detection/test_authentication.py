from datetime import datetime, timedelta

import pytest

from cybersec.detection.authentication import (
    ACCOUNT_LOCKOUT_RULE_ID,
    FAILED_LOGON_BURST_RULE_ID,
    detect_authentication_alerts,
)
from cybersec.domain.events import CanonicalEvent


def make_event(
    *,
    event_code: str,
    occurred_at: datetime,
    record_id: str,
    user_name: str = "alice",
    source_ip: str | None = "10.10.20.15",
    source_host: str | None = "CLIENT-01",
    outcome: str | None = "failure",
) -> CanonicalEvent:
    return CanonicalEvent(
        schema_version="1.0",
        occurred_at=occurred_at,
        event_code=event_code,
        category="authentication",
        action="logon",
        outcome=outcome,
        source_provider="test",
        source_channel="Security",
        source_dataset="unit_test",
        source_record_id=record_id,
        host_name="DC-01",
        user_name=user_name,
        user_domain="TEST",
        user_sid=None,
        source_host=source_host,
        source_ip=source_ip,
        destination_host="DC-01",
        destination_ip=None,
        raw_event="test event",
        attributes={},
    )


def test_account_lockout_creates_alert() -> None:
    event = make_event(
        event_code="4740",
        occurred_at=datetime(2026, 1, 1, 10, 0, 0),
        record_id="100",
        outcome="success",
    )

    alerts = detect_authentication_alerts([event])

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == ACCOUNT_LOCKOUT_RULE_ID
    assert alert.severity == "medium"
    assert alert.user_name == "alice"
    assert alert.evidence_record_ids == ("100",)


def test_five_failed_logons_inside_window_create_alert() -> None:
    start = datetime(2026, 1, 1, 10, 0, 0)

    events = [
        make_event(
            event_code="4625",
            occurred_at=start + timedelta(seconds=index * 30),
            record_id=str(index),
        )
        for index in range(5)
    ]

    alerts = detect_authentication_alerts(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == FAILED_LOGON_BURST_RULE_ID
    assert alert.severity == "high"

    assert len(alert.evidence_record_ids) == 5
    assert alert.mitre_techniques == ("T1110.001",)


def test_failures_outside_window_do_not_alert() -> None:
    start = datetime(2026, 1, 1, 10, 0, 0)

    events = [
        make_event(
            event_code="4625",
            occurred_at=start + timedelta(minutes=index * 2),
            record_id=str(index),
        )
        for index in range(5)
    ]

    alerts = detect_authentication_alerts(events)

    assert alerts == []


def test_different_users_are_not_combined() -> None:
    start = datetime(2026, 1, 1, 10, 0, 0)

    events = [
        make_event(
            event_code="4625",
            occurred_at=start + timedelta(seconds=index),
            record_id=str(index),
            user_name=(
                "alice"
                if index % 2 == 0
                else "bob"
            ),
        )
        for index in range(6)
    ]

    alerts = detect_authentication_alerts(events)

    assert alerts == []


def test_invalid_threshold_is_rejected() -> None:
    with pytest.raises(
        ValueError,
        match="at least 2",
    ):
        detect_authentication_alerts(
            [],
            failed_logon_threshold=1,
        )