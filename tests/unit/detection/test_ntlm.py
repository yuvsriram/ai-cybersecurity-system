from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cybersec.detection.ntlm import (
    NTLM_BRUTE_FORCE_RULE_ID,
    NTLM_PASSWORD_SPRAY_RULE_ID,
    detect_ntlm_alerts,
)
from cybersec.domain.events import CanonicalEvent


BASE_TIME = datetime(
    2024,
    1,
    18,
    12,
    0,
    0,
    tzinfo=timezone.utc,
)


def make_ntlm_event(
    *,
    seconds: int,
    user_name: str,
    source_host: str = "ATTACKER",
    record_id: str,
) -> CanonicalEvent:
    return CanonicalEvent(
        schema_version="1.0",
        occurred_at=(
            BASE_TIME
            + timedelta(seconds=seconds)
        ),
        event_code="8004",
        category="authentication",
        action="ntlm_authentication",
        outcome=None,
        source_provider=(
            "Microsoft-Windows-Security-Netlogon"
        ),
        source_channel=(
            "Microsoft-Windows-NTLM/Operational"
        ),
        source_dataset="ntlm_test",
        source_record_id=record_id,
        host_name="DC-01",
        user_name=user_name,
        user_domain="TEST",
        user_sid=None,
        source_host=source_host,
        source_ip=None,
        destination_host="VICTIM-PC",
        destination_ip=None,
        raw_event=(
            f"<Event>{record_id}</Event>"
        ),
        attributes={},
    )


def test_password_spray_creates_alert() -> None:
    events = [
        make_ntlm_event(
            seconds=index * 10,
            user_name=f"user-{index}",
            record_id=str(index),
        )
        for index in range(5)
    ]

    alerts = detect_ntlm_alerts(
        events,
        spray_user_threshold=5,
        brute_force_event_threshold=10,
    )

    spray_alerts = [
        alert
        for alert in alerts
        if (
            alert.rule_id
            == NTLM_PASSWORD_SPRAY_RULE_ID
        )
    ]

    assert len(spray_alerts) == 1

    alert = spray_alerts[0]

    assert alert.source_host == "ATTACKER"
    assert alert.user_name is None

    assert alert.mitre_techniques == (
        "T1110.003",
    )

    assert len(
        alert.evidence_record_ids
    ) == 5


def test_same_user_burst_creates_alert() -> None:
    events = [
        make_ntlm_event(
            seconds=index * 10,
            user_name="backup",
            record_id=str(index),
        )
        for index in range(5)
    ]

    alerts = detect_ntlm_alerts(
        events,
        spray_user_threshold=10,
        brute_force_event_threshold=5,
    )

    burst_alerts = [
        alert
        for alert in alerts
        if (
            alert.rule_id
            == NTLM_BRUTE_FORCE_RULE_ID
        )
    ]

    assert len(burst_alerts) == 1

    alert = burst_alerts[0]

    assert alert.source_host == "ATTACKER"
    assert alert.user_name == "backup"

    assert alert.mitre_techniques == (
        "T1110.001",
    )

    assert len(
        alert.evidence_record_ids
    ) == 5


def test_events_outside_window_do_not_alert() -> None:
    events = [
        make_ntlm_event(
            seconds=index * 400,
            user_name=f"user-{index}",
            record_id=str(index),
        )
        for index in range(5)
    ]

    alerts = detect_ntlm_alerts(
        events,
        spray_user_threshold=5,
        brute_force_event_threshold=5,
        window=timedelta(minutes=5),
    )

    assert alerts == []


def test_different_sources_are_not_combined() -> None:
    events = [
        make_ntlm_event(
            seconds=0,
            user_name="user-1",
            source_host="HOST-A",
            record_id="1",
        ),
        make_ntlm_event(
            seconds=10,
            user_name="user-2",
            source_host="HOST-A",
            record_id="2",
        ),
        make_ntlm_event(
            seconds=20,
            user_name="user-3",
            source_host="HOST-B",
            record_id="3",
        ),
        make_ntlm_event(
            seconds=30,
            user_name="user-4",
            source_host="HOST-B",
            record_id="4",
        ),
    ]

    alerts = detect_ntlm_alerts(
        events,
        spray_user_threshold=4,
        brute_force_event_threshold=10,
    )

    assert alerts == []


def test_non_ntlm_events_are_ignored() -> None:
    event = CanonicalEvent(
        schema_version="1.0",
        occurred_at=BASE_TIME,
        event_code="4625",
        category="authentication",
        action="logon",
        outcome="failure",
        source_provider="pytest",
        source_channel="Security",
        source_dataset="test",
        source_record_id="1",
        host_name="HOST",
        user_name="user",
        user_domain="TEST",
        user_sid=None,
        source_host="ATTACKER",
        source_ip=None,
        destination_host="VICTIM",
        destination_ip=None,
        raw_event="test",
        attributes={},
    )

    alerts = detect_ntlm_alerts(
        [event],
        spray_user_threshold=2,
        brute_force_event_threshold=2,
    )

    assert alerts == []


def test_invalid_spray_threshold_is_rejected() -> None:
    with pytest.raises(ValueError):
        detect_ntlm_alerts(
            [],
            spray_user_threshold=1,
        )


def test_invalid_brute_force_threshold_is_rejected() -> None:
    with pytest.raises(ValueError):
        detect_ntlm_alerts(
            [],
            brute_force_event_threshold=1,
        )


def test_invalid_window_is_rejected() -> None:
    with pytest.raises(ValueError):
        detect_ntlm_alerts(
            [],
            window=timedelta(0),
        )