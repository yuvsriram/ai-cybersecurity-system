from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from cybersec.domain.alerts import (
    Alert,
    new_alert_id,
)
from cybersec.domain.event_identity import (
    build_event_fingerprint,
)
from cybersec.domain.events import CanonicalEvent


ACCOUNT_LOCKOUT_RULE_ID = "AUTH-001"
FAILED_LOGON_BURST_RULE_ID = "AUTH-002"


def detect_authentication_alerts(
    events: list[CanonicalEvent],
    *,
    failed_logon_threshold: int = 5,
    failed_logon_window: timedelta = timedelta(
        minutes=5
    ),
) -> list[Alert]:
    if failed_logon_threshold < 2:
        raise ValueError(
            "failed_logon_threshold must be at least 2"
        )

    if failed_logon_window <= timedelta(0):
        raise ValueError(
            "failed_logon_window must be positive"
        )

    ordered_events = sorted(
        events,
        key=lambda event: event.occurred_at,
    )

    alerts: list[Alert] = []

    failed_logon_groups: dict[
        tuple[str, str],
        deque[CanonicalEvent],
    ] = defaultdict(deque)

    for event in ordered_events:
        if event.event_code == "4740":
            alerts.append(
                _build_account_lockout_alert(event)
            )

        if event.event_code != "4625":
            continue

        if event.user_name is None:
            continue

        source = (
            event.source_ip
            or event.source_host
        )

        if source is None:
            continue

        group_key = (
            event.user_name,
            source,
        )

        active = failed_logon_groups[
            group_key
        ]

        cutoff = (
            event.occurred_at
            - failed_logon_window
        )

        while (
            active
            and active[0].occurred_at < cutoff
        ):
            active.popleft()

        active.append(event)

        if len(active) == failed_logon_threshold:
            evidence = list(active)

            alerts.append(
                _build_failed_logon_alert(
                    evidence
                )
            )

    alerts.sort(
        key=lambda alert: (
            alert.first_seen_at,
            alert.rule_id,
        )
    )

    return alerts


def _build_account_lockout_alert(
    event: CanonicalEvent,
) -> Alert:
    return Alert(
        id=new_alert_id(),
        rule_id=ACCOUNT_LOCKOUT_RULE_ID,
        rule_version="1.0",
        title="User account locked out",
        description=(
            "Windows reported that a user account "
            "was locked out."
        ),
        severity="medium",
        created_at=_utc_now(),
        first_seen_at=event.occurred_at,
        last_seen_at=event.occurred_at,
        user_name=event.user_name,
        source_ip=event.source_ip,
        source_host=event.source_host,
        destination_host=event.destination_host,
        evidence_record_ids=_record_ids(
            [event]
        ),
        evidence_event_fingerprints=(
            _event_fingerprints(
                [event]
            )
        ),
        evidence_event_codes=(
            event.event_code,
        ),
        mitre_techniques=(),
    )


def _build_failed_logon_alert(
    evidence: list[CanonicalEvent],
) -> Alert:
    first = evidence[0]
    last = evidence[-1]

    return Alert(
        id=new_alert_id(),
        rule_id=FAILED_LOGON_BURST_RULE_ID,
        rule_version="1.0",
        title="Repeated failed logons detected",
        description=(
            f"Detected {len(evidence)} failed logons "
            "for the same user and source within "
            "the configured time window."
        ),
        severity="high",
        created_at=_utc_now(),
        first_seen_at=first.occurred_at,
        last_seen_at=last.occurred_at,
        user_name=last.user_name,
        source_ip=last.source_ip,
        source_host=last.source_host,
        destination_host=last.destination_host,
        evidence_record_ids=_record_ids(
            evidence
        ),
        evidence_event_fingerprints=(
            _event_fingerprints(
                evidence
            )
        ),
        evidence_event_codes=tuple(
            event.event_code
            for event in evidence
        ),
        mitre_techniques=(
            "T1110.001",
        ),
    )


def _record_ids(
    events: list[CanonicalEvent],
) -> tuple[str, ...]:
    return tuple(
        event.source_record_id
        for event in events
        if event.source_record_id is not None
    )


def _event_fingerprints(
    events: list[CanonicalEvent],
) -> tuple[str, ...]:
    return tuple(
        build_event_fingerprint(
            source_dataset=event.source_dataset,
            raw_event=event.raw_event,
        )
        for event in events
    )


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )