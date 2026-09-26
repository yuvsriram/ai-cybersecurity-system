from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone

from cybersec.domain.alerts import (
    Alert,
    new_alert_id,
)
from cybersec.domain.event_identity import (
    build_event_fingerprint,
)
from cybersec.domain.events import CanonicalEvent


NTLM_PASSWORD_SPRAY_RULE_ID = "AUTH-003"
NTLM_BRUTE_FORCE_RULE_ID = "AUTH-004"

NTLM_EVENT_CODE = "8004"


def detect_ntlm_alerts(
    events: list[CanonicalEvent],
    *,
    spray_user_threshold: int = 20,
    brute_force_event_threshold: int = 20,
    window: timedelta = timedelta(minutes=5),
) -> list[Alert]:
    if spray_user_threshold < 2:
        raise ValueError(
            "spray_user_threshold must be at least 2"
        )

    if brute_force_event_threshold < 2:
        raise ValueError(
            "brute_force_event_threshold must be at least 2"
        )

    if window <= timedelta(0):
        raise ValueError(
            "window must be positive"
        )

    ntlm_events = sorted(
        (
            event
            for event in events
            if event.event_code == NTLM_EVENT_CODE
        ),
        key=lambda event: event.occurred_at,
    )

    alerts: list[Alert] = []

    alerts.extend(
        _detect_password_spray(
            ntlm_events,
            user_threshold=spray_user_threshold,
            window_size=window,
        )
    )

    alerts.extend(
        _detect_same_user_burst(
            ntlm_events,
            event_threshold=brute_force_event_threshold,
            window_size=window,
        )
    )

    alerts.sort(
        key=lambda alert: (
            alert.first_seen_at,
            alert.rule_id,
        )
    )

    return alerts


def _detect_password_spray(
    events: list[CanonicalEvent],
    *,
    user_threshold: int,
    window_size: timedelta,
) -> list[Alert]:
    grouped: dict[
        str,
        list[CanonicalEvent],
    ] = defaultdict(list)

    for event in events:
        if (
            event.source_host is None
            or event.user_name is None
        ):
            continue

        grouped[event.source_host].append(
            event
        )

    alerts: list[Alert] = []

    for source_host, group in grouped.items():
        group.sort(
            key=lambda event: event.occurred_at
        )

        active: deque[CanonicalEvent] = deque()
        user_counts: Counter[str] = Counter()

        alert_active = False

        for event in group:
            cutoff = (
                event.occurred_at
                - window_size
            )

            while (
                active
                and active[0].occurred_at < cutoff
            ):
                expired = active.popleft()

                if expired.user_name is not None:
                    user_counts[
                        expired.user_name
                    ] -= 1

                    if (
                        user_counts[
                            expired.user_name
                        ]
                        <= 0
                    ):
                        del user_counts[
                            expired.user_name
                        ]

            active.append(event)

            if event.user_name is not None:
                user_counts[
                    event.user_name
                ] += 1

            distinct_users = len(
                user_counts
            )

            if distinct_users < user_threshold:
                alert_active = False
                continue

            if alert_active:
                continue

            evidence = list(active)

            alerts.append(
                Alert(
                    id=new_alert_id(),
                    rule_id=(
                        NTLM_PASSWORD_SPRAY_RULE_ID
                    ),
                    rule_version="1.0",
                    title=(
                        "NTLM password-spray "
                        "pattern detected"
                    ),
                    description=(
                        "Observed at least "
                        f"{user_threshold} distinct "
                        "usernames from the same source "
                        "host within "
                        f"{_format_window(window_size)} "
                        "using NTLM authentication "
                        "telemetry."
                    ),
                    severity="high",
                    created_at=_utc_now(),
                    first_seen_at=(
                        evidence[0].occurred_at
                    ),
                    last_seen_at=(
                        evidence[-1].occurred_at
                    ),
                    user_name=None,
                    source_ip=None,
                    source_host=source_host,
                    destination_host=(
                        event.destination_host
                    ),
                    evidence_record_ids=(
                        _record_ids(evidence)
                    ),
                    evidence_event_fingerprints=(
                        _event_fingerprints(
                            evidence
                        )
                    ),
                    evidence_event_codes=tuple(
                        evidence_event.event_code
                        for evidence_event in evidence
                    ),
                    mitre_techniques=(
                        "T1110.003",
                    ),
                )
            )

            alert_active = True

    return alerts


def _detect_same_user_burst(
    events: list[CanonicalEvent],
    *,
    event_threshold: int,
    window_size: timedelta,
) -> list[Alert]:
    grouped: dict[
        tuple[str, str],
        list[CanonicalEvent],
    ] = defaultdict(list)

    for event in events:
        if (
            event.source_host is None
            or event.user_name is None
        ):
            continue

        grouped[
            (
                event.source_host,
                event.user_name,
            )
        ].append(event)

    alerts: list[Alert] = []

    for (
        source_host,
        user_name,
    ), group in grouped.items():
        group.sort(
            key=lambda event: event.occurred_at
        )

        active: deque[CanonicalEvent] = deque()

        alert_active = False

        for event in group:
            cutoff = (
                event.occurred_at
                - window_size
            )

            while (
                active
                and active[0].occurred_at < cutoff
            ):
                active.popleft()

            active.append(event)

            if len(active) < event_threshold:
                alert_active = False
                continue

            if alert_active:
                continue

            evidence = list(active)

            alerts.append(
                Alert(
                    id=new_alert_id(),
                    rule_id=(
                        NTLM_BRUTE_FORCE_RULE_ID
                    ),
                    rule_version="1.0",
                    title=(
                        "Repeated NTLM authentication "
                        "burst detected"
                    ),
                    description=(
                        "Observed at least "
                        f"{event_threshold} NTLM "
                        "authentication events for the "
                        "same user and source host within "
                        f"{_format_window(window_size)}."
                    ),
                    severity="high",
                    created_at=_utc_now(),
                    first_seen_at=(
                        evidence[0].occurred_at
                    ),
                    last_seen_at=(
                        evidence[-1].occurred_at
                    ),
                    user_name=user_name,
                    source_ip=None,
                    source_host=source_host,
                    destination_host=(
                        event.destination_host
                    ),
                    evidence_record_ids=(
                        _record_ids(evidence)
                    ),
                    evidence_event_fingerprints=(
                        _event_fingerprints(
                            evidence
                        )
                    ),
                    evidence_event_codes=tuple(
                        evidence_event.event_code
                        for evidence_event in evidence
                    ),
                    mitre_techniques=(
                        "T1110.001",
                    ),
                )
            )

            alert_active = True

    return alerts


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


def _format_window(
    window: timedelta,
) -> str:
    seconds = int(
        window.total_seconds()
    )

    if seconds % 60 == 0:
        minutes = seconds // 60

        if minutes == 1:
            return "1 minute"

        return f"{minutes} minutes"

    return f"{seconds} seconds"


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )