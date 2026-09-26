from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from cybersec.db.models.event import EventModel


@dataclass(
    frozen=True,
    slots=True,
)
class AuthenticationFeatureVector:
    window_start: datetime
    window_end: datetime

    source_host: str | None
    source_ip: str | None

    event_count: int
    distinct_user_count: int
    distinct_destination_count: int

    failed_count: int
    success_count: int
    unknown_outcome_count: int

    event_4625_count: int
    event_4740_count: int
    event_8004_count: int

    events_per_second: float


def build_authentication_feature_vectors(
    events: Iterable[EventModel],
    *,
    window_seconds: int = 300,
) -> list[AuthenticationFeatureVector]:
    if window_seconds <= 0:
        raise ValueError(
            "window_seconds must be positive"
        )

    authentication_events = sorted(
        (
            event
            for event in events
            if event.category
            == "authentication"
        ),
        key=lambda event: (
            event.occurred_at,
            event.id,
        ),
    )

    grouped: dict[
        tuple[str | None, str | None],
        list[EventModel],
    ] = defaultdict(list)

    for event in authentication_events:
        grouped[
            (
                event.source_host,
                event.source_ip,
            )
        ].append(event)

    vectors: list[
        AuthenticationFeatureVector
    ] = []

    for (
        source_host,
        source_ip,
    ), source_events in grouped.items():
        if not source_events:
            continue

        origin = (
            source_events[0]
            .occurred_at
        )

        buckets: dict[
            int,
            list[EventModel],
        ] = defaultdict(list)

        for event in source_events:
            elapsed_seconds = (
                event.occurred_at
                - origin
            ).total_seconds()

            bucket_index = int(
                elapsed_seconds
                // window_seconds
            )

            buckets[
                bucket_index
            ].append(event)

        for bucket_index in sorted(
            buckets
        ):
            window_start = (
                origin
                + timedelta(
                    seconds=(
                        bucket_index
                        * window_seconds
                    )
                )
            )

            vectors.append(
                _build_vector(
                    buckets[
                        bucket_index
                    ],
                    window_start=(
                        window_start
                    ),
                    window_seconds=(
                        window_seconds
                    ),
                    source_host=(
                        source_host
                    ),
                    source_ip=(
                        source_ip
                    ),
                )
            )

    vectors.sort(
        key=lambda vector: (
            vector.window_start,
            vector.source_host or "",
            vector.source_ip or "",
        )
    )

    return vectors


def feature_vector_to_numeric(
    vector: AuthenticationFeatureVector,
) -> list[float]:
    return [
        float(vector.event_count),
        float(
            vector.distinct_user_count
        ),
        float(
            vector.distinct_destination_count
        ),
        float(vector.failed_count),
        float(vector.success_count),
        float(
            vector.unknown_outcome_count
        ),
        float(vector.event_4625_count),
        float(vector.event_4740_count),
        float(vector.event_8004_count),
        vector.events_per_second,
    ]


def feature_names() -> list[str]:
    return [
        "event_count",
        "distinct_user_count",
        "distinct_destination_count",
        "failed_count",
        "success_count",
        "unknown_outcome_count",
        "event_4625_count",
        "event_4740_count",
        "event_8004_count",
        "events_per_second",
    ]


def _build_vector(
    events: list[EventModel],
    *,
    window_start: datetime,
    window_seconds: int,
    source_host: str | None,
    source_ip: str | None,
) -> AuthenticationFeatureVector:
    users = {
        event.user_name
        for event in events
        if event.user_name
    }

    destinations = {
        value
        for event in events
        for value in (
            event.destination_host,
            event.destination_ip,
        )
        if value
    }

    failed_count = sum(
        1
        for event in events
        if event.outcome == "failure"
    )

    success_count = sum(
        1
        for event in events
        if event.outcome == "success"
    )

    unknown_outcome_count = sum(
        1
        for event in events
        if event.outcome is None
    )

    event_4625_count = sum(
        1
        for event in events
        if event.event_code == "4625"
    )

    event_4740_count = sum(
        1
        for event in events
        if event.event_code == "4740"
    )

    event_8004_count = sum(
        1
        for event in events
        if event.event_code == "8004"
    )

    return AuthenticationFeatureVector(
        window_start=window_start,
        window_end=(
            window_start
            + timedelta(
                seconds=window_seconds
            )
        ),
        source_host=source_host,
        source_ip=source_ip,
        event_count=len(events),
        distinct_user_count=(
            len(users)
        ),
        distinct_destination_count=(
            len(destinations)
        ),
        failed_count=failed_count,
        success_count=success_count,
        unknown_outcome_count=(
            unknown_outcome_count
        ),
        event_4625_count=(
            event_4625_count
        ),
        event_4740_count=(
            event_4740_count
        ),
        event_8004_count=(
            event_8004_count
        ),
        events_per_second=(
            len(events)
            / float(window_seconds)
        ),
    )