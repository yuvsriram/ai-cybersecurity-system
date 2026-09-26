from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import timedelta
from pathlib import Path

from cybersec.domain.events import CanonicalEvent
from cybersec.ingestion.parsers.windows_xml import parse_file
from cybersec.normalization.ntlm import normalize_ntlm_event


DATASET_PATH = Path(
    "data/raw/splunk/ntlm_bruteforce.log"
)

DATASET_NAME = "splunk_ntlm_bruteforce"

WINDOW = timedelta(minutes=5)


def main() -> None:
    records = parse_file(DATASET_PATH)

    events: list[CanonicalEvent] = []

    for record in records:
        event = normalize_ntlm_event(
            record,
            dataset_name=DATASET_NAME,
        )

        if event is not None:
            events.append(event)

    events.sort(
        key=lambda event: event.occurred_at
    )

    users = Counter(
        event.user_name
        for event in events
        if event.user_name
    )

    source_hosts = Counter(
        event.source_host
        for event in events
        if event.source_host
    )

    destination_hosts = Counter(
        event.destination_host
        for event in events
        if event.destination_host
    )

    print(f"Total NTLM events: {len(events)}")
    print(
        f"Unique users: "
        f"{len(users)}"
    )
    print(
        f"Unique source hosts: "
        f"{len(source_hosts)}"
    )
    print(
        f"Unique destination hosts: "
        f"{len(destination_hosts)}"
    )

    if events:
        print(
            f"First event: "
            f"{events[0].occurred_at.isoformat()}"
        )
        print(
            f"Last event: "
            f"{events[-1].occurred_at.isoformat()}"
        )

    print()
    print("Top users:")

    for user_name, count in users.most_common(10):
        print(
            f"  {user_name}: {count}"
        )

    print()
    print("Top source hosts:")

    for source_host, count in source_hosts.most_common(10):
        print(
            f"  {source_host}: {count}"
        )

    print()
    print("Top destination hosts:")

    for destination_host, count in (
        destination_hosts.most_common(10)
    ):
        print(
            f"  {destination_host}: {count}"
        )

    spray_result = find_max_distinct_users_window(
        events
    )

    print()
    print("Maximum distinct-user activity")
    print("within a 5-minute window:")

    if spray_result is None:
        print("  No usable source-host data")
    else:
        (
            source_host,
            distinct_users,
            event_count,
            first_seen,
            last_seen,
        ) = spray_result

        print(
            f"  source_host: {source_host}"
        )
        print(
            f"  distinct_users: {distinct_users}"
        )
        print(
            f"  total_events: {event_count}"
        )
        print(
            f"  first_seen: "
            f"{first_seen.isoformat()}"
        )
        print(
            f"  last_seen: "
            f"{last_seen.isoformat()}"
        )

    brute_force_result = (
        find_max_same_user_window(
            events
        )
    )

    print()
    print("Maximum same-user activity")
    print("within a 5-minute window:")

    if brute_force_result is None:
        print("  No usable user/source data")
    else:
        (
            source_host,
            user_name,
            event_count,
            first_seen,
            last_seen,
        ) = brute_force_result

        print(
            f"  source_host: {source_host}"
        )
        print(
            f"  user_name: {user_name}"
        )
        print(
            f"  total_events: {event_count}"
        )
        print(
            f"  first_seen: "
            f"{first_seen.isoformat()}"
        )
        print(
            f"  last_seen: "
            f"{last_seen.isoformat()}"
        )


def find_max_distinct_users_window(
    events: list[CanonicalEvent],
) -> tuple[
    str,
    int,
    int,
    object,
    object,
] | None:
    grouped: dict[
        str,
        list[CanonicalEvent],
    ] = defaultdict(list)

    for event in events:
        if (
            event.source_host
            and event.user_name
        ):
            grouped[event.source_host].append(
                event
            )

    best = None

    for source_host, group in grouped.items():
        group.sort(
            key=lambda event: event.occurred_at
        )

        window: deque[CanonicalEvent] = deque()
        user_counts: Counter[str] = Counter()

        for event in group:
            cutoff = (
                event.occurred_at
                - WINDOW
            )

            while (
                window
                and window[0].occurred_at < cutoff
            ):
                expired = window.popleft()

                if expired.user_name:
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

            window.append(event)

            if event.user_name:
                user_counts[event.user_name] += 1

            candidate = (
                source_host,
                len(user_counts),
                len(window),
                window[0].occurred_at,
                window[-1].occurred_at,
            )

            if (
                best is None
                or candidate[1] > best[1]
                or (
                    candidate[1] == best[1]
                    and candidate[2] > best[2]
                )
            ):
                best = candidate

    return best


def find_max_same_user_window(
    events: list[CanonicalEvent],
) -> tuple[
    str,
    str,
    int,
    object,
    object,
] | None:
    grouped: dict[
        tuple[str, str],
        list[CanonicalEvent],
    ] = defaultdict(list)

    for event in events:
        if (
            event.source_host
            and event.user_name
        ):
            grouped[
                (
                    event.source_host,
                    event.user_name,
                )
            ].append(event)

    best = None

    for (
        source_host,
        user_name,
    ), group in grouped.items():
        group.sort(
            key=lambda event: event.occurred_at
        )

        window: deque[CanonicalEvent] = deque()

        for event in group:
            cutoff = (
                event.occurred_at
                - WINDOW
            )

            while (
                window
                and window[0].occurred_at < cutoff
            ):
                window.popleft()

            window.append(event)

            candidate = (
                source_host,
                user_name,
                len(window),
                window[0].occurred_at,
                window[-1].occurred_at,
            )

            if (
                best is None
                or candidate[2] > best[2]
            ):
                best = candidate

    return best


if __name__ == "__main__":
    main()