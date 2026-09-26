from __future__ import annotations

from pathlib import Path

from cybersec.db.repositories.alerts import AlertRepository
from cybersec.db.repositories.events import EventRepository
from cybersec.db.session import create_session
from cybersec.detection.ntlm import (
    detect_ntlm_alerts,
)
from cybersec.ingestion.parsers.windows_xml import (
    parse_file,
)
from cybersec.normalization.ntlm import (
    normalize_ntlm_event,
)


DATASET_PATH = Path(
    "data/raw/splunk/ntlm_bruteforce.log"
)

DATASET_NAME = "splunk_ntlm_bruteforce"


def main() -> None:
    records = parse_file(
        DATASET_PATH
    )

    events = []

    for record in records:
        event = normalize_ntlm_event(
            record,
            dataset_name=DATASET_NAME,
        )

        if event is not None:
            events.append(event)

    alerts = detect_ntlm_alerts(
        events,
        spray_user_threshold=20,
        brute_force_event_threshold=20,
    )

    session = create_session()

    try:
        event_repository = EventRepository(
            session
        )

        alert_repository = AlertRepository(
            session
        )

        inserted_events = (
            event_repository.add_many(
                events
            )
        )

        inserted_alerts = (
            alert_repository.add_many(
                alerts
            )
        )

        session.commit()

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()

    print(
        f"Parsed records: {len(records)}"
    )

    print(
        f"Normalized events: {len(events)}"
    )

    print(
        f"Detected alerts: {len(alerts)}"
    )

    print(
        f"Inserted events: {inserted_events}"
    )

    print(
        f"Inserted alerts: {inserted_alerts}"
    )

    if alerts:
        print()
        print("Detected alert summary:")

        for alert in alerts:
            print(
                f"{alert.rule_id} | "
                f"{alert.severity} | "
                f"user={alert.user_name} | "
                f"source={alert.source_host} | "
                f"{alert.first_seen_at.isoformat()} "
                f"-> "
                f"{alert.last_seen_at.isoformat()}"
            )


if __name__ == "__main__":
    main()