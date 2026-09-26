from __future__ import annotations

from pathlib import Path

from cybersec.db.repositories.alerts import AlertRepository
from cybersec.db.repositories.events import EventRepository
from cybersec.db.session import create_session
from cybersec.detection.authentication import (
    detect_authentication_alerts,
)
from cybersec.ingestion.parsers.splunk_kv import parse_file
from cybersec.normalization.windows_security import (
    normalize_windows_security_event,
)


DATASET_PATH = Path(
    "data/raw/splunk/account_lockout_windows_security.log"
)

DATASET_NAME = "splunk_account_lockout"


def main() -> None:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    events = []

    for source_record in parse_file(DATASET_PATH):
        normalized = normalize_windows_security_event(
            source_record,
            dataset_name=DATASET_NAME,
        )

        if normalized is not None:
            events.append(normalized)

    alerts = detect_authentication_alerts(events)

    with create_session() as session:
        event_repository = EventRepository(session)
        alert_repository = AlertRepository(session)

        inserted_events = event_repository.add_many(events)
        inserted_alerts = alert_repository.add_many(alerts)

        session.commit()

    print(f"Normalized events: {len(events)}")
    print(f"Detected alerts: {len(alerts)}")
    print(f"Inserted events: {inserted_events}")
    print(f"Inserted alerts: {inserted_alerts}")


if __name__ == "__main__":
    main()