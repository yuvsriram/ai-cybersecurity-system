from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from cybersec.db.repositories.alerts import (
    AlertRepository,
)
from cybersec.db.repositories.cases import (
    CaseRepository,
)
from cybersec.db.repositories.events import (
    EventRepository,
)
from cybersec.detection.authentication import (
    detect_authentication_alerts,
)
from cybersec.ingestion.parsers.splunk_kv import (
    parse_records,
)
from cybersec.normalization.windows_security import (
    normalize_windows_security_event,
)
from cybersec.services.correlation import (
    AlertCorrelationService,
)


@dataclass(
    frozen=True,
    slots=True,
)
class IngestionResult:
    parsed_records: int
    normalized_events: int
    unsupported_records: int

    detected_alerts: int

    inserted_events: int
    inserted_alerts: int


def ingest_windows_security_text(
    *,
    content: str,
    dataset_name: str,
    session: Session,
) -> IngestionResult:
    source_records = list(
        parse_records(
            content.splitlines(
                keepends=True
            )
        )
    )

    normalized_events = []

    for source_record in (
        source_records
    ):
        normalized = (
            normalize_windows_security_event(
                source_record,
                dataset_name=dataset_name,
            )
        )

        if normalized is not None:
            normalized_events.append(
                normalized
            )

    unsupported_records = (
        len(source_records)
        - len(normalized_events)
    )

    alerts = (
        detect_authentication_alerts(
            normalized_events
        )
    )

    event_repository = EventRepository(
        session
    )

    alert_repository = AlertRepository(
        session
    )

    case_repository = CaseRepository(
        session
    )

    correlation_service = (
        AlertCorrelationService(
            case_repository
        )
    )

    inserted_events = (
        event_repository.add_many(
            normalized_events
        )
    )

    inserted_alert_ids = (
        alert_repository
        .add_many_returning_ids(
            alerts
        )
    )

    for alert_id in (
        inserted_alert_ids
    ):
        alert_model = (
            alert_repository.get_by_id(
                alert_id
            )
        )

        if alert_model is None:
            raise RuntimeError(
                "Inserted alert could not "
                f"be loaded: {alert_id}"
            )

        correlation_service.correlate(
            alert=alert_model
        )

    return IngestionResult(
        parsed_records=(
            len(source_records)
        ),
        normalized_events=(
            len(normalized_events)
        ),
        unsupported_records=(
            unsupported_records
        ),
        detected_alerts=(
            len(alerts)
        ),
        inserted_events=(
            inserted_events
        ),
        inserted_alerts=(
            len(inserted_alert_ids)
        ),
    )