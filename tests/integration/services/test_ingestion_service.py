from sqlalchemy.orm import Session

from cybersec.db.repositories.cases import (
    CaseRepository,
)
from cybersec.services.ingestion import (
    ingest_windows_security_text,
)


def _raw_log() -> str:
    return (
        "11/09/2020 12:05:22 PM\n"
        "LogName=Security\n"
        "SourceName=Microsoft Windows security auditing.\n"
        "EventCode=4740\n"
        "ComputerName=DC-01\n"
        "RecordNumber=100\n"
        "Message=A user account was locked out.\n"
        "\n"
        "Account That Was Locked Out:\n"
        "    Security ID: TEST\\alice\n"
        "    Account Name: alice\n"
        "\n"
        "Additional Information:\n"
        "    Caller Computer Name: CLIENT-01\n"
        "11/09/2020 12:05:23 PM\n"
        "LogName=Security\n"
        "SourceName=Microsoft Windows security auditing.\n"
        "EventCode=4688\n"
        "ComputerName=DC-01\n"
        "RecordNumber=101\n"
        "Message=A new process has been created.\n"
    )


def test_ingestion_counts_supported_and_unsupported_records(
    db_session: Session,
) -> None:
    result = ingest_windows_security_text(
        content=_raw_log(),
        dataset_name="service_ingestion_test",
        session=db_session,
    )

    assert result.parsed_records == 2
    assert result.normalized_events == 1
    assert result.unsupported_records == 1

    assert result.detected_alerts == 1

    assert result.inserted_events == 1
    assert result.inserted_alerts == 1


def test_ingestion_automatically_creates_case_for_new_alert(
    db_session: Session,
) -> None:
    result = ingest_windows_security_text(
        content=_raw_log(),
        dataset_name=(
            "service_ingestion_correlation_test"
        ),
        session=db_session,
    )

    assert result.inserted_alerts == 1

    db_session.commit()

    repository = CaseRepository(
        db_session
    )

    cases = repository.list_cases(
        limit=100
    )

    assert len(cases) == 1

    case = cases[0]

    assert case.status == "open"
    assert case.severity == "medium"
    assert (
        case.creation_source
        == "correlation"
    )

    alerts = repository.list_alerts(
        case_id=case.id
    )

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == "AUTH-001"
    assert alert.user_name == "alice"
    assert alert.destination_host == "DC-01"


def test_reingestion_does_not_create_duplicate_case(
    db_session: Session,
) -> None:
    dataset_name = (
        "service_ingestion_idempotency_test"
    )

    first = ingest_windows_security_text(
        content=_raw_log(),
        dataset_name=dataset_name,
        session=db_session,
    )

    db_session.commit()

    second = ingest_windows_security_text(
        content=_raw_log(),
        dataset_name=dataset_name,
        session=db_session,
    )

    db_session.commit()

    assert first.inserted_events == 1
    assert first.inserted_alerts == 1

    assert second.inserted_events == 0
    assert second.inserted_alerts == 0

    repository = CaseRepository(
        db_session
    )

    cases = repository.list_cases(
        limit=100
    )

    assert len(cases) == 1

    alerts = repository.list_alerts(
        case_id=cases[0].id
    )

    assert len(alerts) == 1