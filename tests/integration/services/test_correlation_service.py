from __future__ import annotations

from datetime import (
    datetime,
    timedelta,
)

from sqlalchemy.orm import Session

from cybersec.db.models.alert import (
    AlertModel,
)
from cybersec.db.repositories.cases import (
    CaseRepository,
)
from cybersec.services.correlation import (
    AlertCorrelationService,
)


BASE_TIME = datetime(
    2026,
    1,
    1,
    12,
    0,
    0,
)


def make_alert(
    *,
    alert_id: str,
    dedupe_key: str,
    first_seen_at: datetime,
    source_host: str | None,
    user_name: str | None = None,
    destination_host: str | None = (
        "DESTINATION"
    ),
    rule_id: str = "AUTH-003",
    severity: str = "high",
    fingerprints: list[str] | None = None,
) -> AlertModel:
    return AlertModel(
        id=alert_id,
        dedupe_key=dedupe_key,
        rule_id=rule_id,
        rule_version="1.0",
        title="Test security alert",
        description="Correlation test",
        severity=severity,
        created_at=BASE_TIME,
        first_seen_at=first_seen_at,
        last_seen_at=(
            first_seen_at
            + timedelta(
                seconds=30
            )
        ),
        user_name=user_name,
        source_ip=None,
        source_host=source_host,
        destination_host=(
            destination_host
        ),
        evidence_record_ids=[],
        evidence_event_fingerprints=(
            fingerprints or []
        ),
        evidence_event_codes=[],
        mitre_techniques=[],
    )


def test_first_alert_creates_case(
    db_session: Session,
) -> None:
    alert = make_alert(
        alert_id=(
            "00000000-0000-0000-"
            "0000-000000000301"
        ),
        dedupe_key="1" * 64,
        first_seen_at=BASE_TIME,
        source_host="HOST-A",
    )

    db_session.add(alert)
    db_session.commit()

    repository = CaseRepository(
        db_session
    )

    service = AlertCorrelationService(
        repository
    )

    result = service.correlate(
        alert=alert
    )

    db_session.commit()

    assert result.case_created is True
    assert result.alert_added is True

    case = repository.get_by_id(
        result.case_id
    )

    assert case is not None

    assert (
        case.creation_source
        == "correlation"
    )


def test_same_source_host_within_window_joins_case(
    db_session: Session,
) -> None:
    first = make_alert(
        alert_id=(
            "00000000-0000-0000-"
            "0000-000000000302"
        ),
        dedupe_key="2" * 64,
        first_seen_at=BASE_TIME,
        source_host="HOST-A",
    )

    second = make_alert(
        alert_id=(
            "00000000-0000-0000-"
            "0000-000000000303"
        ),
        dedupe_key="3" * 64,
        first_seen_at=(
            BASE_TIME
            + timedelta(
                minutes=5
            )
        ),
        source_host="HOST-A",
        rule_id="AUTH-004",
    )

    db_session.add_all(
        [
            first,
            second,
        ]
    )

    db_session.commit()

    repository = CaseRepository(
        db_session
    )

    service = AlertCorrelationService(
        repository
    )

    first_result = (
        service.correlate(
            alert=first
        )
    )

    second_result = (
        service.correlate(
            alert=second
        )
    )

    db_session.commit()

    assert (
        first_result.case_id
        == second_result.case_id
    )

    assert (
        second_result.case_created
        is False
    )

    assert (
        second_result.alert_added
        is True
    )

    assert (
        "Shared source host HOST-A"
        in second_result
        .correlation_reason
    )


def test_alert_outside_window_creates_new_case(
    db_session: Session,
) -> None:
    first = make_alert(
        alert_id=(
            "00000000-0000-0000-"
            "0000-000000000304"
        ),
        dedupe_key="4" * 64,
        first_seen_at=BASE_TIME,
        source_host="HOST-A",
    )

    second = make_alert(
        alert_id=(
            "00000000-0000-0000-"
            "0000-000000000305"
        ),
        dedupe_key="5" * 64,
        first_seen_at=(
            BASE_TIME
            + timedelta(
                hours=1
            )
        ),
        source_host="HOST-A",
    )

    db_session.add_all(
        [
            first,
            second,
        ]
    )

    db_session.commit()

    repository = CaseRepository(
        db_session
    )

    service = AlertCorrelationService(
        repository
    )

    first_result = (
        service.correlate(
            alert=first
        )
    )

    second_result = (
        service.correlate(
            alert=second
        )
    )

    db_session.commit()

    assert (
        first_result.case_id
        != second_result.case_id
    )

    assert (
        second_result.case_created
        is True
    )


def test_shared_evidence_has_highest_priority(
    db_session: Session,
) -> None:
    shared = "a" * 64

    first = make_alert(
        alert_id=(
            "00000000-0000-0000-"
            "0000-000000000306"
        ),
        dedupe_key="6" * 64,
        first_seen_at=BASE_TIME,
        source_host="HOST-A",
        fingerprints=[
            shared
        ],
    )

    second = make_alert(
        alert_id=(
            "00000000-0000-0000-"
            "0000-000000000307"
        ),
        dedupe_key="7" * 64,
        first_seen_at=(
            BASE_TIME
            + timedelta(
                minutes=2
            )
        ),
        source_host="HOST-B",
        rule_id="AUTH-004",
        fingerprints=[
            shared
        ],
    )

    db_session.add_all(
        [
            first,
            second,
        ]
    )

    db_session.commit()

    repository = CaseRepository(
        db_session
    )

    service = AlertCorrelationService(
        repository
    )

    first_result = (
        service.correlate(
            alert=first
        )
    )

    second_result = (
        service.correlate(
            alert=second
        )
    )

    db_session.commit()

    assert (
        first_result.case_id
        == second_result.case_id
    )

    assert (
        "Shared evidence events"
        in second_result
        .correlation_reason
    )


def test_correlation_is_idempotent(
    db_session: Session,
) -> None:
    alert = make_alert(
        alert_id=(
            "00000000-0000-0000-"
            "0000-000000000308"
        ),
        dedupe_key="8" * 64,
        first_seen_at=BASE_TIME,
        source_host="HOST-A",
    )

    db_session.add(alert)
    db_session.commit()

    repository = CaseRepository(
        db_session
    )

    service = AlertCorrelationService(
        repository
    )

    first = service.correlate(
        alert=alert
    )

    second = service.correlate(
        alert=alert
    )

    db_session.commit()

    assert (
        first.case_id
        == second.case_id
    )

    assert (
        second.case_created
        is False
    )

    assert (
        second.alert_added
        is False
    )

def test_same_rule_and_destination_without_overlap_do_not_correlate(
    db_session: Session,
) -> None:
    first = make_alert(
        alert_id=(
            "00000000-0000-0000-"
            "0000-000000000309"
        ),
        dedupe_key="9" * 64,
        first_seen_at=BASE_TIME,
        source_host=None,
        user_name=None,
        destination_host="DESTINATION",
        rule_id="AUTH-003",
    )

    second = make_alert(
        alert_id=(
            "00000000-0000-0000-"
            "0000-000000000310"
        ),
        dedupe_key="a" * 64,
        first_seen_at=(
            BASE_TIME
            + timedelta(
                minutes=5
            )
        ),
        source_host=None,
        user_name=None,
        destination_host="DESTINATION",
        rule_id="AUTH-003",
    )

    db_session.add_all(
        [
            first,
            second,
        ]
    )

    db_session.commit()

    repository = CaseRepository(
        db_session
    )

    service = AlertCorrelationService(
        repository
    )

    first_result = service.correlate(
        alert=first
    )

    second_result = service.correlate(
        alert=second
    )

    db_session.commit()

    assert (
        first_result.case_id
        != second_result.case_id
    )

    assert (
        second_result.case_created
        is True
    )