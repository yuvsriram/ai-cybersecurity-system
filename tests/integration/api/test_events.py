from datetime import datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cybersec.db.models.event import EventModel
from cybersec.domain.event_identity import (
    build_event_fingerprint,
)


def create_test_event(
    session: Session,
    *,
    event_code: str = "9999",
    user_name: str = "api-test-user",
    record_id: str = "api-test-record-001",
) -> EventModel:
    source_dataset = "api_integration_test"

    raw_event = (
        f"integration test event:"
        f"{event_code}:"
        f"{user_name}:"
        f"{record_id}"
    )

    event_fingerprint = build_event_fingerprint(
        source_dataset=source_dataset,
        raw_event=raw_event,
    )

    event = EventModel(
        event_fingerprint=event_fingerprint,
        schema_version="1.0",
        occurred_at=datetime(
            2026,
            1,
            1,
            12,
            0,
            0,
        ),
        event_code=event_code,
        category="test",
        action="api_test",
        outcome="success",
        source_provider="pytest",
        source_channel="test",
        source_dataset=source_dataset,
        source_record_id=record_id,
        host_name="api-test-host",
        user_name=user_name,
        user_domain="TEST",
        user_sid=None,
        source_host="source-test-host",
        source_ip="192.0.2.10",
        destination_host="destination-test-host",
        destination_ip="192.0.2.20",
        raw_event=raw_event,
        attributes={
            "test": "true",
        },
    )

    session.add(event)
    session.commit()
    session.refresh(event)

    return event


def test_list_events_can_filter_by_event_code(
    client: TestClient,
    db_session: Session,
) -> None:
    create_test_event(
        db_session,
        event_code="9999",
    )

    response = client.get(
        "/api/v1/events",
        params={
            "event_code": "9999",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert len(body) == 1
    assert body[0]["event_code"] == "9999"
    assert body[0]["user_name"] == "api-test-user"


def test_list_events_can_filter_by_user(
    client: TestClient,
    db_session: Session,
) -> None:
    create_test_event(
        db_session,
        user_name="unique-api-user",
        record_id="api-user-filter-record",
    )

    response = client.get(
        "/api/v1/events",
        params={
            "user_name": "unique-api-user",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert len(body) == 1
    assert body[0]["user_name"] == "unique-api-user"


def test_get_event_by_id(
    client: TestClient,
    db_session: Session,
) -> None:
    event = create_test_event(
        db_session,
        record_id="api-get-record",
    )

    response = client.get(
        f"/api/v1/events/{event.id}"
    )

    assert response.status_code == 200

    body = response.json()

    assert body["id"] == event.id
    assert body["event_code"] == "9999"


def test_missing_event_returns_404(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v1/events/2147483647"
    )

    assert response.status_code == 404

    assert response.json() == {
        "detail": "Event not found"
    }


def test_event_limit_validation(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v1/events",
        params={
            "limit": 501,
        },
    )

    assert response.status_code == 422