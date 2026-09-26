from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cybersec.db.models.alert import AlertModel


def create_test_alert(
    session: Session,
    *,
    severity: str = "critical-test",
    rule_id: str = "TEST-API-001",
) -> AlertModel:
    alert = AlertModel(
        id=str(uuid4()),
        dedupe_key=str(uuid4()).replace("-", ""),
        rule_id=rule_id,
        rule_version="1.0",
        title="API integration test alert",
        description="Created by pytest.",
        severity=severity,
        created_at=datetime.now(timezone.utc),
        first_seen_at=datetime(2026, 1, 1, 12, 0, 0),
        last_seen_at=datetime(2026, 1, 1, 12, 1, 0),
        user_name="api-test-user",
        source_ip="192.0.2.10",
        source_host="api-source-host",
        destination_host="api-destination-host",
        evidence_record_ids=[
            "api-record-001",
        ],
        evidence_event_codes=[
            "9999",
        ],
        mitre_techniques=[],
    )

    session.add(alert)
    session.commit()
    session.refresh(alert)

    return alert


def test_list_alerts_can_filter_by_severity(
    client: TestClient,
    db_session: Session,
) -> None:
    create_test_alert(
        db_session,
        severity="critical-test",
    )

    response = client.get(
        "/api/v1/alerts",
        params={
            "severity": "critical-test",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert len(body) == 1
    assert body[0]["severity"] == "critical-test"


def test_list_alerts_can_filter_by_rule_id(
    client: TestClient,
    db_session: Session,
) -> None:
    create_test_alert(
        db_session,
        rule_id="TEST-UNIQUE-RULE",
    )

    response = client.get(
        "/api/v1/alerts",
        params={
            "rule_id": "TEST-UNIQUE-RULE",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert len(body) == 1
    assert body[0]["rule_id"] == "TEST-UNIQUE-RULE"


def test_get_alert_by_id(
    client: TestClient,
    db_session: Session,
) -> None:
    alert = create_test_alert(db_session)

    response = client.get(
        f"/api/v1/alerts/{alert.id}"
    )

    assert response.status_code == 200

    body = response.json()

    assert body["id"] == alert.id
    assert body["rule_id"] == "TEST-API-001"


def test_missing_alert_returns_404(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v1/alerts/"
        "00000000-0000-0000-0000-000000000000"
    )

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Alert not found"
    }


def test_alert_limit_validation(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v1/alerts",
        params={
            "limit": 0,
        },
    )

    assert response.status_code == 422

from cybersec.db.models.event import EventModel
from cybersec.domain.event_identity import (
    build_event_fingerprint,
)


def test_get_alert_evidence(
    client: TestClient,
    db_session: Session,
) -> None:
    source_dataset = (
        "alert_evidence_integration_test"
    )

    raw_event = (
        "exact evidence integration event"
    )

    fingerprint = build_event_fingerprint(
        source_dataset=source_dataset,
        raw_event=raw_event,
    )

    event = EventModel(
        event_fingerprint=fingerprint,
        schema_version="1.0",
        occurred_at=datetime(
            2026,
            1,
            1,
            12,
            0,
            0,
        ),
        event_code="9999",
        category="test",
        action="evidence_test",
        outcome="success",
        source_provider="pytest",
        source_channel="test",
        source_dataset=source_dataset,
        source_record_id=(
            "evidence-record-001"
        ),
        host_name="evidence-host",
        user_name="evidence-user",
        user_domain="TEST",
        user_sid=None,
        source_host="source-host",
        source_ip="192.0.2.10",
        destination_host="destination-host",
        destination_ip="192.0.2.20",
        raw_event=raw_event,
        attributes={
            "test": "true",
        },
    )

    db_session.add(event)
    db_session.commit()

    alert = create_test_alert(
        db_session
    )

    alert.evidence_record_ids = [
        "evidence-record-001"
    ]

    alert.evidence_event_fingerprints = [
        fingerprint
    ]

    alert.evidence_event_codes = [
        "9999"
    ]

    db_session.commit()

    response = client.get(
        f"/api/v1/alerts/{alert.id}/evidence"
    )

    assert response.status_code == 200

    body = response.json()

    assert body["alert_id"] == alert.id
    assert body["evidence_count"] == 1

    assert len(body["events"]) == 1

    assert (
        body["events"][0][
            "event_fingerprint"
        ]
        == fingerprint
    )

    assert (
        body["events"][0]["event_code"]
        == "9999"
    )


def test_missing_alert_evidence_returns_404(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v1/alerts/"
        "00000000-0000-0000-0000-000000000000/"
        "evidence"
    )

    assert response.status_code == 404

    assert response.json() == {
        "detail": "Alert not found"
    }