from __future__ import annotations

import json
from datetime import datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cybersec.ai.investigation import (
    InvestigationService,
)
from cybersec.ai.provider import (
    ChatMessage,
    LLMProviderError,
)
from cybersec.api.ai_dependencies import (
    get_investigation_service,
)
from cybersec.db.models.alert import (
    AlertModel,
)
from cybersec.db.models.event import (
    EventModel,
)
from cybersec.domain.event_identity import (
    build_event_fingerprint,
)
from cybersec.main import app


ALERT_ID = (
    "00000000-0000-0000-0000-000000000101"
)

DATASET = "ai_api_integration_test"

RAW_EVENT = "AI API integration evidence"

FINGERPRINT = build_event_fingerprint(
    source_dataset=DATASET,
    raw_event=RAW_EVENT,
)


class FakeProvider:
    def generate_structured(
        self,
        *,
        messages,
        response_schema,
    ) -> str:
        return json.dumps(
            {
                "summary": (
                    "Observed NTLM activity is "
                    "consistent with a password-spray "
                    "pattern."
                ),
                "observed_behavior": [
                    (
                        "NTLM activity was observed "
                        "from one source to one "
                        "destination."
                    )
                ],
                "evidence_findings": [
                    {
                        "observation": (
                            "One NTLM event was "
                            "observed."
                        ),
                        "evidence_ids": [
                            "E1"
                        ],
                    }
                ],
                "uncertainties": [
                    (
                        "Authentication outcomes are "
                        "unknown from the supplied "
                        "telemetry."
                    )
                ],
                "recommended_next_steps": [
                    (
                        "Correlate with additional "
                        "authentication telemetry."
                    )
                ],
            }
        )


class FailingProvider:
    def generate_structured(
        self,
        *,
        messages,
        response_schema,
    ) -> str:
        raise LLMProviderError(
            "test provider failure"
        )


def create_event_and_alert(
    session: Session,
) -> None:
    occurred_at = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
    )

    event = EventModel(
        event_fingerprint=FINGERPRINT,
        schema_version="1.0",
        occurred_at=occurred_at,
        event_code="8004",
        category="authentication",
        action="ntlm_authentication",
        outcome=None,
        source_provider="pytest",
        source_channel=(
            "Microsoft-Windows-NTLM/Operational"
        ),
        source_dataset=DATASET,
        source_record_id="api-ai-record-001",
        host_name="DC-01",
        user_name="test-user",
        user_domain=None,
        user_sid=None,
        source_host="SOURCE-HOST",
        source_ip=None,
        destination_host="DESTINATION-HOST",
        destination_ip=None,
        raw_event=RAW_EVENT,
        attributes={},
    )

    alert = AlertModel(
        id=ALERT_ID,
        dedupe_key="d" * 64,
        rule_id="AUTH-003",
        rule_version="1.0",
        title=(
            "NTLM password-spray pattern detected"
        ),
        description="Integration test alert",
        severity="high",
        created_at=occurred_at,
        first_seen_at=occurred_at,
        last_seen_at=occurred_at,
        user_name=None,
        source_ip=None,
        source_host="SOURCE-HOST",
        destination_host="DESTINATION-HOST",
        evidence_record_ids=[
            "api-ai-record-001"
        ],
        evidence_event_fingerprints=[
            FINGERPRINT
        ],
        evidence_event_codes=[
            "8004"
        ],
        mitre_techniques=[
            "T1110.003"
        ],
    )

    session.add_all(
        [
            event,
            alert,
        ]
    )

    session.commit()


def test_investigate_alert(
    client: TestClient,
    db_session: Session,
) -> None:
    create_event_and_alert(
        db_session
    )

    service = InvestigationService(
        FakeProvider()
    )

    app.dependency_overrides[
        get_investigation_service
    ] = lambda: service

    try:
        response = client.post(
            f"/api/v1/alerts/{ALERT_ID}/investigate"
        )

    finally:
        app.dependency_overrides.pop(
            get_investigation_service,
            None,
        )

    assert response.status_code == 200

    body = response.json()

    assert body["alert_id"] == ALERT_ID

    investigation = body["investigation"]

    assert (
        investigation[
            "authentication_outcome"
        ]
        == "unknown"
    )

    assert (
        investigation[
            "evidence_summary"
        ]["event_count"]
        == 1
    )

    assert (
        investigation[
            "evidence_findings"
        ][0]["event_fingerprints"]
        == [FINGERPRINT]
    )


def test_investigate_missing_alert_returns_404(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/v1/alerts/"
        "00000000-0000-0000-0000-000000000999/"
        "investigate"
    )

    assert response.status_code == 404

    assert response.json() == {
        "detail": "Alert not found"
    }


def test_investigation_provider_failure_returns_503(
    client: TestClient,
    db_session: Session,
) -> None:
    create_event_and_alert(
        db_session
    )

    service = InvestigationService(
        FailingProvider()
    )

    app.dependency_overrides[
        get_investigation_service
    ] = lambda: service

    try:
        response = client.post(
            f"/api/v1/alerts/{ALERT_ID}/investigate"
        )

    finally:
        app.dependency_overrides.pop(
            get_investigation_service,
            None,
        )

    assert response.status_code == 503

    assert response.json() == {
        "detail": (
            "AI investigation provider "
            "is unavailable"
        )
    }