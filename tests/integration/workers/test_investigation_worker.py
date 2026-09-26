from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy.orm import Session

from cybersec.ai.provider import (
    LLMProviderError,
)
from cybersec.db.models.alert import (
    AlertModel,
)
from cybersec.db.models.event import (
    EventModel,
)
from cybersec.db.repositories.investigations import (
    InvestigationRunRepository,
)
from cybersec.domain.event_identity import (
    build_event_fingerprint,
)
from cybersec.domain.investigations import (
    INVESTIGATION_STATUS_COMPLETED,
    INVESTIGATION_STATUS_FAILED,
    INVESTIGATION_STATUS_QUEUED,
)
from cybersec.workers.investigations import (
    InvestigationWorker,
)


DATASET = "worker_integration_test"

RAW_EVENT = (
    "worker integration evidence"
)

FINGERPRINT = (
    build_event_fingerprint(
        source_dataset=DATASET,
        raw_event=RAW_EVENT,
    )
)

ALERT_ID = (
    "00000000-0000-0000-"
    "0000-000000000201"
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
                    "consistent with a "
                    "password-spray pattern."
                ),
                "observed_behavior": [
                    (
                        "NTLM authentication "
                        "activity was observed."
                    )
                ],
                "evidence_findings": [
                    {
                        "observation": (
                            "An NTLM event was "
                            "observed."
                        ),
                        "evidence_ids": [
                            "E1"
                        ],
                    }
                ],
                "uncertainties": [
                    (
                        "Authentication outcomes "
                        "are unknown."
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
            "simulated failure"
        )


def create_alert(
    session: Session,
    *,
    alert_id: str = ALERT_ID,
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
            "Microsoft-Windows-NTLM/"
            "Operational"
        ),
        source_dataset=DATASET,
        source_record_id="worker-001",
        host_name="DC-01",
        user_name="test-user",
        user_domain=None,
        user_sid=None,
        source_host="SOURCE",
        source_ip=None,
        destination_host="DESTINATION",
        destination_ip=None,
        raw_event=RAW_EVENT,
        attributes={},
    )

    alert = AlertModel(
        id=alert_id,
        dedupe_key="e" * 64,
        rule_id="AUTH-003",
        rule_version="1.0",
        title=(
            "NTLM password-spray "
            "pattern detected"
        ),
        description=(
            "Worker integration test"
        ),
        severity="high",
        created_at=occurred_at,
        first_seen_at=occurred_at,
        last_seen_at=occurred_at,
        user_name=None,
        source_ip=None,
        source_host="SOURCE",
        destination_host="DESTINATION",
        evidence_record_ids=[
            "worker-001"
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


def queue_run(
    session: Session,
    *,
    alert_id: str = ALERT_ID,
) -> str:
    repository = (
        InvestigationRunRepository(
            session
        )
    )

    run = repository.create_queued(
        alert_id=alert_id,
        provider="ollama",
        model="qwen3:4b",
    )

    run_id = run.id

    session.commit()

    return run_id


def test_worker_completes_investigation(
    db_session: Session,
) -> None:
    create_alert(
        db_session
    )

    run_id = queue_run(
        db_session
    )

    worker = InvestigationWorker(
        provider_factory=(
            lambda provider, model: (
                FakeProvider()
            )
        )
    )

    result = worker.process_one(
        db_session
    )

    assert result is not None

    assert (
        result.status
        == INVESTIGATION_STATUS_COMPLETED
    )

    db_session.expire_all()

    repository = (
        InvestigationRunRepository(
            db_session
        )
    )

    run = repository.get_by_id(
        run_id
    )

    assert run is not None

    assert (
        run.status
        == INVESTIGATION_STATUS_COMPLETED
    )

    assert run.started_at is not None
    assert run.completed_at is not None
    assert run.result is not None

    assert (
        run.result[
            "authentication_outcome"
        ]
        == "unknown"
    )

    assert (
        run.result[
            "evidence_summary"
        ]["event_count"]
        == 1
    )

    assert run.error_message is None


def test_worker_marks_provider_failure(
    db_session: Session,
) -> None:
    create_alert(
        db_session
    )

    run_id = queue_run(
        db_session
    )

    worker = InvestigationWorker(
        provider_factory=(
            lambda provider, model: (
                FailingProvider()
            )
        )
    )

    result = worker.process_one(
        db_session
    )

    assert result is not None

    assert (
        result.status
        == INVESTIGATION_STATUS_FAILED
    )

    db_session.expire_all()

    repository = (
        InvestigationRunRepository(
            db_session
        )
    )

    run = repository.get_by_id(
        run_id
    )

    assert run is not None

    assert (
        run.status
        == INVESTIGATION_STATUS_FAILED
    )

    assert run.result is None
    assert run.completed_at is not None

    assert run.error_message is not None

    assert (
        "simulated failure"
        in run.error_message
    )


def test_worker_returns_none_when_queue_empty(
    db_session: Session,
) -> None:
    worker = InvestigationWorker(
        provider_factory=(
            lambda provider, model: (
                FakeProvider()
            )
        )
    )

    result = worker.process_one(
        db_session
    )

    assert result is None


def test_claim_changes_status_to_running(
    db_session: Session,
) -> None:
    create_alert(
        db_session
    )

    run_id = queue_run(
        db_session
    )

    repository = (
        InvestigationRunRepository(
            db_session
        )
    )

    run = repository.claim_next_queued()

    assert run is not None
    assert run.id == run_id

    assert (
        run.status
        != INVESTIGATION_STATUS_QUEUED
    )

    assert run.started_at is not None

    db_session.rollback()