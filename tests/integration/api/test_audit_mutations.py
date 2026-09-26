from fastapi.testclient import (
    TestClient,
)
from sqlalchemy.orm import Session

from cybersec.db.repositories.audit import (
    AuditRepository,
)


RAW_LOCKOUT = (
    "11/09/2020 12:05:22 PM\n"
    "LogName=Security\n"
    "SourceName=Microsoft Windows "
    "security auditing.\n"
    "EventCode=4740\n"
    "ComputerName=DC-01\n"
    "RecordNumber=100\n"
    "Message=A user account was "
    "locked out.\n"
    "\n"
    "Account That Was Locked Out:\n"
    "    Security ID: TEST\\alice\n"
    "    Account Name: alice\n"
    "\n"
    "Additional Information:\n"
    "    Caller Computer Name: "
    "CLIENT-01\n"
)


def test_mutating_workflows_write_audit_events(
    client: TestClient,
    db_session: Session,
) -> None:
    ingestion_response = (
        client.post(
            (
                "/api/v1/ingest/"
                "windows-security"
            ),
            json={
                "dataset_name": (
                    "audit-mutation-test"
                ),
                "content": (
                    RAW_LOCKOUT
                ),
            },
        )
    )

    assert (
        ingestion_response.status_code
        == 200
    )

    alerts_response = client.get(
        "/api/v1/alerts"
    )

    assert (
        alerts_response.status_code
        == 200
    )

    alerts = alerts_response.json()

    assert len(alerts) == 1

    alert_id = alerts[0]["id"]

    correlation_response = (
        client.post(
            (
                f"/api/v1/alerts/"
                f"{alert_id}/correlate"
            )
        )
    )

    assert (
        correlation_response.status_code
        == 200
    )

    investigation_response = (
        client.post(
            (
                f"/api/v1/alerts/"
                f"{alert_id}/investigations"
            )
        )
    )

    assert (
        investigation_response.status_code
        == 202
    )

    case_response = client.post(
        "/api/v1/cases",
        json={
            "title": (
                "Audit logging test case"
            ),
            "summary": (
                "Case created to verify "
                "security audit logging."
            ),
            "severity": "medium",
            "alert_ids": [],
        },
    )

    assert (
        case_response.status_code
        == 201
    )

    case_id = (
        case_response.json()["id"]
    )

    add_alert_response = client.post(
        (
            f"/api/v1/cases/"
            f"{case_id}/alerts/"
            f"{alert_id}"
        )
    )

    assert (
        add_alert_response.status_code
        == 200
    )

    repository = AuditRepository(
        db_session
    )

    events = repository.list_events(
        limit=100
    )

    actions = {
        event.action
        for event in events
    }

    assert {
        "ingestion.windows_security",
        "alert.correlate",
        "investigation.queue",
        "case.create",
        "case.alert.add",
    }.issubset(actions)

    for event in events:
        if (
            event.action
            in {
                "ingestion.windows_security",
                "alert.correlate",
                "investigation.queue",
                "case.create",
                "case.alert.add",
            }
        ):
            assert (
                event.actor_name
                == "test-admin"
            )

            assert (
                event.actor_role
                == "admin"
            )