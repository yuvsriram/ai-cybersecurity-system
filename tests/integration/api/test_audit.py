from fastapi.testclient import (
    TestClient,
)
from sqlalchemy.orm import Session

from cybersec.core.security import (
    Principal,
)
from cybersec.db.repositories.audit import (
    AuditRepository,
)


def test_admin_can_read_audit_events(
    client: TestClient,
    db_session: Session,
) -> None:
    repository = (
        AuditRepository(
            db_session
        )
    )

    repository.record(
        principal=Principal(
            name="test-admin",
            role="admin",
        ),
        action="test.action",
        resource_type="test",
        resource_id="resource-1",
        attributes={
            "sensitive": "value"
        },
    )

    db_session.commit()

    response = client.get(
        "/api/v1/audit"
    )

    assert (
        response.status_code
        == 200
    )

    payload = response.json()

    assert len(payload) == 1

    assert (
        payload[0]["action"]
        == "test.action"
    )

    assert (
        payload[0]["actor_name"]
        == "test-admin"
    )

    assert (
        payload[0]["resource_id"]
        == "resource-1"
    )


def test_analyst_cannot_read_full_audit_events(
    unauthenticated_client: TestClient,
    analyst_api_key: str,
) -> None:
    response = (
        unauthenticated_client.get(
            "/api/v1/audit",
            headers={
                "X-API-Key": (
                    analyst_api_key
                )
            },
        )
    )

    assert (
        response.status_code
        == 403
    )


def test_viewer_can_read_sanitized_audit_events(
    unauthenticated_client: TestClient,
    viewer_api_key: str,
    db_session: Session,
) -> None:
    repository = (
        AuditRepository(
            db_session
        )
    )

    repository.record(
        principal=Principal(
            name="secret-admin-name",
            role="admin",
        ),
        action="case.create",
        resource_type="case",
        resource_id="secret-resource-id",
        detail="sensitive detail",
        attributes={
            "private": "value"
        },
    )

    db_session.commit()

    response = (
        unauthenticated_client.get(
            "/api/v1/audit/public",
            headers={
                "X-API-Key": (
                    viewer_api_key
                )
            },
        )
    )

    assert (
        response.status_code
        == 200
    )

    payload = response.json()

    assert len(payload) == 1

    event = payload[0]

    assert event["action"] == "case.create"
    assert event["actor_role"] == "admin"
    assert event["resource_type"] == "case"

    assert "actor_name" not in event
    assert "resource_id" not in event
    assert "detail" not in event
    assert "attributes" not in event