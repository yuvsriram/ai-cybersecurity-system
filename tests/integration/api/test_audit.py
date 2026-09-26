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


def test_analyst_cannot_read_audit_events(
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