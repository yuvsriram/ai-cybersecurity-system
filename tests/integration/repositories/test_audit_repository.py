from sqlalchemy.orm import Session

from cybersec.core.security import (
    Principal,
)
from cybersec.db.repositories.audit import (
    AuditRepository,
)


def test_audit_repository_records_event(
    db_session: Session,
) -> None:
    repository = (
        AuditRepository(
            db_session
        )
    )

    principal = Principal(
        name="test-admin",
        role="admin",
    )

    event = repository.record(
        principal=principal,
        action="case.create",
        resource_type="case",
        resource_id="case-123",
        attributes={
            "source": "pytest"
        },
    )

    db_session.commit()

    assert event.id is not None

    events = (
        repository.list_events()
    )

    assert len(events) == 1

    stored = events[0]

    assert (
        stored.actor_name
        == "test-admin"
    )

    assert (
        stored.actor_role
        == "admin"
    )

    assert (
        stored.action
        == "case.create"
    )

    assert (
        stored.resource_type
        == "case"
    )

    assert (
        stored.resource_id
        == "case-123"
    )

    assert (
        stored.outcome
        == "success"
    )