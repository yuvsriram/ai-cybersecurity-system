from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    Query,
)
from sqlalchemy.orm import Session

from cybersec.api.dependencies import (
    get_db_session,
)
from cybersec.api.schemas.audit import (
    AuditEventResponse,
)
from cybersec.db.repositories.audit import (
    AuditRepository,
)


router = APIRouter(
    prefix="/api/v1/audit",
    tags=["audit"],
)


@router.get(
    "",
    response_model=list[
        AuditEventResponse
    ],
)
def list_audit_events(
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    actor_name: (
        str | None
    ) = None,
    action: (
        str | None
    ) = None,
    resource_type: (
        str | None
    ) = None,
    session: Session = Depends(
        get_db_session
    ),
) -> list[
    AuditEventResponse
]:
    repository = (
        AuditRepository(
            session
        )
    )

    events = (
        repository.list_events(
            limit=limit,
            offset=offset,
            actor_name=actor_name,
            action=action,
            resource_type=(
                resource_type
            ),
        )
    )

    return [
        AuditEventResponse
        .model_validate(
            event
        )
        for event in events
    ]