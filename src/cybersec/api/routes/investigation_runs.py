from __future__ import annotations

import os

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from cybersec.api.dependencies import (
    get_current_principal,
    get_db_session,
    require_minimum_role,
)
from cybersec.api.schemas.investigation_runs import (
    InvestigationRunResponse,
)
from cybersec.core.security import (
    Principal,
)
from cybersec.db.repositories.alerts import (
    AlertRepository,
)
from cybersec.db.repositories.audit import (
    AuditRepository,
)
from cybersec.db.repositories.events import (
    EventRepository,
)
from cybersec.db.repositories.investigations import (
    InvestigationRunRepository,
)


router = APIRouter(
    prefix="/api/v1",
    tags=["investigations"],
)


@router.post(
    "/alerts/{alert_id}/investigations",
    response_model=InvestigationRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[
        Depends(
            require_minimum_role(
                "analyst"
            )
        )
    ],
)
def create_investigation_run(
    alert_id: str,
    session: Session = Depends(
        get_db_session
    ),
    principal: Principal = Depends(
        get_current_principal
    ),
) -> InvestigationRunResponse:
    alert_repository = AlertRepository(
        session
    )

    alert = alert_repository.get_by_id(
        alert_id
    )

    if alert is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Alert not found",
        )

    fingerprints = (
        alert.evidence_event_fingerprints
    )

    if not fingerprints:
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=(
                "Alert has no evidence available "
                "for investigation"
            ),
        )

    event_repository = EventRepository(
        session
    )

    events = (
        event_repository
        .get_by_fingerprints(
            fingerprints
        )
    )

    if len(events) != len(
        fingerprints
    ):
        raise HTTPException(
            status_code=(
                status
                .HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Alert evidence integrity "
                "check failed"
            ),
        )

    repository = (
        InvestigationRunRepository(
            session
        )
    )

    try:
        run = repository.create_queued(
            alert_id=alert.id,
            provider=os.getenv(
                "CYBERSEC_LLM_PROVIDER",
                "ollama",
            ),
            model=os.getenv(
                "CYBERSEC_LLM_MODEL",
                "qwen3:4b",
            ),
            prompt_version="1.0",
        )

        session.flush()

        audit_repository = (
            AuditRepository(
                session
            )
        )

        audit_repository.record(
            principal=principal,
            action=(
                "investigation.queue"
            ),
            resource_type=(
                "investigation"
            ),
            resource_id=run.id,
            attributes={
                "alert_id": alert.id,
                "provider": run.provider,
                "model": run.model,
                "prompt_version": (
                    run.prompt_version
                ),
            },
        )

        session.commit()
        session.refresh(run)

    except SQLAlchemyError as exc:
        session.rollback()

        raise HTTPException(
            status_code=(
                status
                .HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "Unable to queue "
                "investigation"
            ),
        ) from exc

    return (
        InvestigationRunResponse
        .model_validate(run)
    )


@router.get(
    "/alerts/{alert_id}/investigations",
    response_model=list[
        InvestigationRunResponse
    ],
)
def list_investigation_runs(
    alert_id: str,
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    session: Session = Depends(
        get_db_session
    ),
) -> list[
    InvestigationRunResponse
]:
    alert_repository = AlertRepository(
        session
    )

    if (
        alert_repository.get_by_id(
            alert_id
        )
        is None
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Alert not found",
        )

    repository = (
        InvestigationRunRepository(
            session
        )
    )

    runs = repository.list_for_alert(
        alert_id=alert_id,
        limit=limit,
        offset=offset,
    )

    return [
        InvestigationRunResponse
        .model_validate(run)
        for run in runs
    ]


@router.get(
    "/alerts/{alert_id}/investigations/{run_id}",
    response_model=InvestigationRunResponse,
)
def get_investigation_run(
    alert_id: str,
    run_id: str,
    session: Session = Depends(
        get_db_session
    ),
) -> InvestigationRunResponse:
    repository = (
        InvestigationRunRepository(
            session
        )
    )

    run = repository.get_by_id(
        run_id
    )

    if (
        run is None
        or run.alert_id != alert_id
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "Investigation run not found"
            ),
        )

    return (
        InvestigationRunResponse
        .model_validate(run)
    )