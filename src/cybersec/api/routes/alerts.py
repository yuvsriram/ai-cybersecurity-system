from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy.orm import Session

from cybersec.ai.investigation import (
    InvestigationAlertContext,
    InvestigationEventContext,
    InvestigationGroundingError,
    InvestigationResponseError,
    InvestigationService,
)
from cybersec.ai.provider import (
    LLMProviderError,
)
from cybersec.api.ai_dependencies import (
    get_investigation_service,
)
from cybersec.api.dependencies import (
    get_db_session,
)
from cybersec.api.schemas.alerts import (
    AlertEvidenceResponse,
    AlertResponse,
)
from cybersec.api.schemas.events import (
    EventResponse,
)
from cybersec.api.schemas.investigations import (
    AlertInvestigationResponse,
)
from cybersec.db.repositories.alerts import (
    AlertRepository,
)
from cybersec.db.repositories.events import (
    EventRepository,
)

from cybersec.api.dependencies import (
    require_minimum_role,
)


router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["alerts"],
)


@router.get(
    "",
    response_model=list[AlertResponse],
)
def list_alerts(
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    severity: str | None = None,
    rule_id: str | None = None,
    session: Session = Depends(
        get_db_session
    ),
) -> list[AlertResponse]:
    repository = AlertRepository(
        session
    )

    alerts = repository.list_alerts(
        limit=limit,
        offset=offset,
        severity=severity,
        rule_id=rule_id,
    )

    return [
        AlertResponse.model_validate(
            alert
        )
        for alert in alerts
    ]


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
)
def get_alert(
    alert_id: str,
    session: Session = Depends(
        get_db_session
    ),
) -> AlertResponse:
    repository = AlertRepository(
        session
    )

    alert = repository.get_by_id(
        alert_id
    )

    if alert is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Alert not found",
        )

    return AlertResponse.model_validate(
        alert
    )


@router.get(
    "/{alert_id}/evidence",
    response_model=AlertEvidenceResponse,
)
def get_alert_evidence(
    alert_id: str,
    session: Session = Depends(
        get_db_session
    ),
) -> AlertEvidenceResponse:
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

    event_repository = EventRepository(
        session
    )

    events = (
        event_repository.get_by_fingerprints(
            alert.evidence_event_fingerprints
        )
    )

    if len(events) != len(
        alert.evidence_event_fingerprints
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Alert evidence integrity check failed"
            ),
        )

    return AlertEvidenceResponse(
        alert_id=alert.id,
        rule_id=alert.rule_id,
        evidence_count=len(events),
        events=[
            EventResponse.model_validate(
                event
            )
            for event in events
        ],
    )


@router.post(
    "/{alert_id}/investigate",
    response_model=AlertInvestigationResponse,
    dependencies=[
        Depends(
            require_minimum_role(
                "analyst"
            )
        )
    ],
)
def investigate_alert(
    alert_id: str,
    session: Session = Depends(
        get_db_session
    ),
    investigation_service: InvestigationService = Depends(
        get_investigation_service
    ),
) -> AlertInvestigationResponse:
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
        event_repository.get_by_fingerprints(
            fingerprints
        )
    )

    if len(events) != len(
        fingerprints
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Alert evidence integrity check failed"
            ),
        )

    alert_context = (
        InvestigationAlertContext
        .model_validate(alert)
    )

    event_contexts = [
        InvestigationEventContext
        .model_validate(event)
        for event in events
    ]

    try:
        result = (
            investigation_service.investigate(
                alert=alert_context,
                events=event_contexts,
            )
        )

    except LLMProviderError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "AI investigation provider "
                "is unavailable"
            ),
        ) from exc

    except (
        InvestigationResponseError,
        InvestigationGroundingError,
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_502_BAD_GATEWAY
            ),
            detail=(
                "AI investigation response "
                "failed validation"
            ),
        ) from exc

    return AlertInvestigationResponse(
        alert_id=alert.id,
        investigation=result,
    )