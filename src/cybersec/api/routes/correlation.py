from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from cybersec.api.dependencies import (
    get_current_principal,
    get_db_session,
)
from cybersec.api.schemas.correlation import (
    AlertCorrelationResponse,
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
from cybersec.db.repositories.cases import (
    CaseRepository,
)
from cybersec.services.correlation import (
    AlertCorrelationService,
)


router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["correlation"],
)


@router.post(
    "/{alert_id}/correlate",
    response_model=(
        AlertCorrelationResponse
    ),
)
def correlate_alert(
    alert_id: str,
    session: Session = Depends(
        get_db_session
    ),
    principal: Principal = Depends(
        get_current_principal
    ),
) -> AlertCorrelationResponse:
    alert_repository = (
        AlertRepository(
            session
        )
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

    case_repository = (
        CaseRepository(
            session
        )
    )

    service = (
        AlertCorrelationService(
            case_repository
        )
    )

    try:
        result = service.correlate(
            alert=alert
        )

        audit_repository = (
            AuditRepository(
                session
            )
        )

        audit_repository.record(
            principal=principal,
            action="alert.correlate",
            resource_type="alert",
            resource_id=alert_id,
            attributes={
                "case_id": (
                    result.case_id
                ),
                "case_created": (
                    result.case_created
                ),
                "alert_added": (
                    result.alert_added
                ),
                "correlation_reason": (
                    result
                    .correlation_reason
                ),
            },
        )

        session.commit()

    except SQLAlchemyError as exc:
        session.rollback()

        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "Unable to correlate alert"
            ),
        ) from exc

    return AlertCorrelationResponse(
        alert_id=result.alert_id,
        case_id=result.case_id,
        case_created=(
            result.case_created
        ),
        alert_added=result.alert_added,
        correlation_reason=(
            result.correlation_reason
        ),
    )