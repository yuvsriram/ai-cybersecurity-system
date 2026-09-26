from __future__ import annotations

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
)
from cybersec.api.schemas.alerts import (
    AlertResponse,
)
from cybersec.api.schemas.cases import (
    CaseCreateRequest,
    CaseDetailResponse,
    CaseResponse,
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
from cybersec.domain.cases import (
    CASE_SEVERITY_CRITICAL,
    CASE_SEVERITY_HIGH,
    CASE_SEVERITY_LOW,
    CASE_SEVERITY_MEDIUM,
)


router = APIRouter(
    prefix="/api/v1/cases",
    tags=["cases"],
)


VALID_SEVERITIES = {
    CASE_SEVERITY_LOW,
    CASE_SEVERITY_MEDIUM,
    CASE_SEVERITY_HIGH,
    CASE_SEVERITY_CRITICAL,
}


@router.post(
    "",
    response_model=CaseDetailResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_case(
    request: CaseCreateRequest,
    session: Session = Depends(
        get_db_session
    ),
    principal: Principal = Depends(
        get_current_principal
    ),
) -> CaseDetailResponse:
    if (
        request.severity
        not in VALID_SEVERITIES
    ):
        raise HTTPException(
            status_code=(
                status
                .HTTP_422_UNPROCESSABLE_CONTENT
            ),
            detail="Invalid case severity",
        )

    alert_repository = (
        AlertRepository(
            session
        )
    )

    for alert_id in request.alert_ids:
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
                detail=(
                    "Alert not found: "
                    f"{alert_id}"
                ),
            )

    repository = CaseRepository(
        session
    )

    try:
        case = repository.create(
            title=request.title,
            severity=request.severity,
            summary=request.summary,
            creation_source="manual",
        )

        unique_alert_ids = list(
            dict.fromkeys(
                request.alert_ids
            )
        )

        for alert_id in (
            unique_alert_ids
        ):
            repository.add_alert(
                case_id=case.id,
                alert_id=alert_id,
                correlation_reason=(
                    "Manually added "
                    "during case creation"
                ),
            )

        audit_repository = (
            AuditRepository(
                session
            )
        )

        audit_repository.record(
            principal=principal,
            action="case.create",
            resource_type="case",
            resource_id=case.id,
            attributes={
                "severity": (
                    request.severity
                ),
                "alert_ids": (
                    unique_alert_ids
                ),
                "alert_count": len(
                    unique_alert_ids
                ),
                "creation_source": (
                    "manual"
                ),
            },
        )

        session.commit()
        session.refresh(case)

    except SQLAlchemyError as exc:
        session.rollback()

        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail="Unable to create case",
        ) from exc

    alerts = repository.list_alerts(
        case_id=case.id
    )

    return CaseDetailResponse(
        **CaseResponse
        .model_validate(case)
        .model_dump(),
        alerts=[
            AlertResponse.model_validate(
                alert
            )
            for alert in alerts
        ],
    )


@router.get(
    "",
    response_model=list[
        CaseResponse
    ],
)
def list_cases(
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    status_filter: str | None = Query(
        default=None,
        alias="status",
    ),
    severity: str | None = None,
    session: Session = Depends(
        get_db_session
    ),
) -> list[CaseResponse]:
    repository = CaseRepository(
        session
    )

    cases = repository.list_cases(
        limit=limit,
        offset=offset,
        status=status_filter,
        severity=severity,
    )

    return [
        CaseResponse.model_validate(
            case
        )
        for case in cases
    ]


@router.get(
    "/{case_id}",
    response_model=CaseDetailResponse,
)
def get_case(
    case_id: str,
    session: Session = Depends(
        get_db_session
    ),
) -> CaseDetailResponse:
    repository = CaseRepository(
        session
    )

    case = repository.get_by_id(
        case_id
    )

    if case is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Case not found",
        )

    alerts = repository.list_alerts(
        case_id=case.id
    )

    return CaseDetailResponse(
        **CaseResponse
        .model_validate(case)
        .model_dump(),
        alerts=[
            AlertResponse.model_validate(
                alert
            )
            for alert in alerts
        ],
    )


@router.post(
    "/{case_id}/alerts/{alert_id}",
    response_model=CaseDetailResponse,
)
def add_alert_to_case(
    case_id: str,
    alert_id: str,
    session: Session = Depends(
        get_db_session
    ),
    principal: Principal = Depends(
        get_current_principal
    ),
) -> CaseDetailResponse:
    repository = CaseRepository(
        session
    )

    case = repository.get_by_id(
        case_id
    )

    if case is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Case not found",
        )

    alert_repository = (
        AlertRepository(
            session
        )
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

    existing_link = (
        repository.get_alert_link(
            case_id=case_id,
            alert_id=alert_id,
        )
    )

    try:
        repository.add_alert(
            case_id=case_id,
            alert_id=alert_id,
            correlation_reason=(
                "Manually added by analyst"
            ),
        )

        audit_repository = (
            AuditRepository(
                session
            )
        )

        audit_repository.record(
            principal=principal,
            action="case.alert.add",
            resource_type="case",
            resource_id=case_id,
            attributes={
                "alert_id": alert_id,
                "already_linked": (
                    existing_link
                    is not None
                ),
            },
        )

        session.commit()
        session.refresh(case)

    except SQLAlchemyError as exc:
        session.rollback()

        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "Unable to update case"
            ),
        ) from exc

    alerts = repository.list_alerts(
        case_id=case.id
    )

    return CaseDetailResponse(
        **CaseResponse
        .model_validate(case)
        .model_dump(),
        alerts=[
            AlertResponse.model_validate(
                alert
            )
            for alert in alerts
        ],
    )