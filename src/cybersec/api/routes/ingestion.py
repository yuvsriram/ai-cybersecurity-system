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
from cybersec.api.schemas.ingestion import (
    IngestionResponse,
    WindowsSecurityIngestionRequest,
)
from cybersec.core.config import (
    get_settings,
)
from cybersec.core.security import (
    Principal,
)
from cybersec.db.repositories.audit import (
    AuditRepository,
)
from cybersec.services.ingestion import (
    ingest_windows_security_text,
)
from cybersec.observability.metrics import (
    observe_ingestion_result,
)


router = APIRouter(
    prefix="/api/v1/ingest",
    tags=["ingestion"],
)


@router.post(
    "/windows-security",
    response_model=IngestionResponse,
    status_code=status.HTTP_200_OK,
)
def ingest_windows_security(
    request: WindowsSecurityIngestionRequest,
    session: Session = Depends(
        get_db_session
    ),
    principal: Principal = Depends(
        get_current_principal
    ),
) -> IngestionResponse:
    settings = get_settings()

    content_size = len(
        request.content.encode(
            "utf-8"
        )
    )

    if (
        content_size
        > settings.max_ingestion_bytes
    ):
        raise HTTPException(
            status_code=(
                status
                .HTTP_413_CONTENT_TOO_LARGE
            ),
            detail=(
                "Ingestion payload exceeds "
                "configured size limit"
            ),
        )

    try:
        result = (
            ingest_windows_security_text(
                content=request.content,
                dataset_name=(
                    request.dataset_name
                ),
                session=session,
            )
        )

        audit_repository = (
            AuditRepository(
                session
            )
        )

        audit_repository.record(
            principal=principal,
            action=(
                "ingestion.windows_security"
            ),
            resource_type="dataset",
            resource_id=(
                request.dataset_name
            ),
            attributes={
                "content_bytes": (
                    content_size
                ),
                "parsed_records": (
                    result.parsed_records
                ),
                "normalized_events": (
                    result.normalized_events
                ),
                "unsupported_records": (
                    result.unsupported_records
                ),
                "detected_alerts": (
                    result.detected_alerts
                ),
                "inserted_events": (
                    result.inserted_events
                ),
                "inserted_alerts": (
                    result.inserted_alerts
                ),
            },
        )

        session.commit()

        observe_ingestion_result(
            parsed_records=(
                result.parsed_records
            ),
            normalized_events=(
                result.normalized_events
            ),
            unsupported_records=(
                result.unsupported_records
            ),
            inserted_events=(
                result.inserted_events
            ),
            detected_alerts=(
                result.detected_alerts
            ),
            inserted_alerts=(
                result.inserted_alerts
            ),
        )

    except ValueError as exc:
        session.rollback()

        raise HTTPException(
            status_code=(
                status
                .HTTP_422_UNPROCESSABLE_CONTENT
            ),
            detail=str(exc),
        ) from exc

    except SQLAlchemyError as exc:
        session.rollback()

        raise HTTPException(
            status_code=(
                status
                .HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "Database operation failed"
            ),
        ) from exc

    return IngestionResponse(
        parsed_records=(
            result.parsed_records
        ),
        normalized_events=(
            result.normalized_events
        ),
        unsupported_records=(
            result.unsupported_records
        ),
        detected_alerts=(
            result.detected_alerts
        ),
        inserted_events=(
            result.inserted_events
        ),
        inserted_alerts=(
            result.inserted_alerts
        ),
    )