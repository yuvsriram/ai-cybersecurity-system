from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from sqlalchemy import text
from sqlalchemy.exc import (
    SQLAlchemyError,
)
from sqlalchemy.orm import Session

from cybersec.api.dependencies import (
    get_db_session,
)


router = APIRouter(
    tags=["health"],
)


@router.get(
    "/health/live"
)
def liveness_check(
) -> dict[str, str]:
    return {
        "status": "ok",
    }


@router.get(
    "/health/ready"
)
def readiness_check(
    session: Session = Depends(
        get_db_session
    ),
) -> dict[str, str]:
    return _database_readiness(
        session
    )


@router.get(
    "/health"
)
def health_check(
    session: Session = Depends(
        get_db_session
    ),
) -> dict[str, str]:
    """
    Backward-compatible readiness alias.
    """
    return _database_readiness(
        session
    )


def _database_readiness(
    session: Session,
) -> dict[str, str]:
    try:
        session.execute(
            text(
                "SELECT 1"
            )
        )

    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=(
                status
                .HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "Database unavailable"
            ),
        ) from exc

    return {
        "status": "ok",
        "database": "ok",
    }