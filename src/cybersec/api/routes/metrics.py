from __future__ import annotations

import hmac
import os

from fastapi import (
    APIRouter,
    HTTPException,
    Security,
    status,
)
from fastapi.responses import Response
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    generate_latest,
)


router = APIRouter(
    tags=["observability"],
)


_metrics_bearer = HTTPBearer(
    auto_error=False
)


def require_metrics_access(
    credentials: (
        HTTPAuthorizationCredentials
        | None
    ) = Security(
        _metrics_bearer
    ),
) -> None:
    expected_token = os.getenv(
        "CYBERSEC_METRICS_TOKEN",
        "",
    ).strip()

    if len(
        expected_token
    ) < 32:
        raise HTTPException(
            status_code=(
                status
                .HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "Metrics authentication "
                "is not configured"
            ),
        )

    if (
        credentials is None
        or credentials.scheme.lower()
        != "bearer"
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_401_UNAUTHORIZED
            ),
            detail=(
                "Metrics bearer token "
                "is required"
            ),
            headers={
                "WWW-Authenticate": (
                    "Bearer"
                )
            },
        )

    if not hmac.compare_digest(
        credentials.credentials,
        expected_token,
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_401_UNAUTHORIZED
            ),
            detail=(
                "Invalid metrics "
                "bearer token"
            ),
            headers={
                "WWW-Authenticate": (
                    "Bearer"
                )
            },
        )


@router.get(
    "/metrics",
    include_in_schema=False,
)
def prometheus_metrics(
    _: None = Security(
        require_metrics_access
    ),
) -> Response:
    return Response(
        content=generate_latest(),
        media_type=(
            CONTENT_TYPE_LATEST
        ),
    )