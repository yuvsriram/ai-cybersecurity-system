from __future__ import annotations

from collections.abc import (
    Callable,
    Generator,
)

from fastapi import (
    Depends,
    HTTPException,
    Security,
    status,
)
from fastapi.security import (
    APIKeyHeader,
)
from sqlalchemy.orm import Session

from cybersec.core.config import (
    get_settings,
)
from cybersec.core.security import (
    Principal,
    authenticate_api_key,
    role_allows,
)
from cybersec.db.session import (
    create_session,
)


_api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
)


def get_db_session(
) -> Generator[
    Session,
    None,
    None,
]:
    session = create_session()

    try:
        yield session

    finally:
        session.close()


def get_current_principal(
    api_key: str | None = Security(
        _api_key_header
    ),
) -> Principal:
    settings = get_settings()

    if not settings.api_keys:
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "API authentication "
                "is not configured"
            ),
        )

    if api_key is None:
        raise HTTPException(
            status_code=(
                status.HTTP_401_UNAUTHORIZED
            ),
            detail=(
                "API key is required"
            ),
            headers={
                "WWW-Authenticate": (
                    "ApiKey"
                )
            },
        )

    principal = authenticate_api_key(
        api_key=api_key,
        credentials=(
            settings.api_keys
        ),
    )

    if principal is None:
        raise HTTPException(
            status_code=(
                status.HTTP_401_UNAUTHORIZED
            ),
            detail=(
                "Invalid API key"
            ),
            headers={
                "WWW-Authenticate": (
                    "ApiKey"
                )
            },
        )

    return principal


def require_minimum_role(
    required_role: str,
) -> Callable[..., Principal]:
    def dependency(
        principal: Principal = Depends(
            get_current_principal
        ),
    ) -> Principal:
        if not role_allows(
            actual_role=(
                principal.role
            ),
            required_role=(
                required_role
            ),
        ):
            raise HTTPException(
                status_code=(
                    status.HTTP_403_FORBIDDEN
                ),
                detail=(
                    "Insufficient permissions"
                ),
            )

        return principal

    return dependency