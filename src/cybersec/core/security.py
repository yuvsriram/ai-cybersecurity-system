from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Iterable

from cybersec.core.config import (
    ApiKeyCredential,
    VALID_API_ROLES,
)


ROLE_PRIORITY = {
    "viewer": 10,
    "analyst": 20,
    "admin": 30,
}


@dataclass(
    frozen=True,
    slots=True,
)
class Principal:
    name: str
    role: str


def hash_api_key(
    api_key: str,
) -> str:
    return hashlib.sha256(
        api_key.encode("utf-8")
    ).hexdigest()


def authenticate_api_key(
    *,
    api_key: str,
    credentials: Iterable[
        ApiKeyCredential
    ],
) -> Principal | None:
    if not api_key:
        return None

    supplied_digest = (
        hash_api_key(
            api_key
        )
    )

    matched: (
        ApiKeyCredential
        | None
    ) = None

    for credential in credentials:
        if hmac.compare_digest(
            supplied_digest,
            credential.sha256,
        ):
            matched = credential

    if matched is None:
        return None

    return Principal(
        name=matched.name,
        role=matched.role,
    )


def role_allows(
    *,
    actual_role: str,
    required_role: str,
) -> bool:
    if (
        actual_role
        not in VALID_API_ROLES
    ):
        return False

    if (
        required_role
        not in VALID_API_ROLES
    ):
        raise ValueError(
            "Unknown required role: "
            f"{required_role}"
        )

    return (
        ROLE_PRIORITY[
            actual_role
        ]
        >= ROLE_PRIORITY[
            required_role
        ]
    )