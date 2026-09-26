from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv


VALID_API_ROLES = frozenset(
    {
        "viewer",
        "analyst",
        "admin",
    }
)


@dataclass(
    frozen=True,
    slots=True,
)
class ApiKeyCredential:
    name: str
    role: str
    sha256: str


@dataclass(
    frozen=True,
    slots=True,
)
class Settings:
    database_url: str
    api_keys: tuple[
        ApiKeyCredential,
        ...
    ]
    max_ingestion_bytes: int
    environment: str
    docs_enabled: bool
    trusted_hosts: tuple[
        str,
        ...
    ]

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    load_dotenv()

    database_url = (
        _required_environment_variable(
            "DATABASE_URL"
        )
    )

    api_keys = _parse_api_keys(
        os.getenv(
            "CYBERSEC_API_KEYS_JSON",
            "[]",
        )
    )

    max_ingestion_bytes = (
        _parse_positive_integer(
            name=(
                "CYBERSEC_MAX_INGESTION_BYTES"
            ),
            raw_value=os.getenv(
                "CYBERSEC_MAX_INGESTION_BYTES",
                str(5 * 1024 * 1024),
            ),
        )
    )

    environment = os.getenv(
        "CYBERSEC_ENVIRONMENT",
        "production",
    ).strip().lower()

    if not environment:
        raise RuntimeError(
            "CYBERSEC_ENVIRONMENT "
            "must not be empty"
        )

    docs_enabled = (
        environment
        in {
            "development",
            "dev",
            "local",
            "test",
        }
    )

    trusted_hosts = (
        _parse_trusted_hosts(
            os.getenv(
                "CYBERSEC_TRUSTED_HOSTS",
                (
                    "localhost,"
                    "127.0.0.1,"
                    "testserver,"
                    "api"
                ),
            )
        )
    )

    return Settings(
        database_url=database_url,
        api_keys=api_keys,
        max_ingestion_bytes=(
            max_ingestion_bytes
        ),
        environment=environment,
        docs_enabled=docs_enabled,
        trusted_hosts=trusted_hosts,
    )


def _required_environment_variable(
    name: str,
) -> str:
    value = os.getenv(name)

    if value is None:
        raise RuntimeError(
            f"{name} must be configured"
        )

    value = value.strip()

    if not value:
        raise RuntimeError(
            f"{name} must not be empty"
        )

    return value


def _parse_api_keys(
    raw_value: str,
) -> tuple[
    ApiKeyCredential,
    ...
]:
    try:
        payload = json.loads(
            raw_value
        )

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "CYBERSEC_API_KEYS_JSON "
            "must contain valid JSON"
        ) from exc

    if not isinstance(
        payload,
        list,
    ):
        raise RuntimeError(
            "CYBERSEC_API_KEYS_JSON "
            "must contain a JSON array"
        )

    credentials: list[
        ApiKeyCredential
    ] = []

    names: set[str] = set()
    hashes: set[str] = set()

    for item in payload:
        if not isinstance(
            item,
            dict,
        ):
            raise RuntimeError(
                "Each API key configuration "
                "must be a JSON object"
            )

        name = str(
            item.get(
                "name",
                "",
            )
        ).strip()

        role = str(
            item.get(
                "role",
                "",
            )
        ).strip().lower()

        digest = str(
            item.get(
                "sha256",
                "",
            )
        ).strip().lower()

        if not name:
            raise RuntimeError(
                "API key name must not "
                "be empty"
            )

        if role not in VALID_API_ROLES:
            raise RuntimeError(
                "API key role must be one "
                "of: viewer, analyst, admin"
            )

        if re.fullmatch(
            r"[0-9a-f]{64}",
            digest,
        ) is None:
            raise RuntimeError(
                "API key sha256 must be a "
                "64-character hexadecimal "
                "SHA-256 digest"
            )

        if name in names:
            raise RuntimeError(
                "API key names must "
                "be unique"
            )

        if digest in hashes:
            raise RuntimeError(
                "API key hashes must "
                "be unique"
            )

        names.add(name)
        hashes.add(digest)

        credentials.append(
            ApiKeyCredential(
                name=name,
                role=role,
                sha256=digest,
            )
        )

    return tuple(
        credentials
    )


def _parse_positive_integer(
    *,
    name: str,
    raw_value: str,
) -> int:
    try:
        value = int(
            raw_value
        )

    except ValueError as exc:
        raise RuntimeError(
            f"{name} must be an integer"
        ) from exc

    if value <= 0:
        raise RuntimeError(
            f"{name} must be positive"
        )

    return value

def _parse_trusted_hosts(
    raw_value: str,
) -> tuple[str, ...]:
    hosts = tuple(
        host.strip()
        for host in raw_value.split(",")
        if host.strip()
    )

    if not hosts:
        raise RuntimeError(
            "CYBERSEC_TRUSTED_HOSTS "
            "must contain at least "
            "one host"
        )

    return hosts