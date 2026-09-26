from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Generator
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import (
    Engine,
    create_engine,
    text,
)
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)
from sqlalchemy.pool import NullPool


# Tests must never export traces to the
# developer's real Tempo instance.
#
# This must be set before importing
# cybersec.main because the application
# configures observability during import.
os.environ[
    "CYBERSEC_TRACING_ENABLED"
] = "false"


from cybersec.api.dependencies import (  # noqa: E402
    get_db_session,
)
from cybersec.core.config import (  # noqa: E402
    get_settings,
)
from cybersec.db.base import Base  # noqa: E402
from cybersec.db.models.alert import (  # noqa: E402,F401
    AlertModel,
)
from cybersec.db.models.audit import (  # noqa: E402,F401
    AuditEventModel,
)
from cybersec.db.models.event import (  # noqa: E402,F401
    EventModel,
)
from cybersec.main import app  # noqa: E402


TEST_VIEWER_API_KEY = (
    "cybersec-test-viewer-key"
)

TEST_ANALYST_API_KEY = (
    "cybersec-test-analyst-key"
)

TEST_ADMIN_API_KEY = (
    "cybersec-test-admin-key"
)

TEST_METRICS_TOKEN = (
    "cybersec-test-metrics-token-"
    "0123456789abcdef"
)


def _hash_api_key(
    value: str,
) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


@pytest.fixture(autouse=True)
def configure_test_security(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[
    None,
    None,
    None,
]:
    # Load the real local test database URL
    # before replacing security configuration.
    get_settings.cache_clear()

    database_url = (
        get_settings().database_url
    )

    credentials = [
        {
            "name": "test-viewer",
            "role": "viewer",
            "sha256": _hash_api_key(
                TEST_VIEWER_API_KEY
            ),
        },
        {
            "name": "test-analyst",
            "role": "analyst",
            "sha256": _hash_api_key(
                TEST_ANALYST_API_KEY
            ),
        },
        {
            "name": "test-admin",
            "role": "admin",
            "sha256": _hash_api_key(
                TEST_ADMIN_API_KEY
            ),
        },
    ]

    monkeypatch.setenv(
        "DATABASE_URL",
        database_url,
    )

    monkeypatch.setenv(
        "CYBERSEC_API_KEYS_JSON",
        json.dumps(
            credentials
        ),
    )

    monkeypatch.setenv(
        "CYBERSEC_MAX_INGESTION_BYTES",
        str(
            5
            * 1024
            * 1024
        ),
    )

    monkeypatch.setenv(
        "CYBERSEC_METRICS_TOKEN",
        TEST_METRICS_TOKEN,
    )

    monkeypatch.setenv(
        "CYBERSEC_TRACING_ENABLED",
        "false",
    )

    get_settings.cache_clear()

    try:
        yield

    finally:
        get_settings.cache_clear()


@pytest.fixture
def test_engine(
) -> Generator[
    Engine,
    None,
    None,
]:
    schema_name = (
        f"test_{uuid4().hex}"
    )

    database_url = (
        get_settings().database_url
    )

    admin_engine = create_engine(
        database_url,
        pool_pre_ping=True,
        poolclass=NullPool,
        connect_args={
            "connect_timeout": 3,
        },
    )

    with admin_engine.begin() as connection:
        connection.execute(
            text(
                f'CREATE SCHEMA '
                f'"{schema_name}"'
            )
        )

    engine = create_engine(
        database_url,
        pool_pre_ping=True,
        poolclass=NullPool,
        connect_args={
            "options": (
                "-csearch_path="
                f"{schema_name}"
            ),
            "connect_timeout": 3,
        },
    )

    Base.metadata.create_all(
        bind=engine
    )

    try:
        yield engine

    finally:
        engine.dispose()

        with admin_engine.begin() as connection:
            connection.execute(
                text(
                    "DROP SCHEMA IF EXISTS "
                    f'"{schema_name}" '
                    "CASCADE"
                )
            )

        admin_engine.dispose()


@pytest.fixture
def db_session(
    test_engine: Engine,
) -> Generator[
    Session,
    None,
    None,
]:
    session_factory = sessionmaker(
        bind=test_engine,
        autoflush=False,
        expire_on_commit=False,
    )

    session = session_factory()

    try:
        yield session

    finally:
        session.rollback()
        session.close()


def _install_db_override(
    test_engine: Engine,
) -> None:
    session_factory = sessionmaker(
        bind=test_engine,
        autoflush=False,
        expire_on_commit=False,
    )

    def override_get_db_session(
    ) -> Generator[
        Session,
        None,
        None,
    ]:
        session = session_factory()

        try:
            yield session

        finally:
            session.close()

    app.dependency_overrides[
        get_db_session
    ] = override_get_db_session


@pytest.fixture
def client(
    test_engine: Engine,
) -> Generator[
    TestClient,
    None,
    None,
]:
    _install_db_override(
        test_engine
    )

    try:
        with TestClient(
            app
        ) as test_client:
            test_client.headers.update(
                {
                    "X-API-Key": (
                        TEST_ADMIN_API_KEY
                    )
                }
            )

            yield test_client

    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def unauthenticated_client(
    test_engine: Engine,
) -> Generator[
    TestClient,
    None,
    None,
]:
    _install_db_override(
        test_engine
    )

    try:
        with TestClient(
            app
        ) as test_client:
            yield test_client

    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def viewer_api_key() -> str:
    return TEST_VIEWER_API_KEY


@pytest.fixture
def analyst_api_key() -> str:
    return TEST_ANALYST_API_KEY


@pytest.fixture
def admin_api_key() -> str:
    return TEST_ADMIN_API_KEY


@pytest.fixture
def metrics_token() -> str:
    return TEST_METRICS_TOKEN