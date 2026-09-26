from fastapi.testclient import (
    TestClient,
)

from cybersec.core.config import (
    get_settings,
)


def test_health_is_public(
    unauthenticated_client: TestClient,
) -> None:
    response = (
        unauthenticated_client.get(
            "/health"
        )
    )

    assert (
        response.status_code
        == 200
    )


def test_protected_endpoint_requires_key(
    unauthenticated_client: TestClient,
) -> None:
    response = (
        unauthenticated_client.get(
            "/api/v1/events"
        )
    )

    assert (
        response.status_code
        == 401
    )

    assert response.json() == {
        "detail": (
            "API key is required"
        )
    }


def test_invalid_api_key_is_rejected(
    unauthenticated_client: TestClient,
) -> None:
    response = (
        unauthenticated_client.get(
            "/api/v1/events",
            headers={
                "X-API-Key": (
                    "definitely-invalid"
                )
            },
        )
    )

    assert (
        response.status_code
        == 401
    )

    assert response.json() == {
        "detail": (
            "Invalid API key"
        )
    }


def test_viewer_can_read_events(
    unauthenticated_client: TestClient,
    viewer_api_key: str,
) -> None:
    response = (
        unauthenticated_client.get(
            "/api/v1/events",
            headers={
                "X-API-Key": (
                    viewer_api_key
                )
            },
        )
    )

    assert (
        response.status_code
        == 200
    )


def test_viewer_cannot_access_cases(
    unauthenticated_client: TestClient,
    viewer_api_key: str,
) -> None:
    response = (
        unauthenticated_client.get(
            "/api/v1/cases",
            headers={
                "X-API-Key": (
                    viewer_api_key
                )
            },
        )
    )

    assert (
        response.status_code
        == 403
    )

    assert response.json() == {
        "detail": (
            "Insufficient permissions"
        )
    }


def test_analyst_can_access_cases(
    unauthenticated_client: TestClient,
    analyst_api_key: str,
) -> None:
    response = (
        unauthenticated_client.get(
            "/api/v1/cases",
            headers={
                "X-API-Key": (
                    analyst_api_key
                )
            },
        )
    )

    assert (
        response.status_code
        == 200
    )


def test_analyst_cannot_ingest(
    unauthenticated_client: TestClient,
    analyst_api_key: str,
) -> None:
    response = (
        unauthenticated_client.post(
            (
                "/api/v1/ingest/"
                "windows-security"
            ),
            headers={
                "X-API-Key": (
                    analyst_api_key
                )
            },
            json={
                "dataset_name": (
                    "authorization-test"
                ),
                "content": "",
            },
        )
    )

    assert (
        response.status_code
        == 403
    )


def test_ingestion_payload_limit(
    client: TestClient,
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "CYBERSEC_MAX_INGESTION_BYTES",
        "8",
    )

    get_settings.cache_clear()

    try:
        response = client.post(
            (
                "/api/v1/ingest/"
                "windows-security"
            ),
            json={
                "dataset_name": (
                    "payload-limit-test"
                ),
                "content": (
                    "123456789"
                ),
            },
        )

    finally:
        get_settings.cache_clear()

    assert (
        response.status_code
        == 413
    )

    assert response.json() == {
        "detail": (
            "Ingestion payload exceeds "
            "configured size limit"
        )
    }