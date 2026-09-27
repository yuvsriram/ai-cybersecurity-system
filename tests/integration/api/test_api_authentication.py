from fastapi.testclient import (
    TestClient,
)

from cybersec.core.config import (
    get_settings,
)


MISSING_ALERT_ID = (
    "00000000-0000-0000-"
    "0000-000000000901"
)

MISSING_RUN_ID = (
    "00000000-0000-0000-"
    "0000-000000000902"
)

MISSING_CASE_ID = (
    "00000000-0000-0000-"
    "0000-000000000903"
)


def test_health_is_public(
    unauthenticated_client: TestClient,
) -> None:
    response = (
        unauthenticated_client.get(
            "/health"
        )
    )

    assert response.status_code == 200


def test_protected_endpoint_requires_key(
    unauthenticated_client: TestClient,
) -> None:
    response = (
        unauthenticated_client.get(
            "/api/v1/events"
        )
    )

    assert response.status_code == 401

    assert response.json() == {
        "detail": "API key is required"
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

    assert response.status_code == 401

    assert response.json() == {
        "detail": "Invalid API key"
    }


def test_viewer_can_read_events(
    unauthenticated_client: TestClient,
    viewer_api_key: str,
) -> None:
    response = (
        unauthenticated_client.get(
            "/api/v1/events",
            headers={
                "X-API-Key":
                    viewer_api_key
            },
        )
    )

    assert response.status_code == 200


def test_viewer_can_access_investigation_history(
    unauthenticated_client: TestClient,
    viewer_api_key: str,
) -> None:
    response = (
        unauthenticated_client.get(
            (
                "/api/v1/alerts/"
                f"{MISSING_ALERT_ID}"
                "/investigations"
            ),
            headers={
                "X-API-Key":
                    viewer_api_key
            },
        )
    )

    assert response.status_code == 404

    assert response.json() == {
        "detail": "Alert not found"
    }


def test_viewer_can_access_investigation_detail(
    unauthenticated_client: TestClient,
    viewer_api_key: str,
) -> None:
    response = (
        unauthenticated_client.get(
            (
                "/api/v1/alerts/"
                f"{MISSING_ALERT_ID}"
                "/investigations/"
                f"{MISSING_RUN_ID}"
            ),
            headers={
                "X-API-Key":
                    viewer_api_key
            },
        )
    )

    assert response.status_code == 404

    assert response.json() == {
        "detail": (
            "Investigation run not found"
        )
    }


def test_viewer_cannot_queue_investigation(
    unauthenticated_client: TestClient,
    viewer_api_key: str,
) -> None:
    response = (
        unauthenticated_client.post(
            (
                "/api/v1/alerts/"
                f"{MISSING_ALERT_ID}"
                "/investigations"
            ),
            headers={
                "X-API-Key":
                    viewer_api_key
            },
        )
    )

    assert response.status_code == 403

    assert response.json() == {
        "detail": (
            "Insufficient permissions"
        )
    }


def test_analyst_can_access_investigation_queue_route(
    unauthenticated_client: TestClient,
    analyst_api_key: str,
) -> None:
    response = (
        unauthenticated_client.post(
            (
                "/api/v1/alerts/"
                f"{MISSING_ALERT_ID}"
                "/investigations"
            ),
            headers={
                "X-API-Key":
                    analyst_api_key
            },
        )
    )

    assert response.status_code == 404

    assert response.json() == {
        "detail": "Alert not found"
    }


def test_viewer_can_read_cases(
    unauthenticated_client: TestClient,
    viewer_api_key: str,
) -> None:
    response = (
        unauthenticated_client.get(
            "/api/v1/cases",
            headers={
                "X-API-Key":
                    viewer_api_key
            },
        )
    )

    assert response.status_code == 200


def test_viewer_can_read_case_detail_route(
    unauthenticated_client: TestClient,
    viewer_api_key: str,
) -> None:
    response = (
        unauthenticated_client.get(
            (
                "/api/v1/cases/"
                f"{MISSING_CASE_ID}"
            ),
            headers={
                "X-API-Key":
                    viewer_api_key
            },
        )
    )

    assert response.status_code == 404

    assert response.json() == {
        "detail": "Case not found"
    }


def test_viewer_cannot_create_case(
    unauthenticated_client: TestClient,
    viewer_api_key: str,
) -> None:
    response = (
        unauthenticated_client.post(
            "/api/v1/cases",
            headers={
                "X-API-Key":
                    viewer_api_key
            },
            json={
                "title": (
                    "Authorization test case"
                ),
                "summary": None,
                "severity": "low",
                "alert_ids": [],
            },
        )
    )

    assert response.status_code == 403

    assert response.json() == {
        "detail": (
            "Insufficient permissions"
        )
    }


def test_viewer_cannot_add_alert_to_case(
    unauthenticated_client: TestClient,
    viewer_api_key: str,
) -> None:
    response = (
        unauthenticated_client.post(
            (
                "/api/v1/cases/"
                f"{MISSING_CASE_ID}"
                "/alerts/"
                f"{MISSING_ALERT_ID}"
            ),
            headers={
                "X-API-Key":
                    viewer_api_key
            },
        )
    )

    assert response.status_code == 403

    assert response.json() == {
        "detail": (
            "Insufficient permissions"
        )
    }


def test_analyst_can_create_case(
    unauthenticated_client: TestClient,
    analyst_api_key: str,
) -> None:
    response = (
        unauthenticated_client.post(
            "/api/v1/cases",
            headers={
                "X-API-Key":
                    analyst_api_key
            },
            json={
                "title": (
                    "Analyst authorization test"
                ),
                "summary": (
                    "RBAC integration test"
                ),
                "severity": "low",
                "alert_ids": [],
            },
        )
    )

    assert response.status_code == 201

    payload = response.json()

    assert (
        payload["title"]
        == "Analyst authorization test"
    )

    assert payload["severity"] == "low"


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
                "X-API-Key":
                    analyst_api_key
            },
            json={
                "dataset_name": (
                    "authorization-test"
                ),
                "content": "",
            },
        )
    )

    assert response.status_code == 403


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
                "content": "123456789",
            },
        )

    finally:
        get_settings.cache_clear()

    assert response.status_code == 413

    assert response.json() == {
        "detail": (
            "Ingestion payload exceeds "
            "configured size limit"
        )
    }