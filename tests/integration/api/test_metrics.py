from fastapi.testclient import (
    TestClient,
)


def test_metrics_require_bearer_token(
    unauthenticated_client: TestClient,
) -> None:
    response = (
        unauthenticated_client.get(
            "/metrics"
        )
    )

    assert (
        response.status_code
        == 401
    )


def test_metrics_expose_http_measurements(
    unauthenticated_client: TestClient,
    metrics_token: str,
) -> None:
    health_response = (
        unauthenticated_client.get(
            "/health"
        )
    )

    assert (
        health_response.status_code
        == 200
    )

    response = (
        unauthenticated_client.get(
            "/metrics",
            headers={
                "Authorization": (
                    "Bearer "
                    f"{metrics_token}"
                )
            },
        )
    )

    assert (
        response.status_code
        == 200
    )

    body = response.text

    assert (
        "cybersec_http_requests_total"
        in body
    )

    assert (
        "cybersec_http_request_"
        "duration_seconds"
        in body
    )

    assert (
        'route="/health"'
        in body
    )