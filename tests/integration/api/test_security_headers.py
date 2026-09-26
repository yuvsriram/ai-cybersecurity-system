from fastapi.testclient import (
    TestClient,
)


def test_security_headers_present(
    client: TestClient,
) -> None:
    response = client.get(
        "/health/live"
    )

    assert response.status_code == 200

    assert (
        response.headers[
            "x-content-type-options"
        ]
        == "nosniff"
    )

    assert (
        response.headers[
            "x-frame-options"
        ]
        == "DENY"
    )

    assert (
        response.headers[
            "referrer-policy"
        ]
        == "no-referrer"
    )

    assert (
        "camera=()"
        in response.headers[
            "permissions-policy"
        ]
    )


def test_untrusted_host_rejected(
    client: TestClient,
) -> None:
    response = client.get(
        "/health/live",
        headers={
            "Host": "untrusted.example",
        },
    )

    assert response.status_code == 400