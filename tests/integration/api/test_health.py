from fastapi.testclient import (
    TestClient,
)


def test_liveness_returns_ok(
    client: TestClient,
) -> None:
    response = client.get(
        "/health/live"
    )

    assert response.status_code == 200

    assert response.json() == {
        "status": "ok",
    }


def test_readiness_returns_ok(
    client: TestClient,
) -> None:
    response = client.get(
        "/health/ready"
    )

    assert response.status_code == 200

    assert response.json() == {
        "status": "ok",
        "database": "ok",
    }


def test_health_backward_compatible(
    client: TestClient,
) -> None:
    response = client.get(
        "/health"
    )

    assert response.status_code == 200

    assert response.json() == {
        "status": "ok",
        "database": "ok",
    }