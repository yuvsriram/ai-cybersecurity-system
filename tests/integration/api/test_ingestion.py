from fastapi.testclient import TestClient


def _build_failed_logon(
    *,
    record_id: int,
    second: int,
) -> str:
    return (
        f"11/09/2020 12:00:{second:02d} PM\n"
        "LogName=Security\n"
        "SourceName=Microsoft Windows security auditing.\n"
        "EventCode=4625\n"
        "ComputerName=DC-01\n"
        f"RecordNumber={record_id}\n"
        "Message=An account failed to log on.\n"
        "\n"
        "Account For Which Logon Failed:\n"
        "    Security ID: NULL SID\n"
        "    Account Name: api-ingest-user\n"
        "    Account Domain: TEST\n"
        "\n"
        "Network Information:\n"
        "    Workstation Name: CLIENT-01\n"
        "    Source Network Address: 192.0.2.55\n"
    )


def test_ingestion_endpoint_persists_events_and_alerts(
    client: TestClient,
) -> None:
    content = "".join(
        _build_failed_logon(
            record_id=500 + index,
            second=index,
        )
        for index in range(5)
    )

    response = client.post(
        "/api/v1/ingest/windows-security",
        json={
            "dataset_name": "api_ingestion_test",
            "content": content,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body == {
        "parsed_records": 5,
        "normalized_events": 5,
        "unsupported_records": 0,
        "detected_alerts": 1,
        "inserted_events": 5,
        "inserted_alerts": 1,
    }


def test_ingestion_endpoint_is_idempotent(
    client: TestClient,
) -> None:
    content = _build_failed_logon(
        record_id=900,
        second=1,
    )

    payload = {
        "dataset_name": "api_idempotency_test",
        "content": content,
    }

    first = client.post(
        "/api/v1/ingest/windows-security",
        json=payload,
    )

    second = client.post(
        "/api/v1/ingest/windows-security",
        json=payload,
    )

    assert first.status_code == 200
    assert second.status_code == 200

    assert first.json()["inserted_events"] == 1
    assert second.json()["inserted_events"] == 0


def test_ingestion_rejects_invalid_preamble(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/v1/ingest/windows-security",
        json={
            "dataset_name": "bad_input_test",
            "content": (
                "unexpected text\n"
                "11/09/2020 12:00:00 PM\n"
                "EventCode=4625\n"
            ),
        },
    )

    assert response.status_code == 422

    assert (
        "before the first event timestamp"
        in response.json()["detail"]
    )


def test_ingestion_rejects_invalid_dataset_name(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/v1/ingest/windows-security",
        json={
            "dataset_name": "../../evil",
            "content": (
                "11/09/2020 12:00:00 PM\n"
                "EventCode=4625\n"
            ),
        },
    )

    assert response.status_code == 422