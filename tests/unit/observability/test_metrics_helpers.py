from prometheus_client import (
    generate_latest,
)

from cybersec.observability.metrics import (
    observe_ingestion_result,
    observe_investigation_worker_result,
    observe_worker_poll,
)


def test_ingestion_metrics_are_exposed() -> None:
    observe_ingestion_result(
        parsed_records=10,
        normalized_events=8,
        unsupported_records=2,
        inserted_events=8,
        detected_alerts=3,
        inserted_alerts=3,
    )

    payload = (
        generate_latest()
        .decode("utf-8")
    )

    assert (
        "cybersec_ingestion_records_total"
        in payload
    )

    assert (
        'kind="parsed"'
        in payload
    )

    assert (
        "cybersec_detected_alerts_total"
        in payload
    )


def test_worker_metrics_are_exposed() -> None:
    observe_worker_poll(
        "processed"
    )

    observe_investigation_worker_result(
        status="completed",
        duration_seconds=1.5,
    )

    payload = (
        generate_latest()
        .decode("utf-8")
    )

    assert (
        "cybersec_investigation_"
        "worker_runs_total"
        in payload
    )

    assert (
        'status="completed"'
        in payload
    )

    assert (
        "cybersec_investigation_"
        "worker_duration_seconds"
        in payload
    )