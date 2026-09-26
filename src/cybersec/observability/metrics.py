from __future__ import annotations

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
)


HTTP_REQUESTS = Counter(
    "cybersec_http_requests_total",
    "Total HTTP requests handled by the API.",
    [
        "method",
        "route",
        "status_code",
    ],
)

HTTP_REQUEST_DURATION = Histogram(
    "cybersec_http_request_duration_seconds",
    "HTTP request duration in seconds.",
    [
        "method",
        "route",
    ],
    buckets=(
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1.0,
        2.5,
        5.0,
        10.0,
    ),
)

HTTP_REQUESTS_IN_PROGRESS = Gauge(
    "cybersec_http_requests_in_progress",
    "HTTP requests currently being processed.",
)

INGESTION_RECORDS = Counter(
    "cybersec_ingestion_records_total",
    "Security telemetry records processed.",
    [
        "kind",
    ],
)

DETECTED_ALERTS = Counter(
    "cybersec_detected_alerts_total",
    "Alerts produced by detection rules.",
)

INVESTIGATION_WORKER_RUNS = Counter(
    "cybersec_investigation_worker_runs_total",
    "AI investigation worker run outcomes.",
    [
        "status",
    ],
)

INVESTIGATION_WORKER_DURATION = Histogram(
    "cybersec_investigation_worker_duration_seconds",
    "AI investigation worker processing duration.",
    [
        "status",
    ],
    buckets=(
        0.1,
        0.5,
        1.0,
        2.5,
        5.0,
        10.0,
        30.0,
        60.0,
        120.0,
        300.0,
        600.0,
    ),
)

INVESTIGATION_WORKER_POLLS = Counter(
    "cybersec_investigation_worker_polls_total",
    "Investigation worker queue polling results.",
    [
        "result",
    ],
)


def observe_ingestion_result(
    *,
    parsed_records: int,
    normalized_events: int,
    unsupported_records: int,
    inserted_events: int,
    detected_alerts: int,
    inserted_alerts: int,
) -> None:
    values = {
        "parsed": parsed_records,
        "normalized": normalized_events,
        "unsupported": unsupported_records,
        "inserted_events": inserted_events,
        "inserted_alerts": inserted_alerts,
    }

    for kind, value in values.items():
        INGESTION_RECORDS.labels(
            kind=kind
        ).inc(
            max(
                0,
                value,
            )
        )

    DETECTED_ALERTS.inc(
        max(
            0,
            detected_alerts,
        )
    )


def observe_investigation_worker_result(
    *,
    status: str,
    duration_seconds: float,
) -> None:
    if status not in {
        "completed",
        "failed",
    }:
        status = "other"

    INVESTIGATION_WORKER_RUNS.labels(
        status=status
    ).inc()

    INVESTIGATION_WORKER_DURATION.labels(
        status=status
    ).observe(
        max(
            0.0,
            duration_seconds,
        )
    )


def observe_worker_poll(
    result: str,
) -> None:
    if result not in {
        "processed",
        "idle",
        "error",
    }:
        result = "other"

    INVESTIGATION_WORKER_POLLS.labels(
        result=result
    ).inc()