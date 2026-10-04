from __future__ import annotations

import argparse
import os
import time
from time import perf_counter

from prometheus_client import (
    start_http_server,
)

from cybersec.db.session import (
    create_session,
)
from cybersec.observability.metrics import (
    observe_investigation_worker_result,
    observe_worker_poll,
)
from cybersec.observability.tracing import (
    configure_tracing,
    force_flush_tracing,
)
from cybersec.workers.investigations import (
    InvestigationWorker,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Process queued AI "
            "investigation runs."
        )
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help=(
            "Process at most one queued "
            "investigation and exit."
        ),
    )

    args = parser.parse_args()

    configure_tracing(
        service_name=(
            "cybersec-investigation-worker"
        ),
    )

    poll_seconds = float(
        os.getenv(
            "CYBERSEC_WORKER_POLL_SECONDS",
            "2",
        )
    )

    if poll_seconds <= 0:
        raise ValueError(
            "CYBERSEC_WORKER_POLL_SECONDS "
            "must be positive"
        )

    metrics_host = os.getenv(
        "CYBERSEC_WORKER_METRICS_HOST",
        "127.0.0.1",
    ).strip()

    metrics_port = int(
        os.getenv(
            "CYBERSEC_WORKER_METRICS_PORT",
            "9101",
        )
    )

    if not (
        0
        <= metrics_port
        <= 65535
    ):
        raise ValueError(
            "CYBERSEC_WORKER_METRICS_PORT "
            "must be between 0 and 65535"
        )

    if metrics_port > 0:
        start_http_server(
            port=metrics_port,
            addr=metrics_host,
        )

        print(
            "Worker metrics listening on "
            f"http://{metrics_host}:"
            f"{metrics_port}"
        )

    worker = InvestigationWorker()

    print(
        "Investigation worker started"
    )

    try:
        while True:
            session = create_session()

            started_at = perf_counter()

            try:
                result = worker.process_one(
                    session
                )

            except Exception:
                observe_worker_poll(
                    "error"
                )
                raise

            finally:
                session.close()

            duration_seconds = (
                perf_counter()
                - started_at
            )

            if result is not None:
                observe_worker_poll(
                    "processed"
                )

                observe_investigation_worker_result(
                    status=result.status,
                    duration_seconds=(
                        duration_seconds
                    ),
                )

                print(
                    f"run={result.run_id} "
                    f"alert={result.alert_id} "
                    f"status={result.status}"
                )

            else:
                observe_worker_poll(
                    "idle"
                )

                if args.once:
                    print(
                        "No queued investigations"
                    )

            if args.once:
                return

            if result is None:
                time.sleep(
                    poll_seconds
                )

    finally:
        if args.once:
            force_flush_tracing(
                timeout_millis=5000
            )


if __name__ == "__main__":
    main()