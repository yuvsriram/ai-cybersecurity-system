from __future__ import annotations

from time import perf_counter

from starlette.types import (
    ASGIApp,
    Message,
    Receive,
    Scope,
    Send,
)

from cybersec.observability.metrics import (
    HTTP_REQUEST_DURATION,
    HTTP_REQUESTS,
    HTTP_REQUESTS_IN_PROGRESS,
)


class PrometheusHTTPMiddleware:
    def __init__(
        self,
        app: ASGIApp,
    ) -> None:
        self._app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if (
            scope["type"]
            != "http"
        ):
            await self._app(
                scope,
                receive,
                send,
            )
            return

        method = str(
            scope.get(
                "method",
                "UNKNOWN",
            )
        )

        started_at = (
            perf_counter()
        )

        status_code = 500

        HTTP_REQUESTS_IN_PROGRESS.inc()

        async def send_wrapper(
            message: Message,
        ) -> None:
            nonlocal status_code

            if (
                message["type"]
                == "http.response.start"
            ):
                status_code = int(
                    message["status"]
                )

            await send(
                message
            )

        try:
            await self._app(
                scope,
                receive,
                send_wrapper,
            )

        finally:
            duration = (
                perf_counter()
                - started_at
            )

            route_object = (
                scope.get(
                    "route"
                )
            )

            route = getattr(
                route_object,
                "path",
                None,
            )

            if not route:
                route = "unmatched"

            HTTP_REQUESTS.labels(
                method=method,
                route=route,
                status_code=str(
                    status_code
                ),
            ).inc()

            HTTP_REQUEST_DURATION.labels(
                method=method,
                route=route,
            ).observe(
                duration
            )

            HTTP_REQUESTS_IN_PROGRESS.dec()