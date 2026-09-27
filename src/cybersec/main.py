from __future__ import annotations

from fastapi import (
    Depends,
    FastAPI,
)
from starlette.middleware.trustedhost import (
    TrustedHostMiddleware,
)

from cybersec.api.dependencies import (
    require_minimum_role,
)
from cybersec.api.middleware import (
    SecurityHeadersMiddleware,
)
from cybersec.api.routes import (
    audit,
    cases,
    correlation,
    investigation_runs,
)
from cybersec.api.routes.analysis import (
    router as analysis_router,
)
from cybersec.api.routes.alerts import (
    router as alerts_router,
)
from cybersec.api.routes.events import (
    router as events_router,
)
from cybersec.api.routes.health import (
    router as health_router,
)
from cybersec.api.routes.ingestion import (
    router as ingestion_router,
)
from cybersec.api.routes.metrics import (
    router as metrics_router,
)
from cybersec.core.config import (
    get_settings,
)
from cybersec.db.session import (
    engine,
)
from cybersec.observability.middleware import (
    PrometheusHTTPMiddleware,
)
from cybersec.observability.tracing import (
    configure_tracing,
    instrument_fastapi_app,
)


def create_app() -> FastAPI:
    settings = get_settings()

    configure_tracing(
        service_name="cybersec-api",
        engine=engine,
    )

    app = FastAPI(
        title=(
            "AI Cybersecurity "
            "Threat Detection API"
        ),
        version="0.1.0",
        description=(
            "Security telemetry, detection, "
            "alerting, and AI-assisted "
            "investigation platform."
        ),
        docs_url=(
            "/docs"
            if settings.docs_enabled
            else None
        ),
        redoc_url=(
            "/redoc"
            if settings.docs_enabled
            else None
        ),
        openapi_url=(
            "/openapi.json"
            if settings.docs_enabled
            else None
        ),
    )

    app.add_middleware(
        PrometheusHTTPMiddleware
    )

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(
            settings.trusted_hosts
        ),
    )

    app.add_middleware(
        SecurityHeadersMiddleware
    )

    instrument_fastapi_app(
        app
    )

    app.include_router(
        health_router
    )

    app.include_router(
        metrics_router
    )

    app.include_router(
        events_router,
        dependencies=[
            Depends(
                require_minimum_role(
                    "viewer"
                )
            )
        ],
    )

    app.include_router(
        alerts_router,
        dependencies=[
            Depends(
                require_minimum_role(
                    "viewer"
                )
            )
        ],
    )

    app.include_router(
        analysis_router,
        dependencies=[
            Depends(
                require_minimum_role(
                    "viewer"
                )
            )
        ],
    )

    app.include_router(
        ingestion_router,
        dependencies=[
            Depends(
                require_minimum_role(
                    "admin"
                )
            )
        ],
    )

    # Investigation history is readable by
    # viewers. Mutating investigation routes
    # enforce stronger roles themselves.
    app.include_router(
        investigation_runs.router,
        dependencies=[
            Depends(
                require_minimum_role(
                    "viewer"
                )
            )
        ],
    )

    app.include_router(
        cases.router,
        dependencies=[
            Depends(
                require_minimum_role(
                    "analyst"
                )
            )
        ],
    )

    app.include_router(
        correlation.router,
        dependencies=[
            Depends(
                require_minimum_role(
                    "analyst"
                )
            )
        ],
    )

    app.include_router(
        audit.router,
        dependencies=[
            Depends(
                require_minimum_role(
                    "admin"
                )
            )
        ],
    )

    return app


app = create_app()