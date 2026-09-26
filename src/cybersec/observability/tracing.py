from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
    OTLPSpanExporter,
)
from opentelemetry.instrumentation.fastapi import (
    FastAPIInstrumentor,
)
from opentelemetry.instrumentation.sqlalchemy import (
    SQLAlchemyInstrumentor,
)
from opentelemetry.sdk.resources import (
    Resource,
)
from opentelemetry.sdk.trace import (
    TracerProvider,
)
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
)
from sqlalchemy import Engine


@dataclass(
    frozen=True,
    slots=True,
)
class TracingConfig:
    enabled: bool
    endpoint: str
    environment: str


_tracing_configured = False
_sqlalchemy_instrumented = False

_tracer_provider: (
    TracerProvider | None
) = None


def get_tracing_config() -> TracingConfig:
    load_dotenv()

    raw_enabled = os.getenv(
        "CYBERSEC_TRACING_ENABLED",
        "false",
    ).strip().lower()

    enabled = raw_enabled in {
        "1",
        "true",
        "yes",
        "on",
    }

    endpoint = os.getenv(
        "CYBERSEC_OTLP_TRACES_ENDPOINT",
        (
            "http://127.0.0.1:"
            "4318/v1/traces"
        ),
    ).strip()

    environment = os.getenv(
        "CYBERSEC_ENVIRONMENT",
        "development",
    ).strip()

    if not endpoint:
        raise ValueError(
            "CYBERSEC_OTLP_TRACES_ENDPOINT "
            "must not be empty"
        )

    if not environment:
        raise ValueError(
            "CYBERSEC_ENVIRONMENT "
            "must not be empty"
        )

    return TracingConfig(
        enabled=enabled,
        endpoint=endpoint,
        environment=environment,
    )


def configure_tracing(
    *,
    service_name: str,
    engine: Engine | None = None,
) -> bool:
    global _tracing_configured
    global _sqlalchemy_instrumented
    global _tracer_provider

    config = get_tracing_config()

    if not config.enabled:
        return False

    if not service_name.strip():
        raise ValueError(
            "service_name must not be empty"
        )

    if not _tracing_configured:
        resource = Resource.create(
            {
                "service.name": (
                    service_name.strip()
                ),
                "deployment.environment": (
                    config.environment
                ),
            }
        )

        provider = TracerProvider(
            resource=resource
        )

        exporter = OTLPSpanExporter(
            endpoint=config.endpoint,
            timeout=5,
        )

        provider.add_span_processor(
            BatchSpanProcessor(
                exporter
            )
        )

        trace.set_tracer_provider(
            provider
        )

        _tracer_provider = provider
        _tracing_configured = True

    if (
        engine is not None
        and not _sqlalchemy_instrumented
    ):
        SQLAlchemyInstrumentor().instrument(
            engine=engine
        )

        _sqlalchemy_instrumented = True

    return True


def force_flush_tracing(
    *,
    timeout_millis: int = 5000,
) -> bool:
    if timeout_millis <= 0:
        raise ValueError(
            "timeout_millis must be positive"
        )

    provider = _tracer_provider

    if provider is None:
        return False

    return provider.force_flush(
        timeout_millis=timeout_millis
    )


def instrument_fastapi_app(
    app: object,
) -> None:
    config = get_tracing_config()

    if not config.enabled:
        return

    FastAPIInstrumentor.instrument_app(
        app,
        excluded_urls=(
            r"/health(?:/.*)?$,"
            r"/metrics$"
        ),
    )