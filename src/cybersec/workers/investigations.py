from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from opentelemetry import trace
from opentelemetry.trace import (
    SpanKind,
    Status,
    StatusCode,
)
from sqlalchemy.orm import Session

from cybersec.ai.factory import (
    build_provider as build_configured_provider,
)
from cybersec.ai.investigation import (
    InvestigationAlertContext,
    InvestigationEventContext,
    InvestigationGroundingError,
    InvestigationService,
)
from cybersec.ai.provider import (
    LLMProviderError,
    StructuredLLMProvider,
)
from cybersec.db.repositories.alerts import (
    AlertRepository,
)
from cybersec.db.repositories.events import (
    EventRepository,
)
from cybersec.db.repositories.investigations import (
    InvestigationRunRepository,
)
from cybersec.domain.investigations import (
    INVESTIGATION_STATUS_COMPLETED,
    INVESTIGATION_STATUS_FAILED,
)


ProviderFactory = Callable[
    [str, str],
    StructuredLLMProvider,
]


SAFE_WORKER_ERROR_LIMIT = 1000


_tracer = trace.get_tracer(
    __name__
)


class InvestigationWorkerError(
    RuntimeError
):
    """Known safe worker processing error."""


@dataclass(
    frozen=True,
    slots=True,
)
class InvestigationWorkerResult:
    run_id: str
    alert_id: str
    status: str


class InvestigationWorker:
    def __init__(
        self,
        *,
        provider_factory: (
            ProviderFactory | None
        ) = None,
    ) -> None:
        self._provider_factory = (
            provider_factory
            or build_provider
        )

    def process_one(
        self,
        session: Session,
    ) -> InvestigationWorkerResult | None:
        run_repository = (
            InvestigationRunRepository(
                session
            )
        )

        # Intentionally outside the tracing
        # span. Empty queue polls should not
        # generate Tempo traces.
        run = (
            run_repository
            .claim_next_queued()
        )

        if run is None:
            session.rollback()
            return None

        run_id = run.id
        alert_id = run.alert_id
        provider_name = run.provider
        model_name = run.model

        # Release the queue row lock before
        # performing expensive processing.
        session.commit()

        with _tracer.start_as_current_span(
            "investigation.process",
            kind=SpanKind.CONSUMER,
            record_exception=False,
            set_status_on_exception=False,
            attributes={
                "cybersec.llm.provider": (
                    provider_name
                ),
                "cybersec.llm.model": (
                    model_name
                ),
                (
                    "cybersec.investigation."
                    "status"
                ): "running",
            },
        ) as span:
            try:
                with (
                    _tracer
                    .start_as_current_span(
                        (
                            "investigation."
                            "load_context"
                        ),
                        record_exception=False,
                        set_status_on_exception=False,
                    )
                ):
                    alert_repository = (
                        AlertRepository(
                            session
                        )
                    )

                    alert = (
                        alert_repository
                        .get_by_id(
                            alert_id
                        )
                    )

                    if alert is None:
                        raise (
                            InvestigationWorkerError(
                                "Alert no longer exists"
                            )
                        )

                    fingerprints = (
                        alert
                        .evidence_event_fingerprints
                    )

                    if not fingerprints:
                        raise (
                            InvestigationWorkerError(
                                "Alert has no evidence"
                            )
                        )

                    event_repository = (
                        EventRepository(
                            session
                        )
                    )

                    events = (
                        event_repository
                        .get_by_fingerprints(
                            fingerprints
                        )
                    )

                    if len(
                        events
                    ) != len(
                        fingerprints
                    ):
                        raise (
                            InvestigationWorkerError(
                                "Alert evidence integrity "
                                "check failed"
                            )
                        )

                    alert_context = (
                        InvestigationAlertContext
                        .model_validate(
                            alert
                        )
                    )

                    event_contexts = [
                        (
                            InvestigationEventContext
                            .model_validate(
                                event
                            )
                        )
                        for event in events
                    ]

                provider = (
                    self._provider_factory(
                        provider_name,
                        model_name,
                    )
                )

                service = (
                    InvestigationService(
                        provider
                    )
                )

                result = service.investigate(
                    alert=alert_context,
                    events=event_contexts,
                )

                with (
                    _tracer
                    .start_as_current_span(
                        (
                            "investigation."
                            "persist_completed"
                        ),
                        record_exception=False,
                        set_status_on_exception=False,
                    )
                ):
                    run_repository = (
                        InvestigationRunRepository(
                            session
                        )
                    )

                    run_repository.mark_completed(
                        run_id=run_id,
                        result=result.model_dump(
                            mode="json"
                        ),
                    )

                    session.commit()

                span.set_attribute(
                    (
                        "cybersec.investigation."
                        "status"
                    ),
                    (
                        INVESTIGATION_STATUS_COMPLETED
                    ),
                )

                span.set_status(
                    Status(
                        StatusCode.OK
                    )
                )

                return (
                    InvestigationWorkerResult(
                        run_id=run_id,
                        alert_id=alert_id,
                        status=(
                            INVESTIGATION_STATUS_COMPLETED
                        ),
                    )
                )

            except Exception as exc:
                session.rollback()

                span.set_attribute(
                    (
                        "cybersec.investigation."
                        "status"
                    ),
                    (
                        INVESTIGATION_STATUS_FAILED
                    ),
                )

                span.set_attribute(
                    (
                        "cybersec.error."
                        "category"
                    ),
                    _trace_error_category(
                        exc
                    ),
                )

                # Do not attach exception text.
                # Arbitrary exception messages
                # may contain telemetry or secrets.
                span.set_status(
                    Status(
                        StatusCode.ERROR
                    )
                )

                with (
                    _tracer
                    .start_as_current_span(
                        (
                            "investigation."
                            "persist_failed"
                        ),
                        record_exception=False,
                        set_status_on_exception=False,
                    )
                ):
                    run_repository = (
                        InvestigationRunRepository(
                            session
                        )
                    )

                    run_repository.mark_failed(
                        run_id=run_id,
                        error_message=(
                            _safe_error_message(
                                exc
                            )
                        ),
                    )

                    session.commit()

                return (
                    InvestigationWorkerResult(
                        run_id=run_id,
                        alert_id=alert_id,
                        status=(
                            INVESTIGATION_STATUS_FAILED
                        ),
                    )
                )


def build_provider(
    provider_name: str,
    model_name: str,
) -> StructuredLLMProvider:
    return build_configured_provider(
        provider_name=provider_name,
        model_name=model_name,
    )


def _safe_error_message(
    exc: Exception,
) -> str:
    if isinstance(
        exc,
        LLMProviderError,
    ):
        message = (
            "LLMProviderError"
            f"[{exc.category}]: "
            f"{exc}"
        )

    elif isinstance(
        exc,
        InvestigationWorkerError,
    ):
        message = (
            "InvestigationWorkerError: "
            f"{exc}"
        )

    else:
        # Do not persist arbitrary exception
        # text. It may contain telemetry,
        # connection data, or secrets.
        message = (
            f"{type(exc).__name__}: "
            "investigation processing failed"
        )

    return message[
        :SAFE_WORKER_ERROR_LIMIT
    ]


def _trace_error_category(
    exc: Exception,
) -> str:
    if isinstance(
        exc,
        LLMProviderError,
    ):
        return (
            f"llm.{exc.category}"
        )

    if isinstance(
        exc,
        InvestigationGroundingError,
    ):
        return "grounding"

    if isinstance(
        exc,
        InvestigationWorkerError,
    ):
        return "worker"

    return "internal"

def test_grounding_error_has_specific_trace_category(
) -> None:
    exc = InvestigationGroundingError(
        "sensitive generated content"
    )

    assert (
        _trace_error_category(exc)
        == "grounding"
    )