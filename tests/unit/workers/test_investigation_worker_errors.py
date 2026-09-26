from cybersec.ai.provider import (
    LLMProviderError,
)
from cybersec.workers.investigations import (
    InvestigationWorkerError,
    _safe_error_message,
)
from cybersec.ai.investigation import (
    InvestigationGroundingError,
)
from cybersec.workers.investigations import (
    _trace_error_category,
)


def test_provider_error_keeps_only_safe_message() -> None:
    error = LLMProviderError(
        "Ollama returned HTTP 503",
        retryable=True,
        category="http",
    )

    message = (
        _safe_error_message(
            error
        )
    )

    assert message == (
        "LLMProviderError[http]: "
        "Ollama returned HTTP 503"
    )


def test_unexpected_error_detail_is_not_persisted() -> None:
    error = RuntimeError(
        "password=super-secret-value"
    )

    message = (
        _safe_error_message(
            error
        )
    )

    assert (
        "super-secret-value"
        not in message
    )

    assert message == (
        "RuntimeError: "
        "investigation processing failed"
    )


def test_known_worker_error_is_preserved() -> None:
    error = (
        InvestigationWorkerError(
            "Alert has no evidence"
        )
    )

    assert (
        _safe_error_message(
            error
        )
        == (
            "InvestigationWorkerError: "
            "Alert has no evidence"
        )
    )

def test_grounding_error_has_specific_trace_category(
) -> None:
    exc = InvestigationGroundingError(
        "sensitive generated content"
    )

    assert (
        _trace_error_category(exc)
        == "grounding"
    )