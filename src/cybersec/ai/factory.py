from __future__ import annotations

import os

from cybersec.ai.ollama import (
    OllamaProvider,
)
from cybersec.ai.provider import (
    LLMProviderError,
    StructuredLLMProvider,
)


def build_provider(
    *,
    provider_name: str | None = None,
    model_name: str | None = None,
) -> StructuredLLMProvider:
    resolved_provider = (
        provider_name
        or os.getenv(
            "CYBERSEC_LLM_PROVIDER",
            "ollama",
        )
    ).strip().lower()

    resolved_model = (
        model_name
        or os.getenv(
            "CYBERSEC_LLM_MODEL",
            "qwen3:4b",
        )
    ).strip()

    if (
        resolved_provider
        != "ollama"
    ):
        raise LLMProviderError(
            "Unsupported LLM provider",
            retryable=False,
            category="configuration",
        )

    return OllamaProvider(
        model=resolved_model,
        base_url=os.getenv(
            "CYBERSEC_LLM_BASE_URL",
            "http://localhost:11434",
        ),
        timeout_seconds=(
            _read_float(
                "CYBERSEC_LLM_TIMEOUT_SECONDS",
                default=300.0,
                minimum=0.001,
            )
        ),
        context_window=(
            _read_int(
                "CYBERSEC_LLM_CONTEXT_WINDOW",
                default=4096,
                minimum=1024,
            )
        ),
        max_output_tokens=(
            _read_int(
                "CYBERSEC_LLM_MAX_OUTPUT_TOKENS",
                default=1600,
                minimum=1,
            )
        ),
        max_attempts=(
            _read_int(
                "CYBERSEC_LLM_MAX_ATTEMPTS",
                default=2,
                minimum=1,
                maximum=5,
            )
        ),
        retry_base_seconds=(
            _read_float(
                (
                    "CYBERSEC_LLM_"
                    "RETRY_BASE_SECONDS"
                ),
                default=1.0,
                minimum=0.0,
            )
        ),
        max_response_bytes=(
            _read_int(
                (
                    "CYBERSEC_LLM_"
                    "MAX_RESPONSE_BYTES"
                ),
                default=(
                    1024 * 1024
                ),
                minimum=1024,
            )
        ),
    )


def _read_int(
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int | None = None,
) -> int:
    raw_value = os.getenv(
        name
    )

    if raw_value is None:
        return default

    try:
        value = int(
            raw_value
        )

    except ValueError as exc:
        raise LLMProviderError(
            f"Invalid configuration: {name}",
            retryable=False,
            category="configuration",
        ) from exc

    if value < minimum:
        raise LLMProviderError(
            f"Invalid configuration: {name}",
            retryable=False,
            category="configuration",
        )

    if (
        maximum is not None
        and value > maximum
    ):
        raise LLMProviderError(
            f"Invalid configuration: {name}",
            retryable=False,
            category="configuration",
        )

    return value


def _read_float(
    name: str,
    *,
    default: float,
    minimum: float,
) -> float:
    raw_value = os.getenv(
        name
    )

    if raw_value is None:
        return default

    try:
        value = float(
            raw_value
        )

    except ValueError as exc:
        raise LLMProviderError(
            f"Invalid configuration: {name}",
            retryable=False,
            category="configuration",
        ) from exc

    if value < minimum:
        raise LLMProviderError(
            f"Invalid configuration: {name}",
            retryable=False,
            category="configuration",
        )

    return value