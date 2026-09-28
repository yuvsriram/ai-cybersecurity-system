from __future__ import annotations

import os

from pathlib import Path

from dotenv import load_dotenv

from cybersec.ai.groq import (
    GroqProvider,
)
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
    load_dotenv(
        dotenv_path=(
            Path(__file__)
            .resolve()
            .parents[3]
            / ".env"
        ),
        override=False,
    )

    resolved_provider = (
        provider_name
        or os.getenv(
            "CYBERSEC_LLM_PROVIDER",
            "ollama",
        )
    ).strip().lower()

    configured_model = (
        model_name
        or os.getenv(
            "CYBERSEC_LLM_MODEL"
        )
    )

    if configured_model is not None:
        resolved_model = (
            configured_model.strip()
        )

        if not resolved_model:
            raise LLMProviderError(
                (
                    "CYBERSEC_LLM_MODEL "
                    "must not be empty"
                ),
                retryable=False,
                category="configuration",
            )

    elif resolved_provider == "groq":
        resolved_model = (
            "openai/gpt-oss-20b"
        )

    else:
        resolved_model = (
            "qwen3:4b"
        )

    timeout_seconds = _read_float(
        "CYBERSEC_LLM_TIMEOUT_SECONDS",
        default=300.0,
        minimum=0.001,
    )

    max_output_tokens = _read_int(
        (
            "CYBERSEC_LLM_"
            "MAX_OUTPUT_TOKENS"
        ),
        default=1600,
        minimum=1,
    )

    max_attempts = _read_int(
        "CYBERSEC_LLM_MAX_ATTEMPTS",
        default=2,
        minimum=1,
        maximum=5,
    )

    retry_base_seconds = _read_float(
        (
            "CYBERSEC_LLM_"
            "RETRY_BASE_SECONDS"
        ),
        default=1.0,
        minimum=0.0,
    )

    max_response_bytes = _read_int(
        (
            "CYBERSEC_LLM_"
            "MAX_RESPONSE_BYTES"
        ),
        default=(
            1024 * 1024
        ),
        minimum=1024,
    )

    if resolved_provider == "ollama":
        return OllamaProvider(
            model=resolved_model,
            base_url=os.getenv(
                "CYBERSEC_LLM_BASE_URL",
                (
                    "http://localhost:"
                    "11434"
                ),
            ),
            timeout_seconds=(
                timeout_seconds
            ),
            context_window=(
                _read_int(
                    (
                        "CYBERSEC_LLM_"
                        "CONTEXT_WINDOW"
                    ),
                    default=4096,
                    minimum=1024,
                )
            ),
            max_output_tokens=(
                max_output_tokens
            ),
            max_attempts=(
                max_attempts
            ),
            retry_base_seconds=(
                retry_base_seconds
            ),
            max_response_bytes=(
                max_response_bytes
            ),
        )

    if resolved_provider == "groq":
        return GroqProvider(
            api_key=(
                _required_environment_variable(
                    "GROQ_API_KEY"
                )
            ),
            model=resolved_model,
            base_url=os.getenv(
                "CYBERSEC_GROQ_BASE_URL",
                (
                    "https://api.groq.com"
                    "/openai/v1"
                ),
            ),
            timeout_seconds=(
                timeout_seconds
            ),
            max_output_tokens=(
                max_output_tokens
            ),
            max_attempts=(
                max_attempts
            ),
            retry_base_seconds=(
                retry_base_seconds
            ),
            max_response_bytes=(
                max_response_bytes
            ),
        )

    raise LLMProviderError(
        "Unsupported LLM provider",
        retryable=False,
        category="configuration",
    )


def _required_environment_variable(
    name: str,
) -> str:
    value = os.getenv(
        name
    )

    if value is None:
        raise LLMProviderError(
            (
                f"{name} must be "
                "configured"
            ),
            retryable=False,
            category="configuration",
        )

    normalized = (
        value.strip()
    )

    if not normalized:
        raise LLMProviderError(
            (
                f"{name} must not "
                "be empty"
            ),
            retryable=False,
            category="configuration",
        )

    return normalized


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
            (
                "Invalid configuration: "
                f"{name}"
            ),
            retryable=False,
            category="configuration",
        ) from exc

    if value < minimum:
        raise LLMProviderError(
            (
                "Invalid configuration: "
                f"{name}"
            ),
            retryable=False,
            category="configuration",
        )

    if (
        maximum is not None
        and value > maximum
    ):
        raise LLMProviderError(
            (
                "Invalid configuration: "
                f"{name}"
            ),
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
            (
                "Invalid configuration: "
                f"{name}"
            ),
            retryable=False,
            category="configuration",
        ) from exc

    if value < minimum:
        raise LLMProviderError(
            (
                "Invalid configuration: "
                f"{name}"
            ),
            retryable=False,
            category="configuration",
        )

    return value