from __future__ import annotations

import json
import time
from collections.abc import Callable
from http.client import (
    HTTPException as HTTPClientError,
)
from typing import (
    Any,
    Mapping,
    Sequence,
)
from urllib.error import (
    HTTPError,
    URLError,
)
from urllib.parse import urlsplit
from urllib.request import (
    Request,
    urlopen,
)

from opentelemetry import trace
from opentelemetry.trace import (
    SpanKind,
)

from cybersec.ai.provider import (
    ChatMessage,
    LLMProviderError,
)


RETRYABLE_HTTP_CODES = {
    408,
    429,
}


_tracer = trace.get_tracer(
    __name__
)


class OllamaProvider:
    def __init__(
        self,
        *,
        model: str = "qwen3:4b",
        base_url: str = (
            "http://localhost:11434"
        ),
        timeout_seconds: float = (
            300.0
        ),
        context_window: int = 4096,
        max_output_tokens: int = 1600,
        max_attempts: int = 2,
        retry_base_seconds: float = 1.0,
        max_response_bytes: int = (
            1024 * 1024
        ),
        sleep_fn: Callable[
            [float],
            None,
        ] = time.sleep,
    ) -> None:
        if not model.strip():
            raise ValueError(
                "model must not be empty"
            )

        if timeout_seconds <= 0:
            raise ValueError(
                "timeout_seconds must "
                "be positive"
            )

        if context_window < 1024:
            raise ValueError(
                "context_window must be "
                "at least 1024"
            )

        if max_output_tokens < 1:
            raise ValueError(
                "max_output_tokens must "
                "be positive"
            )

        if not (
            1
            <= max_attempts
            <= 5
        ):
            raise ValueError(
                "max_attempts must be "
                "between 1 and 5"
            )

        if retry_base_seconds < 0:
            raise ValueError(
                "retry_base_seconds must "
                "not be negative"
            )

        if (
            max_response_bytes
            < 1024
        ):
            raise ValueError(
                "max_response_bytes must "
                "be at least 1024"
            )

        parsed_url = urlsplit(
            base_url
        )

        if (
            parsed_url.scheme
            not in {
                "http",
                "https",
            }
            or not parsed_url.netloc
        ):
            raise ValueError(
                "base_url must be a valid "
                "HTTP or HTTPS URL"
            )

        if (
            parsed_url.username
            is not None
            or parsed_url.password
            is not None
        ):
            raise ValueError(
                "base_url must not contain "
                "embedded credentials"
            )

        self._server_address = (
            parsed_url.hostname
            or "unknown"
        )

        self._server_port = (
            parsed_url.port
            or (
                443
                if parsed_url.scheme
                == "https"
                else 80
            )
        )

        self._model = (
            model.strip()
        )

        self._base_url = (
            base_url.rstrip("/")
        )

        self._timeout_seconds = (
            timeout_seconds
        )

        self._context_window = (
            context_window
        )

        self._max_output_tokens = (
            max_output_tokens
        )

        self._max_attempts = (
            max_attempts
        )

        self._retry_base_seconds = (
            retry_base_seconds
        )

        self._max_response_bytes = (
            max_response_bytes
        )

        self._sleep_fn = (
            sleep_fn
        )

    @property
    def model(
        self,
    ) -> str:
        return self._model

    def generate_structured(
        self,
        *,
        messages: Sequence[
            ChatMessage
        ],
        response_schema: Mapping[
            str,
            Any,
        ],
    ) -> str:
        for attempt in range(
            1,
            self._max_attempts + 1,
        ):
            try:
                return (
                    self._generate_once(
                        messages=messages,
                        response_schema=(
                            response_schema
                        ),
                        attempt=attempt,
                    )
                )

            except LLMProviderError as exc:
                if (
                    not exc.retryable
                    or attempt
                    >= self._max_attempts
                ):
                    raise

                delay = min(
                    self._retry_base_seconds
                    * (
                        2
                        ** (
                            attempt - 1
                        )
                    ),
                    8.0,
                )

                self._sleep_fn(
                    delay
                )

        raise LLMProviderError(
            "Ollama request failed",
            category=(
                "provider_error"
            ),
        )

    def _generate_once(
        self,
        *,
        messages: Sequence[
            ChatMessage
        ],
        response_schema: Mapping[
            str,
            Any,
        ],
        attempt: int,
    ) -> str:
        payload = {
            "model": self._model,
            "stream": False,
            "think": False,
            "keep_alive": "10m",
            "messages": [
                {
                    "role": (
                        message.role
                    ),
                    "content": (
                        message.content
                    ),
                }
                for message in (
                    messages
                )
            ],
            "format": dict(
                response_schema
            ),
            "options": {
                "temperature": 0,
                "num_ctx": (
                    self._context_window
                ),
                "num_predict": (
                    self
                    ._max_output_tokens
                ),
            },
        }

        request = Request(
            url=(
                f"{self._base_url}"
                "/api/chat"
            ),
            data=json.dumps(
                payload
            ).encode(
                "utf-8"
            ),
            headers={
                "Content-Type": (
                    "application/json"
                ),
            },
            method="POST",
        )

        with _tracer.start_as_current_span(
            "ollama.chat",
            kind=SpanKind.CLIENT,
            record_exception=False,
            set_status_on_exception=False,
            attributes={
                "cybersec.llm.provider": (
                    "ollama"
                ),
                "cybersec.llm.model": (
                    self._model
                ),
                "cybersec.llm.attempt": (
                    attempt
                ),
                "server.address": (
                    self._server_address
                ),
                "server.port": (
                    self._server_port
                ),
            },
        ) as span:
            try:
                with urlopen(
                    request,
                    timeout=(
                        self
                        ._timeout_seconds
                    ),
                ) as response:
                    response_body = (
                        response.read(
                            self
                            ._max_response_bytes
                            + 1
                        )
                    )

                    raw_status = getattr(
                        response,
                        "status",
                        None,
                    )

                    status_code = (
                        raw_status
                        if isinstance(
                            raw_status,
                            int,
                        )
                        else 200
                    )

                    span.set_attribute(
                        (
                            "http.response."
                            "status_code"
                        ),
                        status_code,
                    )

            except HTTPError as exc:
                span.set_attribute(
                    (
                        "http.response."
                        "status_code"
                    ),
                    exc.code,
                )

                retryable = (
                    exc.code
                    in RETRYABLE_HTTP_CODES
                    or (
                        500
                        <= exc.code
                        <= 599
                    )
                )

                raise LLMProviderError(
                    "Ollama returned HTTP "
                    f"{exc.code}",
                    retryable=retryable,
                    category="http",
                ) from exc

            except TimeoutError as exc:
                raise LLMProviderError(
                    "Ollama request timed out",
                    retryable=True,
                    category="timeout",
                ) from exc

            except URLError as exc:
                raise LLMProviderError(
                    "Unable to connect "
                    "to Ollama",
                    retryable=True,
                    category="connection",
                ) from exc

            except (
                HTTPClientError,
                OSError,
            ) as exc:
                raise LLMProviderError(
                    "Ollama transport "
                    "request failed",
                    retryable=True,
                    category="connection",
                ) from exc

            if (
                len(response_body)
                > self._max_response_bytes
            ):
                raise LLMProviderError(
                    "Ollama response exceeded "
                    "the configured size limit",
                    retryable=False,
                    category=(
                        "response_too_large"
                    ),
                )

            span.set_attribute(
                (
                    "cybersec.llm."
                    "response_bytes"
                ),
                len(
                    response_body
                ),
            )

        try:
            decoded = (
                response_body.decode(
                    "utf-8"
                )
            )

            parsed = json.loads(
                decoded
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise LLMProviderError(
                "Ollama returned an "
                "invalid response",
                retryable=False,
                category=(
                    "invalid_response"
                ),
            ) from exc

        if not isinstance(
            parsed,
            dict,
        ):
            raise LLMProviderError(
                "Ollama returned an "
                "invalid chat response",
                retryable=False,
                category=(
                    "invalid_response"
                ),
            )

        done_reason = (
            parsed.get(
                "done_reason"
            )
        )

        if (
            done_reason
            == "length"
        ):
            raise LLMProviderError(
                "Ollama response was "
                "truncated because the "
                "output token limit "
                "was reached",
                retryable=False,
                category="truncated",
            )

        try:
            message = (
                parsed["message"]
            )

            content = (
                message["content"]
            )

        except (
            KeyError,
            TypeError,
        ) as exc:
            raise LLMProviderError(
                "Ollama returned an "
                "invalid chat response",
                retryable=False,
                category=(
                    "invalid_response"
                ),
            ) from exc

        if not isinstance(
            content,
            str,
        ):
            raise LLMProviderError(
                "Ollama response content "
                "was not a string",
                retryable=False,
                category=(
                    "invalid_response"
                ),
            )

        if not content.strip():
            raise LLMProviderError(
                "Ollama returned empty "
                "content",
                retryable=False,
                category=(
                    "invalid_response"
                ),
            )

        return content