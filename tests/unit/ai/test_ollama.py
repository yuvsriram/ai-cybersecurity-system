from __future__ import annotations

import io
import json
from urllib.error import (
    HTTPError,
    URLError,
)

import pytest

import cybersec.ai.ollama as ollama_module
from cybersec.ai.ollama import (
    OllamaProvider,
)
from cybersec.ai.provider import (
    ChatMessage,
    LLMProviderError,
)


class FakeResponse:
    def __init__(
        self,
        body: bytes,
    ) -> None:
        self._body = body

    def __enter__(
        self,
    ) -> FakeResponse:
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ) -> bool:
        return False

    def read(
        self,
        amount: int,
    ) -> bytes:
        return self._body[
            :amount
        ]


def _success_response() -> bytes:
    return json.dumps(
        {
            "done_reason": "stop",
            "message": {
                "content": (
                    '{"result":"ok"}'
                )
            },
        }
    ).encode(
        "utf-8"
    )


def test_transient_connection_failure_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    def fake_urlopen(
        request,
        *,
        timeout,
    ):
        nonlocal attempts
        attempts += 1

        if attempts == 1:
            raise URLError(
                "sensitive-network-detail"
            )

        return FakeResponse(
            _success_response()
        )

    monkeypatch.setattr(
        ollama_module,
        "urlopen",
        fake_urlopen,
    )

    provider = OllamaProvider(
        max_attempts=2,
        retry_base_seconds=0,
        sleep_fn=lambda _: None,
    )

    result = (
        provider.generate_structured(
            messages=[
                ChatMessage(
                    role="user",
                    content="test",
                )
            ],
            response_schema={},
        )
    )

    assert attempts == 2

    assert result == (
        '{"result":"ok"}'
    )


def test_non_retryable_http_error_does_not_leak_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    def fake_urlopen(
        request,
        *,
        timeout,
    ):
        nonlocal attempts
        attempts += 1

        raise HTTPError(
            url=(
                "http://localhost:11434"
            ),
            code=400,
            msg="bad request",
            hdrs=None,
            fp=io.BytesIO(
                b"secret upstream body"
            ),
        )

    monkeypatch.setattr(
        ollama_module,
        "urlopen",
        fake_urlopen,
    )

    provider = OllamaProvider(
        max_attempts=3,
        retry_base_seconds=0,
        sleep_fn=lambda _: None,
    )

    with pytest.raises(
        LLMProviderError
    ) as exc_info:
        provider.generate_structured(
            messages=[],
            response_schema={},
        )

    assert attempts == 1

    assert (
        exc_info.value.retryable
        is False
    )

    assert (
        exc_info.value.category
        == "http"
    )

    assert (
        "secret upstream body"
        not in str(
            exc_info.value
        )
    )


def test_retryable_http_error_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    def fake_urlopen(
        request,
        *,
        timeout,
    ):
        nonlocal attempts
        attempts += 1

        raise HTTPError(
            url=(
                "http://localhost:11434"
            ),
            code=503,
            msg="unavailable",
            hdrs=None,
            fp=io.BytesIO(
                b"internal detail"
            ),
        )

    monkeypatch.setattr(
        ollama_module,
        "urlopen",
        fake_urlopen,
    )

    provider = OllamaProvider(
        max_attempts=2,
        retry_base_seconds=0,
        sleep_fn=lambda _: None,
    )

    with pytest.raises(
        LLMProviderError
    ) as exc_info:
        provider.generate_structured(
            messages=[],
            response_schema={},
        )

    assert attempts == 2

    assert (
        exc_info.value.retryable
        is True
    )


def test_response_size_limit_is_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(
        request,
        *,
        timeout,
    ):
        return FakeResponse(
            b"x" * 1025
        )

    monkeypatch.setattr(
        ollama_module,
        "urlopen",
        fake_urlopen,
    )

    provider = OllamaProvider(
        max_response_bytes=1024,
    )

    with pytest.raises(
        LLMProviderError
    ) as exc_info:
        provider.generate_structured(
            messages=[],
            response_schema={},
        )

    assert (
        exc_info.value.category
        == "response_too_large"
    )