from __future__ import annotations

import io
import json

from email.message import (
    Message,
)
from urllib.error import (
    HTTPError,
)
from urllib.request import (
    Request,
)

import pytest

import cybersec.ai.groq as groq_module

from cybersec.ai.groq import (
    GroqProvider,
)
from cybersec.ai.provider import (
    ChatMessage,
    LLMProviderError,
)


class FakeResponse:
    def __init__(
        self,
        payload: bytes,
        *,
        status: int = 200,
    ) -> None:
        self._payload = payload
        self.status = status

    def read(
        self,
        amount: int = -1,
    ) -> bytes:
        if amount < 0:
            return self._payload

        return self._payload[
            :amount
        ]

    def __enter__(
        self,
    ) -> FakeResponse:
        return self

    def __exit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        return None


def make_chat_response(
    content: str,
    *,
    finish_reason: str = "stop",
) -> bytes:
    return json.dumps(
        {
            "choices": [
                {
                    "finish_reason": (
                        finish_reason
                    ),
                    "message": {
                        "role": (
                            "assistant"
                        ),
                        "content": (
                            content
                        ),
                    },
                }
            ]
        }
    ).encode(
        "utf-8"
    )


def test_structured_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_request: (
        Request | None
    ) = None

    def fake_urlopen(
        request: Request,
        *,
        timeout: float,
    ) -> FakeResponse:
        nonlocal captured_request

        captured_request = (
            request
        )

        assert timeout == 15.0

        return FakeResponse(
            make_chat_response(
                '{"summary":"ok"}'
            )
        )

    monkeypatch.setattr(
        groq_module,
        "urlopen",
        fake_urlopen,
    )

    provider = GroqProvider(
        api_key="test-secret-key",
        model=(
            "openai/gpt-oss-20b"
        ),
        timeout_seconds=15.0,
        max_attempts=1,
    )

    result = (
        provider.generate_structured(
            messages=[
                ChatMessage(
                    role="system",
                    content=(
                        "Return JSON."
                    ),
                ),
                ChatMessage(
                    role="user",
                    content="Test.",
                ),
            ],
            response_schema={
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string"
                    }
                },
                "required": [
                    "summary"
                ],
                "additionalProperties": (
                    False
                ),
            },
        )
    )

    assert result == (
        '{"summary":"ok"}'
    )

    assert (
        captured_request
        is not None
    )

    payload = json.loads(
        (
            captured_request.data
            or b""
        ).decode(
            "utf-8"
        )
    )

    assert payload["model"] == (
        "openai/gpt-oss-20b"
    )

    assert (
        payload[
            "response_format"
        ]["type"]
        == "json_schema"
    )

    assert (
        payload[
            "response_format"
        ]["json_schema"]["strict"]
        is False
    )

    assert (
        captured_request.get_header(
            "Authorization"
        )
        == (
            "Bearer "
            "test-secret-key"
        )
    )

    assert (
        captured_request.get_header(
            "User-agent"
        )
        == (
            "ai-cybersecurity-system/0.1"
        )
    )


def test_retryable_http_error_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    sleeps: list[
        float
    ] = []

    def fake_urlopen(
        request: Request,
        *,
        timeout: float,
    ) -> FakeResponse:
        del request
        del timeout

        nonlocal attempts

        attempts += 1

        if attempts == 1:
            raise HTTPError(
                url=(
                    "https://api.groq.com"
                ),
                code=429,
                msg=(
                    "Too Many Requests"
                ),
                hdrs=Message(),
                fp=io.BytesIO(
                    (
                        b"sensitive "
                        b"provider body"
                    )
                ),
            )

        return FakeResponse(
            make_chat_response(
                '{"summary":"ok"}'
            )
        )

    monkeypatch.setattr(
        groq_module,
        "urlopen",
        fake_urlopen,
    )

    provider = GroqProvider(
        api_key="test-key",
        max_attempts=2,
        retry_base_seconds=0.25,
        sleep_fn=sleeps.append,
    )

    result = (
        provider.generate_structured(
            messages=[],
            response_schema={
                "type": "object"
            },
        )
    )

    assert result == (
        '{"summary":"ok"}'
    )

    assert attempts == 2

    assert sleeps == [
        0.25
    ]


def test_non_retryable_http_error_does_not_leak_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(
        request: Request,
        *,
        timeout: float,
    ) -> FakeResponse:
        del request
        del timeout

        raise HTTPError(
            url=(
                "https://api.groq.com"
            ),
            code=401,
            msg="Unauthorized",
            hdrs=Message(),
            fp=io.BytesIO(
                (
                    b"provider secret "
                    b"diagnostic"
                )
            ),
        )

    monkeypatch.setattr(
        groq_module,
        "urlopen",
        fake_urlopen,
    )

    provider = GroqProvider(
        api_key="test-key",
        max_attempts=2,
    )

    with pytest.raises(
        LLMProviderError
    ) as exc_info:
        provider.generate_structured(
            messages=[],
            response_schema={
                "type": "object"
            },
        )

    message = str(
        exc_info.value
    )

    assert message == (
        "Groq returned HTTP 401"
    )

    assert (
        "provider secret"
        not in message
    )


def test_response_size_limit_is_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(
        request: Request,
        *,
        timeout: float,
    ) -> FakeResponse:
        del request
        del timeout

        return FakeResponse(
            b"x" * 1025
        )

    monkeypatch.setattr(
        groq_module,
        "urlopen",
        fake_urlopen,
    )

    provider = GroqProvider(
        api_key="test-key",
        max_attempts=1,
        max_response_bytes=1024,
    )

    with pytest.raises(
        LLMProviderError,
        match=(
            "configured size limit"
        ),
    ):
        provider.generate_structured(
            messages=[],
            response_schema={
                "type": "object"
            },
        )


def test_length_finish_reason_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(
        request: Request,
        *,
        timeout: float,
    ) -> FakeResponse:
        del request
        del timeout

        return FakeResponse(
            make_chat_response(
                (
                    '{"summary":'
                    '"partial"}'
                ),
                finish_reason="length",
            )
        )

    monkeypatch.setattr(
        groq_module,
        "urlopen",
        fake_urlopen,
    )

    provider = GroqProvider(
        api_key="test-key",
        max_attempts=1,
    )

    with pytest.raises(
        LLMProviderError,
        match="truncated",
    ):
        provider.generate_structured(
            messages=[],
            response_schema={
                "type": "object"
            },
        )