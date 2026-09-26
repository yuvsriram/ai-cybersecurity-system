from __future__ import annotations
import re

import pytest
from cybersec.observability import (
    tracing,
)


class FakeTracerProvider:
    def __init__(
        self,
        *,
        flush_result: bool = True,
    ) -> None:
        self.flush_result = flush_result

        self.timeout_millis: (
            int | None
        ) = None

    def force_flush(
        self,
        *,
        timeout_millis: int,
    ) -> bool:
        self.timeout_millis = (
            timeout_millis
        )

        return self.flush_result


def test_force_flush_returns_false_without_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tracing,
        "_tracer_provider",
        None,
    )

    assert (
        tracing.force_flush_tracing()
        is False
    )


def test_force_flush_uses_configured_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = FakeTracerProvider()

    monkeypatch.setattr(
        tracing,
        "_tracer_provider",
        provider,
    )

    result = (
        tracing.force_flush_tracing(
            timeout_millis=1234
        )
    )

    assert result is True

    assert (
        provider.timeout_millis
        == 1234
    )


def test_force_flush_requires_positive_timeout(
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "timeout_millis must be positive"
        ),
    ):
        tracing.force_flush_tracing(
            timeout_millis=0
        )

def test_fastapi_instrumentation_excludes_health_and_metrics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "CYBERSEC_TRACING_ENABLED",
        "true",
    )

    captured: dict[str, object] = {}

    def fake_instrument_app(
        app: object,
        *,
        excluded_urls: str,
    ) -> None:
        captured["app"] = app
        captured["excluded_urls"] = (
            excluded_urls
        )

    monkeypatch.setattr(
        tracing.FastAPIInstrumentor,
        "instrument_app",
        fake_instrument_app,
    )

    app = object()

    tracing.instrument_fastapi_app(
        app
    )

    assert captured["app"] is app

    excluded_urls = captured[
        "excluded_urls"
    ]

    assert isinstance(
        excluded_urls,
        str,
    )

    patterns = (
        excluded_urls.split(",")
    )

    excluded = [
        "http://testserver/health",
        "http://testserver/health/live",
        "http://testserver/health/ready",
        "http://testserver/metrics",
    ]

    for url in excluded:
        assert any(
            re.search(
                pattern,
                url,
            )
            for pattern in patterns
        )

    assert not any(
        re.search(
            pattern,
            (
                "http://testserver/"
                "api/v1/events"
            ),
        )
        for pattern in patterns
    )