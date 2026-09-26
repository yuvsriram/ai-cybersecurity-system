from __future__ import annotations

from cybersec.core.config import (
    get_settings,
)
from cybersec.main import (
    create_app,
)


def test_production_disables_api_docs(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "CYBERSEC_ENVIRONMENT",
        "production",
    )

    get_settings.cache_clear()

    try:
        app = create_app()

        assert app.docs_url is None
        assert app.redoc_url is None
        assert app.openapi_url is None

    finally:
        get_settings.cache_clear()


def test_development_enables_api_docs(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "CYBERSEC_ENVIRONMENT",
        "development",
    )

    get_settings.cache_clear()

    try:
        app = create_app()

        assert app.docs_url == "/docs"
        assert app.redoc_url == "/redoc"
        assert (
            app.openapi_url
            == "/openapi.json"
        )

    finally:
        get_settings.cache_clear()