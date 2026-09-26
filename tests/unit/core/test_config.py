import json

import pytest

from cybersec.core.config import (
    get_settings,
)


def test_settings_parse_api_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "DATABASE_URL",
        (
            "postgresql+psycopg://"
            "test:test@localhost/test"
        ),
    )

    monkeypatch.setenv(
        "CYBERSEC_API_KEYS_JSON",
        json.dumps(
            [
                {
                    "name": (
                        "local-admin"
                    ),
                    "role": "admin",
                    "sha256": "a" * 64,
                }
            ]
        ),
    )

    get_settings.cache_clear()

    try:
        settings = get_settings()

        assert (
            len(settings.api_keys)
            == 1
        )

        assert (
            settings.api_keys[0].name
            == "local-admin"
        )

        assert (
            settings.api_keys[0].role
            == "admin"
        )

    finally:
        get_settings.cache_clear()


def test_invalid_api_key_hash_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "DATABASE_URL",
        (
            "postgresql+psycopg://"
            "test:test@localhost/test"
        ),
    )

    monkeypatch.setenv(
        "CYBERSEC_API_KEYS_JSON",
        json.dumps(
            [
                {
                    "name": "bad-key",
                    "role": "viewer",
                    "sha256": (
                        "not-a-valid-hash"
                    ),
                }
            ]
        ),
    )

    get_settings.cache_clear()

    try:
        with pytest.raises(
            RuntimeError
        ):
            get_settings()

    finally:
        get_settings.cache_clear()