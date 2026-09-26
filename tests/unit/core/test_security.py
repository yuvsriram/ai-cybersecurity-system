from cybersec.core.config import (
    ApiKeyCredential,
)
from cybersec.core.security import (
    authenticate_api_key,
    hash_api_key,
    role_allows,
)


def test_api_key_authentication() -> None:
    secret = (
        "test-secret-key"
    )

    credentials = (
        ApiKeyCredential(
            name="test-user",
            role="analyst",
            sha256=hash_api_key(
                secret
            ),
        ),
    )

    principal = (
        authenticate_api_key(
            api_key=secret,
            credentials=credentials,
        )
    )

    assert principal is not None
    assert (
        principal.name
        == "test-user"
    )
    assert (
        principal.role
        == "analyst"
    )


def test_invalid_api_key_is_rejected() -> None:
    credentials = (
        ApiKeyCredential(
            name="admin",
            role="admin",
            sha256=hash_api_key(
                "correct-key"
            ),
        ),
    )

    principal = (
        authenticate_api_key(
            api_key="wrong-key",
            credentials=credentials,
        )
    )

    assert principal is None


def test_role_hierarchy() -> None:
    assert role_allows(
        actual_role="admin",
        required_role="viewer",
    )

    assert role_allows(
        actual_role="analyst",
        required_role="viewer",
    )

    assert role_allows(
        actual_role="analyst",
        required_role="analyst",
    )

    assert not role_allows(
        actual_role="viewer",
        required_role="analyst",
    )

    assert not role_allows(
        actual_role="analyst",
        required_role="admin",
    )


def test_api_key_hash_is_not_plaintext() -> None:
    secret = (
        "do-not-store-this"
    )

    digest = hash_api_key(
        secret
    )

    assert digest != secret
    assert len(digest) == 64