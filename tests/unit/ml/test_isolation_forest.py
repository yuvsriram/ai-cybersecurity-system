from datetime import datetime

from cybersec.ml.features import (
    AuthenticationFeatureVector,
)
from cybersec.ml.isolation_forest import (
    AuthenticationIsolationForest,
)


def _vector(
    *,
    event_count: int,
    users: int,
) -> AuthenticationFeatureVector:
    start = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
    )

    return AuthenticationFeatureVector(
        window_start=start,
        window_end=start,
        source_host="SOURCE",
        source_ip=None,
        event_count=event_count,
        distinct_user_count=users,
        distinct_destination_count=1,
        failed_count=event_count,
        success_count=0,
        unknown_outcome_count=0,
        event_4625_count=(
            event_count
        ),
        event_4740_count=0,
        event_8004_count=0,
        events_per_second=(
            event_count / 300
        ),
    )


def test_model_can_fit_and_score() -> None:
    vectors = [
        _vector(
            event_count=1,
            users=1,
        ),
        _vector(
            event_count=2,
            users=1,
        ),
        _vector(
            event_count=1,
            users=1,
        ),
        _vector(
            event_count=2,
            users=2,
        ),
        _vector(
            event_count=100,
            users=50,
        ),
    ]

    model = (
        AuthenticationIsolationForest(
            contamination=0.2
        )
    )

    model.fit(
        vectors
    )

    scores = model.score(
        vectors
    )

    assert len(scores) == 5

    assert any(
        score.is_anomaly
        for score in scores
    )


def test_score_before_fit_is_rejected() -> None:
    model = (
        AuthenticationIsolationForest()
    )

    try:
        model.score(
            [
                _vector(
                    event_count=1,
                    users=1,
                )
            ]
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError(
            "Expected RuntimeError"
        )


def test_fit_requires_multiple_vectors() -> None:
    model = (
        AuthenticationIsolationForest()
    )

    try:
        model.fit(
            [
                _vector(
                    event_count=1,
                    users=1,
                )
            ]
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Expected ValueError"
        )