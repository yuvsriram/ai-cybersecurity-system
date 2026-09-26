from datetime import datetime

from cybersec.db.models.event import (
    EventModel,
)
from cybersec.ml.features import (
    build_authentication_feature_vectors,
    feature_names,
    feature_vector_to_numeric,
)


def _event(
    *,
    event_id: int,
    second: int,
    event_code: str,
    user_name: str,
    outcome: str | None,
) -> EventModel:
    return EventModel(
        id=event_id,
        event_fingerprint=(
            f"{event_id:064x}"
        ),
        schema_version="1.0",
        occurred_at=datetime(
            2026,
            1,
            1,
            12,
            0,
            second,
        ),
        event_code=event_code,
        category="authentication",
        action="test",
        outcome=outcome,
        source_provider="pytest",
        source_channel="test",
        source_dataset="ml_test",
        source_record_id=(
            str(event_id)
        ),
        host_name="DC-01",
        user_name=user_name,
        user_domain=None,
        user_sid=None,
        source_host="SOURCE",
        source_ip="192.0.2.10",
        destination_host="DEST",
        destination_ip=None,
        raw_event="test",
        attributes={},
    )


def test_feature_vector_counts_authentication_activity() -> None:
    events = [
        _event(
            event_id=1,
            second=1,
            event_code="4625",
            user_name="alice",
            outcome="failure",
        ),
        _event(
            event_id=2,
            second=2,
            event_code="4625",
            user_name="bob",
            outcome="failure",
        ),
        _event(
            event_id=3,
            second=3,
            event_code="8004",
            user_name="charlie",
            outcome=None,
        ),
    ]

    vectors = (
        build_authentication_feature_vectors(
            events
        )
    )

    assert len(vectors) == 1

    vector = vectors[0]

    assert vector.event_count == 3
    assert (
        vector.distinct_user_count
        == 3
    )

    assert vector.failed_count == 2
    assert vector.success_count == 0

    assert (
        vector.unknown_outcome_count
        == 1
    )

    assert (
        vector.event_4625_count
        == 2
    )

    assert (
        vector.event_8004_count
        == 1
    )


def test_numeric_feature_shape_matches_names() -> None:
    vector = (
        build_authentication_feature_vectors(
            [
                _event(
                    event_id=1,
                    second=1,
                    event_code="4625",
                    user_name="alice",
                    outcome="failure",
                )
            ]
        )[0]
    )

    numeric = (
        feature_vector_to_numeric(
            vector
        )
    )

    assert len(numeric) == len(
        feature_names()
    )


def test_invalid_window_rejected() -> None:
    try:
        build_authentication_feature_vectors(
            [],
            window_seconds=0,
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Expected ValueError"
        )

def test_sparse_multi_year_events_do_not_create_empty_windows() -> None:
    first = _event(
        event_id=10,
        second=1,
        event_code="4625",
        user_name="alice",
        outcome="failure",
    )

    second = _event(
        event_id=11,
        second=2,
        event_code="4625",
        user_name="bob",
        outcome="failure",
    )

    second.occurred_at = datetime(
        2030,
        1,
        1,
        12,
        0,
        2,
    )

    vectors = (
        build_authentication_feature_vectors(
            [
                first,
                second,
            ]
        )
    )

    assert len(vectors) == 2

    assert (
        sum(
            vector.event_count
            for vector in vectors
        )
        == 2
    )