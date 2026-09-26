from cybersec.domain.event_identity import (
    build_event_fingerprint,
)


def test_same_event_produces_same_fingerprint() -> None:
    first = build_event_fingerprint(
        source_dataset="dataset-a",
        raw_event="<Event>abc</Event>",
    )

    second = build_event_fingerprint(
        source_dataset="dataset-a",
        raw_event="<Event>abc</Event>",
    )

    assert first == second
    assert len(first) == 64


def test_different_payload_produces_different_fingerprint() -> None:
    first = build_event_fingerprint(
        source_dataset="dataset-a",
        raw_event="<Event>abc</Event>",
    )

    second = build_event_fingerprint(
        source_dataset="dataset-a",
        raw_event="<Event>xyz</Event>",
    )

    assert first != second


def test_dataset_is_part_of_fingerprint() -> None:
    first = build_event_fingerprint(
        source_dataset="dataset-a",
        raw_event="<Event>abc</Event>",
    )

    second = build_event_fingerprint(
        source_dataset="dataset-b",
        raw_event="<Event>abc</Event>",
    )

    assert first != second