from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path


_TIMESTAMP_PATTERN = re.compile(
    r"^\d{1,2}/\d{1,2}/\d{4} "
    r"\d{1,2}:\d{2}:\d{2} "
    r"(?:AM|PM)$"
)

_TOP_LEVEL_FIELD_PATTERN = re.compile(
    r"^(?P<key>[A-Za-z][A-Za-z0-9_]*)=(?P<value>.*)$"
)


@dataclass(slots=True)
class SplunkKvRecord:
    """One event parsed from the Splunk key/value export format."""

    timestamp: str
    fields: dict[str, str]
    raw_text: str


def parse_records(lines: Iterable[str]) -> Iterator[SplunkKvRecord]:
    """Parse Splunk key/value log lines into individual source records."""

    current_timestamp: str | None = None
    current_lines: list[str] = []

    for raw_line in lines:
        line = raw_line.rstrip("\r\n")

        if _TIMESTAMP_PATTERN.fullmatch(line):
            if current_timestamp is not None:
                yield _build_record(
                    timestamp=current_timestamp,
                    raw_lines=current_lines,
                )

            current_timestamp = line
            current_lines = [raw_line]
            continue

        if current_timestamp is None:
            if line.strip():
                raise ValueError(
                    "Found non-empty content before the first event timestamp."
                )

            continue

        current_lines.append(raw_line)

    if current_timestamp is not None:
        yield _build_record(
            timestamp=current_timestamp,
            raw_lines=current_lines,
        )


def parse_file(path: str | Path) -> Iterator[SplunkKvRecord]:
    """Stream records from a Splunk key/value log file."""

    file_path = Path(path)

    with file_path.open(
        mode="r",
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        yield from parse_records(handle)


def _build_record(
    timestamp: str,
    raw_lines: list[str],
) -> SplunkKvRecord:
    fields: dict[str, str] = {}
    message_started = False

    for raw_line in raw_lines[1:]:
        line = raw_line.rstrip("\r\n")

        if message_started:
            continue

        match = _TOP_LEVEL_FIELD_PATTERN.fullmatch(line)

        if match is None:
            continue

        key = match.group("key")
        value = match.group("value")

        fields[key] = value

        if key == "Message":
            message_started = True

    return SplunkKvRecord(
        timestamp=timestamp,
        fields=fields,
        raw_text="".join(raw_lines),
    )