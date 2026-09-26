from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import re
import xml.etree.ElementTree as ET


_EVENT_NAMESPACE = (
    "http://schemas.microsoft.com/win/2004/08/events/event"
)

_NS = {
    "e": _EVENT_NAMESPACE,
}


@dataclass(frozen=True, slots=True)
class WindowsXmlRecord:
    event_id: str
    occurred_at: datetime
    provider: str | None
    channel: str | None
    computer: str | None
    record_id: str | None
    security_user_id: str | None
    event_data: dict[str, str]
    raw_xml: str


def parse_xml_event(
    raw_xml: str,
) -> WindowsXmlRecord:
    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as exc:
        raise ValueError(
            f"Invalid Windows event XML: {exc}"
        ) from exc

    event_id = _required_text(
        root,
        "e:System/e:EventID",
    )

    time_created = root.find(
        "e:System/e:TimeCreated",
        _NS,
    )

    if time_created is None:
        raise ValueError(
            "Windows event XML is missing TimeCreated"
        )

    system_time = time_created.get("SystemTime")

    if not system_time:
        raise ValueError(
            "Windows event XML TimeCreated is missing "
            "SystemTime"
        )

    provider_element = root.find(
        "e:System/e:Provider",
        _NS,
    )

    security_element = root.find(
        "e:System/e:Security",
        _NS,
    )

    data: dict[str, str] = {}

    for element in root.findall(
        "e:EventData/e:Data",
        _NS,
    ):
        name = element.get("Name")

        if not name:
            continue

        data[name] = (element.text or "").strip()

    return WindowsXmlRecord(
        event_id=event_id,
        occurred_at=_parse_system_time(system_time),
        provider=(
            provider_element.get("Name")
            if provider_element is not None
            else None
        ),
        channel=_optional_text(
            root,
            "e:System/e:Channel",
        ),
        computer=_optional_text(
            root,
            "e:System/e:Computer",
        ),
        record_id=_optional_text(
            root,
            "e:System/e:EventRecordID",
        ),
        security_user_id=(
            security_element.get("UserID")
            if security_element is not None
            else None
        ),
        event_data=data,
        raw_xml=raw_xml,
    )


def parse_records(
    lines: list[str] | tuple[str, ...],
) -> list[WindowsXmlRecord]:
    records: list[WindowsXmlRecord] = []

    for line_number, line in enumerate(
        lines,
        start=1,
    ):
        stripped = line.strip()

        if not stripped:
            continue

        try:
            records.append(
                parse_xml_event(stripped)
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid XML event on line "
                f"{line_number}: {exc}"
            ) from exc

    return records


def parse_file(
    path: str | Path,
) -> list[WindowsXmlRecord]:
    file_path = Path(path)

    with file_path.open(
        "r",
        encoding="utf-8-sig",
    ) as handle:
        return parse_records(handle.readlines())


def _required_text(
    root: ET.Element,
    path: str,
) -> str:
    value = _optional_text(
        root,
        path,
    )

    if value is None:
        raise ValueError(
            f"Windows event XML is missing {path}"
        )

    return value


def _optional_text(
    root: ET.Element,
    path: str,
) -> str | None:
    element = root.find(
        path,
        _NS,
    )

    if element is None:
        return None

    value = (element.text or "").strip()

    return value or None


def _parse_system_time(
    value: str,
) -> datetime:
    # Windows XML can contain nanosecond precision while
    # Python datetime stores microseconds.
    normalized = re.sub(
        r"(\.\d{6})\d+(?=Z$)",
        r"\1",
        value,
    )

    normalized = normalized.replace(
        "Z",
        "+00:00",
    )

    try:
        return datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(
            f"Invalid Windows SystemTime: {value}"
        ) from exc