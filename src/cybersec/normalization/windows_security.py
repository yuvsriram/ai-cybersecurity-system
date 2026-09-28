from __future__ import annotations

import re
from datetime import datetime

from cybersec.domain.events import CanonicalEvent
from cybersec.ingestion.parsers.splunk_kv import SplunkKvRecord


_TIMESTAMP_FORMAT = "%m/%d/%Y %I:%M:%S %p"


def normalize_windows_security_event(
    record: SplunkKvRecord,
    *,
    dataset_name: str = "splunk_attack_data",
) -> CanonicalEvent | None:
    """
    Normalize supported Windows Security events.

    Currently supported:
    - 4625: failed logon
    - 4740: account lockout
    """

    event_code = record.fields.get("EventCode")

    if event_code == "4625":
        return _normalize_failed_logon(
            record,
            dataset_name=dataset_name,
        )

    if event_code == "4740":
        return _normalize_account_lockout(
            record,
            dataset_name=dataset_name,
        )

    return None


def _normalize_failed_logon(
    record: SplunkKvRecord,
    *,
    dataset_name: str,
) -> CanonicalEvent:
    return CanonicalEvent(
        schema_version="1.0",
        occurred_at=_parse_timestamp(record.timestamp),
        event_code="4625",
        category="authentication",
        action="logon",
        outcome="failure",
        source_provider=record.fields.get("SourceName"),
        source_channel=record.fields.get("LogName"),
        source_dataset=dataset_name,
        source_record_id=record.fields.get("RecordNumber"),
        host_name=record.fields.get("ComputerName"),
        user_name=_extract_section_field(
            record.raw_text,
            section_title="Account For Which Logon Failed",
            field_name="Account Name",
        ),
        user_domain=_extract_section_field(
            record.raw_text,
            section_title="Account For Which Logon Failed",
            field_name="Account Domain",
        ),
        user_sid=_extract_section_field(
            record.raw_text,
            section_title="Account For Which Logon Failed",
            field_name="Security ID",
        ),
        source_host=_extract_section_field(
            record.raw_text,
            section_title="Network Information",
            field_name="Workstation Name",
        ),
        source_ip=_extract_section_field(
            record.raw_text,
            section_title="Network Information",
            field_name="Source Network Address",
        ),
        destination_host=record.fields.get("ComputerName"),
        destination_ip=None,
        raw_event=record.raw_text,
        attributes=_base_attributes(record),
    )


def _normalize_account_lockout(
    record: SplunkKvRecord,
    *,
    dataset_name: str,
) -> CanonicalEvent:
    return CanonicalEvent(
        schema_version="1.0",
        occurred_at=_parse_timestamp(record.timestamp),
        event_code="4740",
        category="identity",
        action="account_lockout",
        outcome="success",
        source_provider=record.fields.get("SourceName"),
        source_channel=record.fields.get("LogName"),
        source_dataset=dataset_name,
        source_record_id=record.fields.get("RecordNumber"),
        host_name=record.fields.get("ComputerName"),
        user_name=_extract_section_field(
            record.raw_text,
            section_title="Account That Was Locked Out",
            field_name="Account Name",
        ),
        user_domain=_extract_domain_from_sid(
            _extract_section_field(
                record.raw_text,
                section_title="Account That Was Locked Out",
                field_name="Security ID",
            )
        ),
        user_sid=_extract_section_field(
            record.raw_text,
            section_title="Account That Was Locked Out",
            field_name="Security ID",
        ),
        source_host=_extract_section_field(
            record.raw_text,
            section_title="Additional Information",
            field_name="Caller Computer Name",
        ),
        source_ip=None,
        destination_host=record.fields.get("ComputerName"),
        destination_ip=None,
        raw_event=record.raw_text,
        attributes=_base_attributes(record),
    )


def _parse_timestamp(value: str) -> datetime:
    return datetime.strptime(value, _TIMESTAMP_FORMAT)


def _base_attributes(
    record: SplunkKvRecord,
) -> dict[str, str]:
    keys = (
        "EventType",
        "Type",
        "TaskCategory",
        "OpCode",
        "RecordNumber",
        "Keywords",
        "Message",
    )

    return {
        key: record.fields[key]
        for key in keys
        if key in record.fields
    }


def _extract_section_field(
    raw_text: str,
    *,
    section_title: str,
    field_name: str,
) -> str | None:
    lines = raw_text.splitlines()

    section_start: int | None = None

    for index, line in enumerate(lines):
        if line.strip() == f"{section_title}:":
            section_start = index + 1
            break

    if section_start is None:
        return None

    expected_prefix = f"{field_name}:"

    for line in lines[section_start:]:
        stripped = line.strip()
        if (
            line
            and not line[0].isspace()
            and stripped.endswith(":")
        ):
            break

        if not stripped.startswith(expected_prefix):
            continue

        value = stripped[len(expected_prefix):].strip()

        if not value or value == "-":
            return None

        return value

    return None


def _extract_domain_from_sid(
    security_id: str | None,
) -> str | None:
    if security_id is None:
        return None

    if "\\" not in security_id:
        return None

    domain, _ = security_id.split("\\", 1)

    return domain or None