from __future__ import annotations

from cybersec.domain.events import CanonicalEvent
from cybersec.ingestion.parsers.windows_xml import WindowsXmlRecord


NTLM_AUDIT_EVENT_ID = "8004"


def normalize_ntlm_event(
    record: WindowsXmlRecord,
    *,
    dataset_name: str,
) -> CanonicalEvent | None:
    if record.event_id != NTLM_AUDIT_EVENT_ID:
        return None

    user_domain = _clean_value(
        record.event_data.get("DomainName")
    )
    user_name = _clean_value(
        record.event_data.get("UserName")
    )
    workstation = _clean_value(
        record.event_data.get("WorkstationName")
    )
    secure_channel = _clean_value(
        record.event_data.get("SChannelName")
    )

    attributes = {
        "SChannelType": record.event_data.get(
            "SChannelType",
            "",
        ),
    }

    if record.security_user_id:
        attributes["SecurityUserID"] = (
            record.security_user_id
        )

    return CanonicalEvent(
        schema_version="1.0",
        occurred_at=record.occurred_at,
        event_code=record.event_id,
        category="authentication",
        action="ntlm_authentication",
        outcome=None,
        source_provider=record.provider,
        source_channel=record.channel,
        source_dataset=dataset_name,
        source_record_id=record.record_id,
        host_name=record.computer,
        user_name=user_name,
        user_domain=user_domain,
        user_sid=None,
        source_host=workstation,
        source_ip=None,
        destination_host=secure_channel,
        destination_ip=None,
        raw_event=record.raw_xml,
        attributes=attributes,
    )


def _clean_value(
    value: str | None,
) -> str | None:
    if value is None:
        return None

    cleaned = value.strip()

    if not cleaned:
        return None

    if cleaned.upper() in {
        "NULL",
        "N/A",
        "-",
    }:
        return None

    return cleaned
