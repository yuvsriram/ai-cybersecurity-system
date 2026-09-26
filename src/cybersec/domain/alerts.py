from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4


@dataclass(slots=True)
class Alert:
    id: str

    rule_id: str
    rule_version: str

    title: str
    description: str
    severity: str

    created_at: datetime
    first_seen_at: datetime
    last_seen_at: datetime

    user_name: str | None
    source_ip: str | None
    source_host: str | None
    destination_host: str | None

    evidence_record_ids: tuple[str, ...]
    evidence_event_fingerprints: tuple[str, ...]
    evidence_event_codes: tuple[str, ...]

    mitre_techniques: tuple[str, ...]


def new_alert_id() -> str:
    return str(uuid4())