from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from cybersec.api.schemas.events import EventResponse


class AlertResponse(BaseModel):
    model_config = ConfigDict(
        from_attributes=True
    )

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

    evidence_record_ids: list[str]
    evidence_event_fingerprints: list[str]
    evidence_event_codes: list[str]

    mitre_techniques: list[str]


class AlertEvidenceResponse(BaseModel):
    alert_id: str
    rule_id: str

    evidence_count: int

    events: list[EventResponse]