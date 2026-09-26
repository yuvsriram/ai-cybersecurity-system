from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class EventResponse(BaseModel):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: int
    event_fingerprint: str

    schema_version: str
    occurred_at: datetime

    event_code: str
    category: str
    action: str
    outcome: str | None

    source_provider: str | None
    source_channel: str | None
    source_dataset: str | None
    source_record_id: str | None

    host_name: str | None

    user_name: str | None
    user_domain: str | None
    user_sid: str | None

    source_host: str | None
    source_ip: str | None

    destination_host: str | None
    destination_ip: str | None

    attributes: dict[str, str]