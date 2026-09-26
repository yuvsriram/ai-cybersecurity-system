from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class AuditEventResponse(
    BaseModel
):
    id: int
    created_at: datetime

    actor_name: str
    actor_role: str

    action: str

    resource_type: str
    resource_id: str | None

    outcome: str

    detail: str | None

    attributes: dict[
        str,
        object,
    ]

    model_config = {
        "from_attributes": True
    }