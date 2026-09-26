from __future__ import annotations

from datetime import datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
)

from cybersec.api.schemas.alerts import (
    AlertResponse,
)


class CaseCreateRequest(BaseModel):
    title: str = Field(
        min_length=1,
        max_length=255,
    )

    summary: str | None = Field(
        default=None,
        max_length=5000,
    )

    severity: str

    alert_ids: list[str] = Field(
        default_factory=list,
        max_length=100,
    )


class CaseResponse(BaseModel):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: str
    title: str
    summary: str | None

    status: str
    severity: str
    creation_source: str

    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None


class CaseDetailResponse(
    CaseResponse
):
    alerts: list[AlertResponse]