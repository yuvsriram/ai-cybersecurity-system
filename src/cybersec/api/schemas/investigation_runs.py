from __future__ import annotations

from datetime import datetime

from pydantic import (
    BaseModel,
    ConfigDict,
)

from cybersec.ai.investigation import (
    InvestigationResult,
)


class InvestigationRunResponse(
    BaseModel
):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: str
    alert_id: str

    status: str

    provider: str
    model: str
    prompt_version: str

    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None

    result: InvestigationResult | None

    error_message: str | None