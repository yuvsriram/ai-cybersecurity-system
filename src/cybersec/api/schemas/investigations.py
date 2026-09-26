from __future__ import annotations

from pydantic import BaseModel

from cybersec.ai.investigation import (
    InvestigationResult,
)


class AlertInvestigationResponse(
    BaseModel
):
    alert_id: str

    investigation: InvestigationResult