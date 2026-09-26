from __future__ import annotations

from pydantic import BaseModel


class AlertCorrelationResponse(
    BaseModel
):
    alert_id: str
    case_id: str

    case_created: bool
    alert_added: bool

    correlation_reason: str