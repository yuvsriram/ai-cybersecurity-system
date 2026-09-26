from __future__ import annotations

from dataclasses import dataclass


@dataclass(
    frozen=True,
    slots=True,
)
class AlertCorrelationResult:
    alert_id: str
    case_id: str

    case_created: bool
    alert_added: bool

    correlation_reason: str