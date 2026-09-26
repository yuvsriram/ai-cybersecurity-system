from __future__ import annotations

from typing import Literal


CaseStatus = Literal[
    "open",
    "investigating",
    "resolved",
    "closed",
]

CaseSeverity = Literal[
    "low",
    "medium",
    "high",
    "critical",
]


CASE_STATUS_OPEN = "open"
CASE_STATUS_INVESTIGATING = "investigating"
CASE_STATUS_RESOLVED = "resolved"
CASE_STATUS_CLOSED = "closed"

CASE_SEVERITY_LOW = "low"
CASE_SEVERITY_MEDIUM = "medium"
CASE_SEVERITY_HIGH = "high"
CASE_SEVERITY_CRITICAL = "critical"