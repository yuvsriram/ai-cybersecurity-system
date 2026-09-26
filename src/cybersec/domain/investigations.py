from __future__ import annotations

from typing import Literal


InvestigationRunStatus = Literal[
    "queued",
    "running",
    "completed",
    "failed",
]


INVESTIGATION_STATUS_QUEUED = "queued"
INVESTIGATION_STATUS_RUNNING = "running"
INVESTIGATION_STATUS_COMPLETED = "completed"
INVESTIGATION_STATUS_FAILED = "failed"