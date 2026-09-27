from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import (
    BaseModel,
    Field,
)

from cybersec.ai.investigation import (
    InvestigationResult,
)


AnalysisFormat = Literal[
    "splunk_windows_security",
    "windows_ntlm_xml",
]

AnalysisSeverity = Literal[
    "none",
    "low",
    "medium",
    "high",
    "critical",
]


class LogAnalysisRequest(BaseModel):
    format: AnalysisFormat

    dataset_name: str = Field(
        default="interactive_analysis",
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.-]+$",
    )

    content: str = Field(
        min_length=1,
        max_length=2_000_000,
    )


class AnalysisEventResponse(BaseModel):
    event_fingerprint: str

    occurred_at: datetime

    event_code: str
    category: str
    action: str
    outcome: str | None

    source_provider: str | None
    source_channel: str | None

    host_name: str | None

    user_name: str | None
    user_domain: str | None

    source_host: str | None
    source_ip: str | None

    destination_host: str | None
    destination_ip: str | None


class AnalysisAlertResponse(BaseModel):
    rule_id: str
    rule_version: str

    title: str
    description: str
    severity: str

    first_seen_at: datetime
    last_seen_at: datetime

    user_name: str | None

    source_ip: str | None
    source_host: str | None

    destination_host: str | None

    evidence_count: int
    evidence_event_codes: list[str]

    mitre_techniques: list[str]


class SeveritySummaryResponse(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class LogAnalysisResponse(BaseModel):
    format: AnalysisFormat

    overall_severity: AnalysisSeverity

    parsed_records: int
    normalized_events: int
    unsupported_records: int

    detected_alerts: int

    severity_summary: (
        SeveritySummaryResponse
    )

    alerts: list[
        AnalysisAlertResponse
    ]

    events: list[
        AnalysisEventResponse
    ]


class LogAnalysisExplanationResponse(
    BaseModel
):
    analysis: LogAnalysisResponse

    primary_finding: (
        AnalysisAlertResponse
        | None
    )

    explanation: (
        InvestigationResult
        | None
    )