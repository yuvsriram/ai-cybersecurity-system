from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    status,
)

from cybersec.api.schemas.analysis import (
    AnalysisAlertResponse,
    AnalysisEventResponse,
    LogAnalysisRequest,
    LogAnalysisResponse,
    SeveritySummaryResponse,
)
from cybersec.core.config import (
    get_settings,
)
from cybersec.services.analysis import (
    analyze_security_logs,
    build_analysis_event_fingerprint,
    build_severity_summary,
)


router = APIRouter(
    prefix="/api/v1/analyze",
    tags=["analysis"],
)


@router.post(
    "",
    response_model=LogAnalysisResponse,
)
def analyze_logs(
    request: LogAnalysisRequest,
) -> LogAnalysisResponse:
    settings = get_settings()

    content_size = len(
        request.content.encode(
            "utf-8"
        )
    )

    if (
        content_size
        > settings.max_ingestion_bytes
    ):
        raise HTTPException(
            status_code=(
                status
                .HTTP_413_CONTENT_TOO_LARGE
            ),
            detail=(
                "Analysis payload exceeds "
                "configured size limit"
            ),
        )

    try:
        result = analyze_security_logs(
            format=request.format,
            content=request.content,
            dataset_name=(
                request.dataset_name
            ),
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=(
                status
                .HTTP_422_UNPROCESSABLE_CONTENT
            ),
            detail=str(exc),
        ) from exc

    summary = build_severity_summary(
        result.alerts
    )

    return LogAnalysisResponse(
        format=result.format,
        overall_severity=(
            result.overall_severity
        ),
        parsed_records=(
            result.parsed_records
        ),
        normalized_events=(
            result.normalized_events
        ),
        unsupported_records=(
            result.unsupported_records
        ),
        detected_alerts=(
            len(result.alerts)
        ),
        severity_summary=(
            SeveritySummaryResponse(
                critical=summary[
                    "critical"
                ],
                high=summary[
                    "high"
                ],
                medium=summary[
                    "medium"
                ],
                low=summary[
                    "low"
                ],
            )
        ),
        alerts=[
            AnalysisAlertResponse(
                rule_id=alert.rule_id,
                rule_version=(
                    alert.rule_version
                ),
                title=alert.title,
                description=(
                    alert.description
                ),
                severity=alert.severity,
                first_seen_at=(
                    alert.first_seen_at
                ),
                last_seen_at=(
                    alert.last_seen_at
                ),
                user_name=(
                    alert.user_name
                ),
                source_ip=(
                    alert.source_ip
                ),
                source_host=(
                    alert.source_host
                ),
                destination_host=(
                    alert.destination_host
                ),
                evidence_count=len(
                    alert
                    .evidence_event_fingerprints
                ),
                evidence_event_codes=list(
                    alert
                    .evidence_event_codes
                ),
                mitre_techniques=list(
                    alert.mitre_techniques
                ),
            )
            for alert in result.alerts
        ],
        events=[
            AnalysisEventResponse(
                event_fingerprint=(
                    build_analysis_event_fingerprint(
                        event
                    )
                ),
                occurred_at=(
                    event.occurred_at
                ),
                event_code=(
                    event.event_code
                ),
                category=(
                    event.category
                ),
                action=event.action,
                outcome=event.outcome,
                source_provider=(
                    event.source_provider
                ),
                source_channel=(
                    event.source_channel
                ),
                host_name=(
                    event.host_name
                ),
                user_name=(
                    event.user_name
                ),
                user_domain=(
                    event.user_domain
                ),
                source_host=(
                    event.source_host
                ),
                source_ip=(
                    event.source_ip
                ),
                destination_host=(
                    event.destination_host
                ),
                destination_ip=(
                    event.destination_ip
                ),
            )
            for event in result.events
        ],
    )