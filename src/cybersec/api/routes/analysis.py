from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)

from cybersec.ai.investigation import (
    InvestigationAlertContext,
    InvestigationEventContext,
    InvestigationGroundingError,
    InvestigationResponseError,
    InvestigationService,
)
from cybersec.ai.provider import (
    LLMProviderError,
)
from cybersec.api.ai_dependencies import (
    get_investigation_service,
)
from cybersec.api.schemas.analysis import (
    AnalysisAlertResponse,
    AnalysisEventResponse,
    LogAnalysisExplanationResponse,
    LogAnalysisRequest,
    LogAnalysisResponse,
    SeveritySummaryResponse,
)
from cybersec.core.config import (
    get_settings,
)
from cybersec.domain.events import (
    CanonicalEvent,
)
from cybersec.services.analysis import (
    AnalysisResult,
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
    result = _run_analysis(
        request
    )

    return _build_response(
        result
    )


@router.post(
    "/explain",
    response_model=(
        LogAnalysisExplanationResponse
    ),
)
def explain_logs(
    request: LogAnalysisRequest,
    investigation_service: (
        InvestigationService
    ) = Depends(
        get_investigation_service
    ),
) -> LogAnalysisExplanationResponse:
    result = _run_analysis(
        request
    )

    analysis_response = (
        _build_response(
            result
        )
    )

    if not result.alerts:
        return (
            LogAnalysisExplanationResponse(
                analysis=(
                    analysis_response
                ),
                primary_finding=None,
                explanation=None,
            )
        )

    primary_alert = (
        result.alerts[0]
    )

    event_by_fingerprint = {
        build_analysis_event_fingerprint(
            event
        ): event
        for event in result.events
    }

    evidence_contexts: list[
        InvestigationEventContext
    ] = []

    for fingerprint in (
        primary_alert
        .evidence_event_fingerprints
    ):
        event = (
            event_by_fingerprint.get(
                fingerprint
            )
        )

        if event is None:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_500_INTERNAL_SERVER_ERROR
                ),
                detail=(
                    "Analysis evidence "
                    "integrity check failed"
                ),
            )

        evidence_contexts.append(
            _build_event_context(
                event=event,
                fingerprint=(
                    fingerprint
                ),
            )
        )

    if not evidence_contexts:
        raise HTTPException(
            status_code=(
                status
                .HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Primary finding has "
                "no analysis evidence"
            ),
        )

    alert_context = (
        InvestigationAlertContext
        .model_validate(
            primary_alert
        )
    )

    try:
        explanation = (
            investigation_service
            .investigate(
                alert=alert_context,
                events=(
                    evidence_contexts
                ),
            )
        )

    except LLMProviderError as exc:
        raise HTTPException(
            status_code=(
                status
                .HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "AI explanation provider "
                "is unavailable"
            ),
        ) from exc

    except (
        InvestigationResponseError,
        InvestigationGroundingError,
    ) as exc:
        raise HTTPException(
            status_code=(
                status
                .HTTP_502_BAD_GATEWAY
            ),
            detail=(
                "AI explanation response "
                "failed grounding validation"
            ),
        ) from exc

    return (
        LogAnalysisExplanationResponse(
            analysis=analysis_response,
            primary_finding=(
                analysis_response
                .alerts[0]
            ),
            explanation=explanation,
        )
    )


def _run_analysis(
    request: LogAnalysisRequest,
) -> AnalysisResult:
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
        return analyze_security_logs(
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


def _build_response(
    result: AnalysisResult,
) -> LogAnalysisResponse:
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
            _build_alert_response(
                alert
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


def _build_alert_response(
    alert,
) -> AnalysisAlertResponse:
    return AnalysisAlertResponse(
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


def _build_event_context(
    *,
    event: CanonicalEvent,
    fingerprint: str,
) -> InvestigationEventContext:
    return (
        InvestigationEventContext
        .model_validate(
            {
                "event_fingerprint": (
                    fingerprint
                ),
                "occurred_at": (
                    event.occurred_at
                ),
                "event_code": (
                    event.event_code
                ),
                "category": (
                    event.category
                ),
                "action": (
                    event.action
                ),
                "outcome": (
                    event.outcome
                ),
                "source_provider": (
                    event.source_provider
                ),
                "source_channel": (
                    event.source_channel
                ),
                "source_dataset": (
                    event.source_dataset
                ),
                "source_record_id": (
                    event.source_record_id
                ),
                "host_name": (
                    event.host_name
                ),
                "user_name": (
                    event.user_name
                ),
                "user_domain": (
                    event.user_domain
                ),
                "source_host": (
                    event.source_host
                ),
                "source_ip": (
                    event.source_ip
                ),
                "destination_host": (
                    event.destination_host
                ),
                "destination_ip": (
                    event.destination_ip
                ),
                "attributes": dict(
                    event.attributes
                ),
            }
        )
    )