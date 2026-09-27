from __future__ import annotations

import re
from dataclasses import dataclass

from cybersec.detection.authentication import (
    detect_authentication_alerts,
)
from cybersec.detection.ntlm import (
    detect_ntlm_alerts,
)
from cybersec.domain.alerts import (
    Alert,
)
from cybersec.domain.event_identity import (
    build_event_fingerprint,
)
from cybersec.domain.events import (
    CanonicalEvent,
)
from cybersec.ingestion.parsers.splunk_kv import (
    parse_records as parse_splunk_records,
)
from cybersec.ingestion.parsers.windows_xml import (
    parse_xml_event,
)
from cybersec.normalization.ntlm import (
    normalize_ntlm_event,
)
from cybersec.normalization.windows_security import (
    normalize_windows_security_event,
)


SUPPORTED_FORMATS = {
    "splunk_windows_security",
    "windows_ntlm_xml",
}

_SEVERITY_RANK = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(
    frozen=True,
    slots=True,
)
class AnalysisResult:
    format: str

    parsed_records: int
    normalized_events: int
    unsupported_records: int

    overall_severity: str

    alerts: tuple[
        Alert,
        ...
    ]

    events: tuple[
        CanonicalEvent,
        ...
    ]


def analyze_security_logs(
    *,
    format: str,
    content: str,
    dataset_name: str = (
        "interactive_analysis"
    ),
) -> AnalysisResult:
    normalized_format = (
        format.strip().lower()
    )

    if (
        normalized_format
        not in SUPPORTED_FORMATS
    ):
        raise ValueError(
            "Unsupported analysis format"
        )

    if not content.strip():
        raise ValueError(
            "Analysis content must not "
            "be empty"
        )

    if not dataset_name.strip():
        raise ValueError(
            "dataset_name must not "
            "be empty"
        )

    if (
        normalized_format
        == "splunk_windows_security"
    ):
        return _analyze_splunk_windows(
            content=content,
            dataset_name=dataset_name,
        )

    return _analyze_windows_ntlm_xml(
        content=content,
        dataset_name=dataset_name,
    )


def build_analysis_event_fingerprint(
    event: CanonicalEvent,
) -> str:
    return build_event_fingerprint(
        source_dataset=(
            event.source_dataset
        ),
        raw_event=event.raw_event,
    )


def build_severity_summary(
    alerts: tuple[
        Alert,
        ...
    ],
) -> dict[str, int]:
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for alert in alerts:
        severity = (
            alert.severity
            .strip()
            .lower()
        )

        if severity in summary:
            summary[severity] += 1

    return summary


def _analyze_splunk_windows(
    *,
    content: str,
    dataset_name: str,
) -> AnalysisResult:
    source_records = list(
        parse_splunk_records(
            content.splitlines(
                keepends=True
            )
        )
    )

    normalized_events: list[
        CanonicalEvent
    ] = []

    for source_record in (
        source_records
    ):
        event = (
            normalize_windows_security_event(
                source_record,
                dataset_name=dataset_name,
            )
        )

        if event is not None:
            normalized_events.append(
                event
            )

    alerts = (
        detect_authentication_alerts(
            normalized_events
        )
    )

    return _build_result(
        format=(
            "splunk_windows_security"
        ),
        parsed_records=(
            len(source_records)
        ),
        events=normalized_events,
        alerts=alerts,
    )


def _analyze_windows_ntlm_xml(
    *,
    content: str,
    dataset_name: str,
) -> AnalysisResult:
    xml_records = (
        _parse_xml_records(
            content
        )
    )

    normalized_events: list[
        CanonicalEvent
    ] = []

    for record in xml_records:
        event = normalize_ntlm_event(
            record,
            dataset_name=dataset_name,
        )

        if event is not None:
            normalized_events.append(
                event
            )

    alerts = detect_ntlm_alerts(
        normalized_events
    )

    return _build_result(
        format="windows_ntlm_xml",
        parsed_records=(
            len(xml_records)
        ),
        events=normalized_events,
        alerts=alerts,
    )


def _parse_xml_records(
    content: str,
):
    stripped = content.strip()

    event_blocks = re.findall(
        (
            r"<Event\b[^>]*>"
            r".*?"
            r"</Event>"
        ),
        stripped,
        flags=(
            re.DOTALL
            | re.IGNORECASE
        ),
    )

    if event_blocks:
        return [
            parse_xml_event(
                block
            )
            for block in event_blocks
        ]

    return [
        parse_xml_event(
            stripped
        )
    ]


def _build_result(
    *,
    format: str,
    parsed_records: int,
    events: list[
        CanonicalEvent
    ],
    alerts: list[
        Alert
    ],
) -> AnalysisResult:
    ordered_alerts = sorted(
        alerts,
        key=lambda alert: (
            -_severity_rank(
                alert.severity
            ),
            alert.first_seen_at,
            alert.rule_id,
        ),
    )

    overall_severity = (
        _get_overall_severity(
            ordered_alerts
        )
    )

    unsupported_records = (
        parsed_records
        - len(events)
    )

    return AnalysisResult(
        format=format,
        parsed_records=(
            parsed_records
        ),
        normalized_events=(
            len(events)
        ),
        unsupported_records=(
            unsupported_records
        ),
        overall_severity=(
            overall_severity
        ),
        alerts=tuple(
            ordered_alerts
        ),
        events=tuple(
            sorted(
                events,
                key=lambda event: (
                    event.occurred_at
                ),
            )
        ),
    )


def _get_overall_severity(
    alerts: list[
        Alert
    ],
) -> str:
    if not alerts:
        return "none"

    highest = max(
        alerts,
        key=lambda alert: (
            _severity_rank(
                alert.severity
            )
        ),
    )

    severity = (
        highest.severity
        .strip()
        .lower()
    )

    if severity not in _SEVERITY_RANK:
        return "none"

    return severity


def _severity_rank(
    severity: str,
) -> int:
    return _SEVERITY_RANK.get(
        severity.strip().lower(),
        0,
    )