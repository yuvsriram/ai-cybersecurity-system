from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from cybersec.db.models.alert import (
    AlertModel,
)
from cybersec.db.models.case import (
    CaseModel,
)
from cybersec.db.repositories.cases import (
    CaseRepository,
)
from cybersec.domain.correlation import (
    AlertCorrelationResult,
)


CORRELATION_WINDOW = timedelta(
    minutes=15
)


SEVERITY_PRIORITY = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(
    frozen=True,
    slots=True,
)
class _Candidate:
    case: CaseModel
    priority: int
    gap_seconds: float
    reason: str


class AlertCorrelationService:
    def __init__(
        self,
        case_repository: CaseRepository,
    ) -> None:
        self._cases = case_repository

    def correlate(
        self,
        *,
        alert: AlertModel,
    ) -> AlertCorrelationResult:
        existing_cases = (
            self._cases
            .list_cases_for_alert(
                alert_id=alert.id
            )
        )

        if existing_cases:
            case = existing_cases[0]

            return AlertCorrelationResult(
                alert_id=alert.id,
                case_id=case.id,
                case_created=False,
                alert_added=False,
                correlation_reason=(
                    "Alert is already linked "
                    "to this case"
                ),
            )

        candidate = (
            self._find_best_candidate(
                alert
            )
        )

        if candidate is not None:
            added = self._cases.add_alert(
                case_id=(
                    candidate.case.id
                ),
                alert_id=alert.id,
                correlation_reason=(
                    candidate.reason
                ),
            )

            self._raise_case_severity(
                case=candidate.case,
                alert=alert,
            )

            return AlertCorrelationResult(
                alert_id=alert.id,
                case_id=(
                    candidate.case.id
                ),
                case_created=False,
                alert_added=added,
                correlation_reason=(
                    candidate.reason
                ),
            )

        case = self._cases.create(
            title=(
                "Correlated investigation: "
                f"{alert.title}"
            ),
            severity=alert.severity,
            summary=(
                "Automatically created from "
                f"alert {alert.id} "
                f"({alert.rule_id})."
            ),
            creation_source="correlation",
        )

        reason = (
            "Initial alert for automatically "
            "created case"
        )

        self._cases.add_alert(
            case_id=case.id,
            alert_id=alert.id,
            correlation_reason=reason,
        )

        return AlertCorrelationResult(
            alert_id=alert.id,
            case_id=case.id,
            case_created=True,
            alert_added=True,
            correlation_reason=reason,
        )

    def _find_best_candidate(
        self,
        alert: AlertModel,
    ) -> _Candidate | None:
        candidates: list[
            _Candidate
        ] = []

        active_cases = (
            self._cases.list_active_cases()
        )

        for case in active_cases:
            existing_alerts = (
                self._cases.list_alerts(
                    case_id=case.id
                )
            )

            for existing in (
                existing_alerts
            ):
                gap_seconds = (
                    _time_gap_seconds(
                        alert,
                        existing,
                    )
                )

                if (
                    gap_seconds
                    > CORRELATION_WINDOW
                    .total_seconds()
                ):
                    continue

                match = (
                    _match_alerts(
                        alert,
                        existing,
                    )
                )

                if match is None:
                    continue

                priority, reason = match
                if (
                    priority == 10
                    and gap_seconds > 0
                ):
                    continue

                candidates.append(
                    _Candidate(
                        case=case,
                        priority=priority,
                        gap_seconds=(
                            gap_seconds
                        ),
                        reason=(
                            f"{reason}; "
                            "evidence-window gap "
                            f"{gap_seconds:.1f}s"
                        ),
                    )
                )

        if not candidates:
            return None

        candidates.sort(
            key=lambda candidate: (
                -candidate.priority,
                candidate.gap_seconds,
                -candidate.case
                .updated_at
                .timestamp(),
                candidate.case.id,
            )
        )

        return candidates[0]

    def _raise_case_severity(
        self,
        *,
        case: CaseModel,
        alert: AlertModel,
    ) -> None:
        current_priority = (
            SEVERITY_PRIORITY.get(
                case.severity,
                0,
            )
        )

        alert_priority = (
            SEVERITY_PRIORITY.get(
                alert.severity,
                0,
            )
        )

        if (
            alert_priority
            > current_priority
        ):
            self._cases.update_severity(
                case_id=case.id,
                severity=alert.severity,
            )


def _match_alerts(
    new_alert: AlertModel,
    existing_alert: AlertModel,
) -> tuple[
    int,
    str,
] | None:
    new_fingerprints = set(
        new_alert
        .evidence_event_fingerprints
        or []
    )

    existing_fingerprints = set(
        existing_alert
        .evidence_event_fingerprints
        or []
    )

    overlap = (
        new_fingerprints
        & existing_fingerprints
    )

    if overlap:
        return (
            50,
            (
                "Shared evidence events "
                f"({len(overlap)} overlapping "
                "fingerprint(s))"
            ),
        )

    if (
        new_alert.source_ip
        and existing_alert.source_ip
        and (
            new_alert.source_ip
            == existing_alert.source_ip
        )
    ):
        return (
            40,
            (
                "Shared source IP "
                f"{new_alert.source_ip}"
            ),
        )

    if (
        new_alert.source_host
        and existing_alert.source_host
        and (
            new_alert.source_host
            == existing_alert.source_host
        )
    ):
        return (
            30,
            (
                "Shared source host "
                f"{new_alert.source_host}"
            ),
        )

    if (
        new_alert.user_name
        and existing_alert.user_name
        and (
            new_alert.user_name
            == existing_alert.user_name
        )
        and new_alert.destination_host
        and existing_alert.destination_host
        and (
            new_alert.destination_host
            == existing_alert.destination_host
        )
    ):
        return (
            20,
            (
                "Shared user and destination "
                f"({new_alert.user_name}, "
                f"{new_alert.destination_host})"
            ),
        )

    if (
        new_alert.rule_id
        == existing_alert.rule_id
        and new_alert.destination_host
        and existing_alert.destination_host
        and (
            new_alert.destination_host
            == existing_alert.destination_host
        )
    ):
        return (
            10,
            (
                "Shared rule and destination "
                f"({new_alert.rule_id}, "
                f"{new_alert.destination_host})"
            ),
        )

    return None


def _time_gap_seconds(
    first: AlertModel,
    second: AlertModel,
) -> float:
    if (
        first.last_seen_at
        < second.first_seen_at
    ):
        return (
            second.first_seen_at
            - first.last_seen_at
        ).total_seconds()

    if (
        second.last_seen_at
        < first.first_seen_at
    ):
        return (
            first.first_seen_at
            - second.last_seen_at
        ).total_seconds()

    return 0.0