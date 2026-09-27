from __future__ import annotations

from datetime import datetime

from fastapi.testclient import (
    TestClient,
)

from cybersec.ai.provider import (
    LLMProviderError,
)
from cybersec.api.ai_dependencies import (
    get_investigation_service,
)
from cybersec.main import app


def _failed_logon_content() -> str:
    timestamps = [
        "01/01/2026 12:00:00 PM",
        "01/01/2026 12:00:30 PM",
        "01/01/2026 12:01:00 PM",
        "01/01/2026 12:01:30 PM",
        "01/01/2026 12:02:00 PM",
    ]

    records: list[str] = []

    for index, timestamp in (
        enumerate(
            timestamps
        )
    ):
        records.append(
            f"{timestamp}\n"
            "EventCode=4625\n"
            "SourceName="
            "Microsoft-Windows-"
            "Security-Auditing\n"
            "LogName=Security\n"
            "ComputerName=SERVER01\n"
            f"RecordNumber="
            f"{9100 + index}\n"
            "Message=An account "
            "failed to log on.\n"
            "Account For Which "
            "Logon Failed:\n"
            "    Security ID: "
            "NULL SID\n"
            "    Account Name: "
            "alice\n"
            "    Account Domain: "
            "CORP\n"
            "Network Information:\n"
            "    Workstation Name: "
            "CLIENT01\n"
            "    Source Network "
            "Address: 10.0.0.50\n"
            "\n"
        )

    return "".join(
        records
    )


def _no_detection_content() -> str:
    return (
        "01/01/2026 12:00:00 PM\n"
        "EventCode=4625\n"
        "SourceName=Microsoft-Windows-"
        "Security-Auditing\n"
        "LogName=Security\n"
        "ComputerName=SERVER01\n"
        "RecordNumber=9200\n"
        "Message=An account failed "
        "to log on.\n"
        "Account For Which Logon Failed:\n"
        "    Security ID: NULL SID\n"
        "    Account Name: alice\n"
        "    Account Domain: CORP\n"
        "Network Information:\n"
        "    Workstation Name: CLIENT01\n"
        "    Source Network Address: "
        "10.0.0.50\n"
        "\n"
    )


class FakeInvestigationService:
    def __init__(
        self,
    ) -> None:
        self.calls = 0

    def investigate(
        self,
        *,
        alert,
        events,
    ):
        self.calls += 1

        assert (
            alert.rule_id
            == "AUTH-002"
        )

        assert (
            alert.severity
            == "high"
        )

        assert (
            alert.mitre_techniques
            == ["T1110.001"]
            or alert.mitre_techniques
            == ("T1110.001",)
        )

        assert len(events) == 5

        fingerprints = [
            event.event_fingerprint
            for event in events
        ]

        return {
            "evidence_summary": {
                "event_count": 5,
                "first_seen_at": (
                    datetime(
                        2026,
                        1,
                        1,
                        12,
                        0,
                        0,
                    )
                ),
                "last_seen_at": (
                    datetime(
                        2026,
                        1,
                        1,
                        12,
                        2,
                        0,
                    )
                ),
                "duration_seconds": (
                    120.0
                ),
                "unique_user_count": 1,
                "source_hosts": [
                    "CLIENT01"
                ],
                "destination_hosts": [
                    "SERVER01"
                ],
                "event_codes": [
                    "4625"
                ],
                "known_outcomes": {
                    "failure": 5
                },
                "unknown_outcome_count": (
                    0
                ),
            },
            "authentication_outcome": (
                "failure"
            ),
            "summary": (
                "Repeated failed logon "
                "activity was observed "
                "for the same account "
                "and source."
            ),
            "observed_behavior": [
                (
                    "Five failed logon "
                    "events occurred "
                    "within two minutes."
                )
            ],
            "evidence_findings": [
                {
                    "observation": (
                        "The detection is "
                        "supported by the "
                        "supplied events."
                    ),
                    "event_fingerprints": (
                        fingerprints[:3]
                    ),
                }
            ],
            "uncertainties": [
                (
                    "The supplied telemetry "
                    "does not establish "
                    "whether an attacker "
                    "controlled the source."
                )
            ],
            "recommended_next_steps": [
                (
                    "Review authentication "
                    "activity for the user "
                    "and source."
                )
            ],
        }


class FailingInvestigationService:
    def investigate(
        self,
        *,
        alert,
        events,
    ):
        raise LLMProviderError(
            "test provider failure"
        )


class MustNotRunService:
    def investigate(
        self,
        *,
        alert,
        events,
    ):
        raise AssertionError(
            "AI service must not run "
            "when there is no detection"
        )


def test_explain_analysis_uses_backend_finding(
    client: TestClient,
) -> None:
    service = (
        FakeInvestigationService()
    )

    app.dependency_overrides[
        get_investigation_service
    ] = lambda: service

    try:
        response = client.post(
            "/api/v1/analyze/explain",
            json={
                "format": (
                    "splunk_windows_security"
                ),
                "dataset_name": (
                    "analysis_ai_test"
                ),
                "content": (
                    _failed_logon_content()
                ),
            },
        )

    finally:
        app.dependency_overrides.pop(
            get_investigation_service,
            None,
        )

    assert response.status_code == 200

    body = response.json()

    assert (
        body["analysis"][
            "overall_severity"
        ]
        == "high"
    )

    assert (
        body[
            "primary_finding"
        ]["rule_id"]
        == "AUTH-002"
    )

    assert (
        body[
            "primary_finding"
        ]["severity"]
        == "high"
    )

    assert (
        body[
            "primary_finding"
        ]["mitre_techniques"]
        == [
            "T1110.001"
        ]
    )

    assert (
        body["explanation"][
            "evidence_summary"
        ]["event_count"]
        == 5
    )

    assert service.calls == 1


def test_explain_analysis_skips_ai_without_detection(
    client: TestClient,
) -> None:
    app.dependency_overrides[
        get_investigation_service
    ] = lambda: MustNotRunService()

    try:
        response = client.post(
            "/api/v1/analyze/explain",
            json={
                "format": (
                    "splunk_windows_security"
                ),
                "dataset_name": (
                    "analysis_ai_test"
                ),
                "content": (
                    _no_detection_content()
                ),
            },
        )

    finally:
        app.dependency_overrides.pop(
            get_investigation_service,
            None,
        )

    assert response.status_code == 200

    body = response.json()

    assert (
        body["analysis"][
            "detected_alerts"
        ]
        == 0
    )

    assert (
        body["primary_finding"]
        is None
    )

    assert (
        body["explanation"]
        is None
    )


def test_explain_analysis_provider_failure_returns_503(
    client: TestClient,
) -> None:
    app.dependency_overrides[
        get_investigation_service
    ] = (
        lambda:
        FailingInvestigationService()
    )

    try:
        response = client.post(
            "/api/v1/analyze/explain",
            json={
                "format": (
                    "splunk_windows_security"
                ),
                "dataset_name": (
                    "analysis_ai_test"
                ),
                "content": (
                    _failed_logon_content()
                ),
            },
        )

    finally:
        app.dependency_overrides.pop(
            get_investigation_service,
            None,
        )

    assert response.status_code == 503

    assert response.json() == {
        "detail": (
            "AI explanation provider "
            "is unavailable"
        )
    }