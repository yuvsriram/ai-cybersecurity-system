from __future__ import annotations

import json
from datetime import (
    datetime,
    timedelta,
    timezone,
)
from typing import Any, Mapping, Sequence

import pytest

from cybersec.ai.investigation import (
    InvestigationAlertContext,
    InvestigationEventContext,
    InvestigationGroundingError,
    InvestigationService,
)
from cybersec.ai.provider import (
    ChatMessage,
)


FINGERPRINT = "a" * 64


class FakeProvider:
    def __init__(
        self,
        response: str,
    ) -> None:
        self.response = response

        self.messages: (
            Sequence[ChatMessage] | None
        ) = None

        self.response_schema: (
            Mapping[str, Any] | None
        ) = None

    def generate_structured(
        self,
        *,
        messages: Sequence[ChatMessage],
        response_schema: Mapping[
            str,
            Any,
        ],
    ) -> str:
        self.messages = messages
        self.response_schema = (
            response_schema
        )

        return self.response


def make_alert(
) -> InvestigationAlertContext:
    return InvestigationAlertContext(
        id=(
            "00000000-0000-0000-"
            "0000-000000000001"
        ),
        rule_id="AUTH-003",
        rule_version="1.0",
        title=(
            "NTLM password-spray "
            "pattern detected"
        ),
        description="Test alert",
        severity="high",
        first_seen_at=datetime(
            2024,
            1,
            18,
            4,
            55,
            tzinfo=timezone.utc,
        ),
        last_seen_at=datetime(
            2024,
            1,
            18,
            4,
            56,
            tzinfo=timezone.utc,
        ),
        user_name=None,
        source_ip=None,
        source_host="SERVER",
        destination_host="VICTIM_PC",
        mitre_techniques=[
            "T1110.003"
        ],
    )


def make_event(
    *,
    fingerprint: str = FINGERPRINT,
    seconds: int = 0,
    user_name: str = "user-1",
) -> InvestigationEventContext:
    return InvestigationEventContext(
        event_fingerprint=fingerprint,
        occurred_at=(
            datetime(
                2024,
                1,
                18,
                4,
                55,
                tzinfo=timezone.utc,
            )
            + timedelta(
                seconds=seconds
            )
        ),
        event_code="8004",
        category="authentication",
        action="ntlm_authentication",
        outcome=None,
        source_provider=(
            "Microsoft-Windows-"
            "Security-Netlogon"
        ),
        source_channel=(
            "Microsoft-Windows-"
            "NTLM/Operational"
        ),
        source_dataset="test",
        source_record_id="12345",
        host_name="DC-01",
        user_name=user_name,
        user_domain=None,
        source_host="SERVER",
        source_ip=None,
        destination_host="VICTIM_PC",
        destination_ip=None,
        attributes={
            "SecurityUserID": "S-1-5-18",
        },
    )


def valid_response() -> str:
    return json.dumps(
        {
            "summary": (
                "The observed NTLM activity is "
                "consistent with password spraying."
            ),
            "observed_behavior": [
                (
                    "One source host generated NTLM "
                    "activity involving multiple users."
                )
            ],
            "evidence_findings": [
                {
                    "observation": (
                        "NTLM authentication activity "
                        "was observed."
                    ),
                    "evidence_ids": [
                        "E1"
                    ],
                }
            ],
            "uncertainties": [
                (
                    "Authentication outcomes are "
                    "unknown from the supplied telemetry."
                )
            ],
            "recommended_next_steps": [
                (
                    "Correlate with additional "
                    "authentication telemetry."
                )
            ],
        }
    )

def ungrounded_response() -> str:
    return json.dumps(
        {
            "summary": (
                "Failed authentication activity "
                "was observed."
            ),
            "observed_behavior": [
                (
                    "Failed authentication attempts "
                    "were observed from one source."
                )
            ],
            "evidence_findings": [
                {
                    "observation": (
                        "Failed authentication "
                        "was observed."
                    ),
                    "evidence_ids": [
                        "E1"
                    ],
                }
            ],
            "uncertainties": [],
            "recommended_next_steps": [],
        }
    )


def test_investigation_returns_structured_result(
) -> None:
    provider = FakeProvider(
        valid_response()
    )

    service = InvestigationService(
        provider
    )

    result = service.investigate(
        alert=make_alert(),
        events=[
            make_event()
        ],
    )

    assert (
        result.authentication_outcome
        == "unknown"
    )

    assert (
        result.evidence_summary.event_count
        == 1
    )

    assert (
        result.evidence_summary
        .unknown_outcome_count
        == 1
    )

    assert (
        result.evidence_findings[0]
        .event_fingerprints
        == [FINGERPRINT]
    )


def test_evidence_summary_is_deterministic(
) -> None:
    provider = FakeProvider(
        valid_response()
    )

    service = InvestigationService(
        provider
    )

    result = service.investigate(
        alert=make_alert(),
        events=[
            make_event(
                fingerprint=FINGERPRINT,
                seconds=0,
                user_name="user-a",
            ),
            make_event(
                fingerprint="b" * 64,
                seconds=32,
                user_name="user-b",
            ),
        ],
    )

    assert (
        result.evidence_summary.event_count
        == 2
    )

    assert (
        result.evidence_summary
        .unique_user_count
        == 2
    )

    assert (
        result.evidence_summary
        .duration_seconds
        == 32.0
    )


def test_unknown_evidence_id_is_rejected(
) -> None:
    response = json.dumps(
        {
            "summary": "Test",
            "observed_behavior": [],
            "evidence_findings": [
                {
                    "observation": (
                        "Invented evidence"
                    ),
                    "evidence_ids": [
                        "E999"
                    ],
                }
            ],
            "uncertainties": [],
            "recommended_next_steps": [],
        }
    )

    service = InvestigationService(
        FakeProvider(response)
    )

    with pytest.raises(
        InvestigationGroundingError
    ):
        service.investigate(
            alert=make_alert(),
            events=[
                make_event()
            ],
        )


def test_unknown_outcome_claim_is_rejected(
) -> None:
    response = json.dumps(
        {
            "summary": (
                "No successful authentication "
                "was observed."
            ),
            "observed_behavior": [],
            "evidence_findings": [
                {
                    "observation": (
                        "NTLM activity was observed."
                    ),
                    "evidence_ids": [
                        "E1"
                    ],
                }
            ],
            "uncertainties": [],
            "recommended_next_steps": [],
        }
    )

    service = InvestigationService(
        FakeProvider(response)
    )

    with pytest.raises(
        InvestigationGroundingError
    ):
        service.investigate(
            alert=make_alert(),
            events=[
                make_event()
            ],
        )

def test_grounding_failure_is_repaired_once(
) -> None:
    provider = SequencedFakeProvider(
        [
            ungrounded_response(),
            valid_response(),
        ]
    )

    service = InvestigationService(
        provider
    )

    result = service.investigate(
        alert=make_alert(),
        events=[
            make_event()
        ],
    )

    assert provider.call_count == 2

    assert (
        result.authentication_outcome
        == "unknown"
    )

    assert (
        result.summary
        == (
            "The observed NTLM activity is "
            "consistent with password spraying."
        )
    )

    assert len(
        provider.messages_history
    ) == 2

    repair_prompt = "\n".join(
        message.content
        for message in (
            provider.messages_history[1]
        )
    )

    assert (
        "previous candidate response"
        in repair_prompt
    )

    assert (
        "Failed authentication activity "
        "was observed."
        not in repair_prompt
    )


def test_repeated_grounding_failure_is_rejected(
) -> None:
    provider = SequencedFakeProvider(
        [
            ungrounded_response(),
            ungrounded_response(),
        ]
    )

    service = InvestigationService(
        provider
    )

    with pytest.raises(
        InvestigationGroundingError
    ):
        service.investigate(
            alert=make_alert(),
            events=[
                make_event()
            ],
        )

    assert provider.call_count == 2

def test_prompt_uses_compact_evidence_ids(
) -> None:
    provider = FakeProvider(
        valid_response()
    )

    service = InvestigationService(
        provider
    )

    service.investigate(
        alert=make_alert(),
        events=[
            make_event()
        ],
    )

    assert provider.messages is not None

    prompt = "\n".join(
        message.content
        for message in provider.messages
    )

    assert "S-1-5-18" not in prompt
    assert "DC-01" not in prompt

    assert FINGERPRINT not in prompt

    assert '"evidence_id":"E1"' in prompt

    assert (
        "authentication_outcome"
        in prompt
    )


def test_empty_evidence_is_rejected(
) -> None:
    service = InvestigationService(
        FakeProvider("{}")
    )

    with pytest.raises(
        ValueError
    ):
        service.investigate(
            alert=make_alert(),
            events=[],
        )

class SequencedFakeProvider:
    def __init__(
        self,
        responses: Sequence[str],
    ) -> None:
        self.responses = list(
            responses
        )

        self.call_count = 0

        self.messages_history: list[
            Sequence[ChatMessage]
        ] = []

        self.response_schema: (
            Mapping[str, Any] | None
        ) = None

    def generate_structured(
        self,
        *,
        messages: Sequence[ChatMessage],
        response_schema: Mapping[
            str,
            Any,
        ],
    ) -> str:
        self.messages_history.append(
            list(messages)
        )

        self.response_schema = (
            response_schema
        )

        if self.call_count >= len(
            self.responses
        ):
            raise AssertionError(
                "provider called more times "
                "than expected"
            )

        response = self.responses[
            self.call_count
        ]

        self.call_count += 1

        return response