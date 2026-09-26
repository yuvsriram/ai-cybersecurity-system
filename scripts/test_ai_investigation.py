from __future__ import annotations

import sys

from cybersec.ai.investigation import (
    InvestigationAlertContext,
    InvestigationEventContext,
    InvestigationService,
)
from cybersec.ai.ollama import (
    OllamaProvider,
)
from cybersec.db.repositories.alerts import (
    AlertRepository,
)
from cybersec.db.repositories.events import (
    EventRepository,
)
from cybersec.db.session import (
    create_session,
)


def main() -> None:
    session = create_session()

    try:
        alert_repository = AlertRepository(
            session
        )

        event_repository = EventRepository(
            session
        )

        if len(sys.argv) > 1:
            alert = (
                alert_repository.get_by_id(
                    sys.argv[1]
                )
            )

        else:
            alerts = (
                alert_repository.list_alerts(
                    rule_id="AUTH-003",
                    limit=1,
                )
            )

            alert = (
                alerts[0]
                if alerts
                else None
            )

        if alert is None:
            raise RuntimeError(
                "No alert found"
            )

        events = (
            event_repository
            .get_by_fingerprints(
                alert
                .evidence_event_fingerprints
            )
        )

        if len(events) != len(
            alert.evidence_event_fingerprints
        ):
            raise RuntimeError(
                "Alert evidence integrity "
                "check failed"
            )

        alert_context = (
            InvestigationAlertContext
            .model_validate(alert)
        )

        event_contexts = [
            InvestigationEventContext
            .model_validate(event)
            for event in events
        ]

        provider = OllamaProvider(
            model="qwen3:4b",
            timeout_seconds=300.0,
            context_window=4096,
            max_output_tokens=1600,
        )

        service = InvestigationService(
            provider
        )

        result = service.investigate(
            alert=alert_context,
            events=event_contexts,
        )

        print(
            result.model_dump_json(
                indent=2
            )
        )

    finally:
        session.close()


if __name__ == "__main__":
    main()