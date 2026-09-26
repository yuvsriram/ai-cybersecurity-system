from __future__ import annotations

from sqlalchemy import select

from cybersec.db.models.alert import (
    AlertModel,
)
from cybersec.db.models.event import (
    EventModel,
)
from cybersec.db.session import (
    create_session,
)
from cybersec.ml.features import (
    AuthenticationFeatureVector,
    build_authentication_feature_vectors,
    feature_names,
)
from cybersec.ml.isolation_forest import (
    AuthenticationIsolationForest,
)


def main() -> None:
    session = create_session()

    try:
        events = list(
            session.scalars(
                select(EventModel)
                .where(
                    EventModel.category
                    == "authentication"
                )
                .order_by(
                    EventModel.occurred_at,
                    EventModel.id,
                )
            ).all()
        )

        alerts = list(
            session.scalars(
                select(AlertModel)
                .order_by(
                    AlertModel.first_seen_at,
                    AlertModel.id,
                )
            ).all()
        )

        print(
            f"Authentication events: "
            f"{len(events)}"
        )

        print(
            f"Existing rule alerts: "
            f"{len(alerts)}"
        )

        vectors = (
            build_authentication_feature_vectors(
                events,
                window_seconds=300,
            )
        )

        print(
            f"Feature windows: "
            f"{len(vectors)}"
        )

        print(
            "Features: "
            + ", ".join(
                feature_names()
            )
        )

        if len(vectors) < 2:
            raise RuntimeError(
                "Not enough feature windows "
                "to train model"
            )

        model = (
            AuthenticationIsolationForest(
                contamination=0.10,
                random_state=42,
            )
        )

        model.fit(
            vectors
        )

        scores = model.score(
            vectors
        )

        ranked = sorted(
            scores,
            key=lambda score: (
                score.anomaly_score
            ),
            reverse=True,
        )

        anomaly_count = sum(
            1
            for score in scores
            if score.is_anomaly
        )

        print()
        print(
            f"Isolation Forest anomalies: "
            f"{anomaly_count}/"
            f"{len(scores)}"
        )

        print()
        print(
            "Top anomaly windows"
        )

        print(
            "=" * 100
        )

        for index, score in enumerate(
            ranked[:15],
            start=1,
        ):
            vector = score.vector

            matching_rules = (
                _matching_alert_rules(
                    vector,
                    alerts,
                )
            )

            print(
                f"#{index}"
            )

            print(
                "  score: "
                f"{score.anomaly_score:.6f}"
            )

            print(
                "  anomaly: "
                f"{score.is_anomaly}"
            )

            print(
                "  window: "
                f"{vector.window_start}"
                " -> "
                f"{vector.window_end}"
            )

            print(
                "  source_host: "
                f"{vector.source_host}"
            )

            print(
                "  source_ip: "
                f"{vector.source_ip}"
            )

            print(
                "  event_count: "
                f"{vector.event_count}"
            )

            print(
                "  distinct_users: "
                f"{vector.distinct_user_count}"
            )

            print(
                "  distinct_destinations: "
                f"{vector.distinct_destination_count}"
            )

            print(
                "  outcomes: "
                f"failure="
                f"{vector.failed_count}, "
                f"success="
                f"{vector.success_count}, "
                f"unknown="
                f"{vector.unknown_outcome_count}"
            )

            print(
                "  event_codes: "
                f"4625="
                f"{vector.event_4625_count}, "
                f"4740="
                f"{vector.event_4740_count}, "
                f"8004="
                f"{vector.event_8004_count}"
            )

            print(
                "  rule_alert_overlap: "
                + (
                    ", ".join(
                        matching_rules
                    )
                    if matching_rules
                    else "none"
                )
            )

            print(
                "-" * 100
            )

    finally:
        session.close()


def _matching_alert_rules(
    vector: AuthenticationFeatureVector,
    alerts: list[AlertModel],
) -> list[str]:
    matching: set[str] = set()

    for alert in alerts:
        if not _time_overlaps(
            vector,
            alert,
        ):
            continue

        if not _source_matches(
            vector,
            alert,
        ):
            continue

        matching.add(
            alert.rule_id
        )

    return sorted(
        matching
    )


def _time_overlaps(
    vector: AuthenticationFeatureVector,
    alert: AlertModel,
) -> bool:
    return not (
        vector.window_end
        < alert.first_seen_at
        or vector.window_start
        > alert.last_seen_at
    )


def _source_matches(
    vector: AuthenticationFeatureVector,
    alert: AlertModel,
) -> bool:
    if (
        vector.source_ip
        and alert.source_ip
    ):
        return (
            vector.source_ip
            == alert.source_ip
        )

    if (
        vector.source_host
        and alert.source_host
    ):
        return (
            vector.source_host
            == alert.source_host
        )

    if (
        vector.source_ip is None
        and vector.source_host is None
        and alert.source_ip is None
        and alert.source_host is None
    ):
        return True

    return False


if __name__ == "__main__":
    main()