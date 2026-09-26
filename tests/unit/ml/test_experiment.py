from datetime import datetime

from cybersec.ml.experiment import (
    build_experiment_summary,
)
from cybersec.ml.features import (
    AuthenticationFeatureVector,
)
from cybersec.ml.isolation_forest import (
    AnomalyScore,
)


def _score(
    *,
    anomaly_score: float,
    is_anomaly: bool,
) -> AnomalyScore:
    timestamp = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
    )

    vector = (
        AuthenticationFeatureVector(
            window_start=timestamp,
            window_end=timestamp,
            source_host="SOURCE",
            source_ip=None,
            event_count=1,
            distinct_user_count=1,
            distinct_destination_count=1,
            failed_count=1,
            success_count=0,
            unknown_outcome_count=0,
            event_4625_count=1,
            event_4740_count=0,
            event_8004_count=0,
            events_per_second=(
                1 / 300
            ),
        )
    )

    return AnomalyScore(
        vector=vector,
        anomaly_score=(
            anomaly_score
        ),
        is_anomaly=is_anomaly,
    )


def test_experiment_summary_ranks_scores() -> None:
    summary = (
        build_experiment_summary(
            [
                _score(
                    anomaly_score=0.1,
                    is_anomaly=True,
                ),
                _score(
                    anomaly_score=-0.2,
                    is_anomaly=False,
                ),
            ]
        )
    )

    assert (
        summary["window_count"]
        == 2
    )

    assert (
        summary["anomaly_count"]
        == 1
    )

    assert (
        summary["top_windows"][0]
        ["anomaly_score"]
        == 0.1
    )