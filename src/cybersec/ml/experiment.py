from __future__ import annotations

from dataclasses import asdict

from cybersec.ml.isolation_forest import (
    AnomalyScore,
)


def build_experiment_summary(
    scores: list[AnomalyScore],
) -> dict[str, object]:
    ranked = sorted(
        scores,
        key=lambda score: (
            score.anomaly_score
        ),
        reverse=True,
    )

    return {
        "window_count": len(scores),
        "anomaly_count": sum(
            1
            for score in scores
            if score.is_anomaly
        ),
        "top_windows": [
            {
                **asdict(
                    score.vector
                ),
                "anomaly_score": (
                    score.anomaly_score
                ),
                "is_anomaly": (
                    score.is_anomaly
                ),
            }
            for score in ranked[:20]
        ],
    }