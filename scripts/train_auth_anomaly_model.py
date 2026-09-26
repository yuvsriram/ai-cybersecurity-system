from __future__ import annotations

import json
import os
from pathlib import Path

import mlflow
import mlflow.sklearn
from sqlalchemy import select

from cybersec.db.models.event import (
    EventModel,
)
from cybersec.db.session import (
    create_session,
)
from cybersec.ml.experiment import (
    build_experiment_summary,
)
from cybersec.ml.features import (
    build_authentication_feature_vectors,
    feature_names,
)
from cybersec.ml.isolation_forest import (
    AuthenticationIsolationForest,
)


EXPERIMENT_NAME = (
    "authentication-anomaly-detection"
)

WINDOW_SECONDS = 300
CONTAMINATION = 0.10
RANDOM_STATE = 42
N_ESTIMATORS = 200


def main() -> None:
    tracking_uri = os.getenv(
        "CYBERSEC_MLFLOW_TRACKING_URI",
        "sqlite:///mlflow.db",
    )

    mlflow.set_tracking_uri(
        tracking_uri
    )

    mlflow.set_experiment(
        EXPERIMENT_NAME
    )

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

    finally:
        session.close()

    vectors = (
        build_authentication_feature_vectors(
            events,
            window_seconds=(
                WINDOW_SECONDS
            ),
        )
    )

    if len(vectors) < 2:
        raise RuntimeError(
            "Not enough feature vectors "
            "to train model"
        )

    model = AuthenticationIsolationForest(
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
    )

    model.fit(
        vectors
    )

    scores = model.score(
        vectors
    )

    summary = (
        build_experiment_summary(
            scores
        )
    )

    artifact_dir = Path(
        ".artifacts"
    )

    artifact_dir.mkdir(
        exist_ok=True
    )

    summary_path = (
        artifact_dir
        / "auth_anomaly_summary.json"
    )

    features_path = (
        artifact_dir
        / "auth_anomaly_features.json"
    )

    summary_path.write_text(
        json.dumps(
            summary,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    features_path.write_text(
        json.dumps(
            {
                "feature_names": (
                    feature_names()
                ),
                "window_seconds": (
                    WINDOW_SECONDS
                ),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    with mlflow.start_run() as run:
        mlflow.log_params(
            {
                "window_seconds": (
                    WINDOW_SECONDS
                ),
                "contamination": (
                    CONTAMINATION
                ),
                "random_state": (
                    RANDOM_STATE
                ),
                "n_estimators": (
                    N_ESTIMATORS
                ),
                "feature_count": len(
                    feature_names()
                ),
            }
        )

        mlflow.log_metrics(
            {
                "authentication_event_count": (
                    len(events)
                ),
                "feature_window_count": (
                    len(vectors)
                ),
                "anomaly_count": (
                    summary[
                        "anomaly_count"
                    ]
                ),
                "anomaly_fraction": (
                    summary[
                        "anomaly_count"
                    ]
                    / len(vectors)
                ),
            }
        )

        mlflow.log_artifact(
            str(summary_path)
        )

        mlflow.log_artifact(
            str(features_path)
        )

        mlflow.sklearn.log_model(
            sk_model=model.estimator,
            name="model",
            skops_trusted_types=[
                "sklearn.tree._tree.Tree",
            ],
        )

        print(
            "MLflow experiment: "
            f"{EXPERIMENT_NAME}"
        )

        print(
            f"Run ID: "
            f"{run.info.run_id}"
        )

        print(
            f"Tracking URI: "
            f"{tracking_uri}"
        )

        print(
            "Authentication events: "
            f"{len(events)}"
        )

        print(
            "Feature windows: "
            f"{len(vectors)}"
        )

        print(
            "Anomalies: "
            f"{summary['anomaly_count']}"
        )


if __name__ == "__main__":
    main()