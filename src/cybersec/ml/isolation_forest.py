from __future__ import annotations

from dataclasses import dataclass

from sklearn.ensemble import (
    IsolationForest,
)

from cybersec.ml.features import (
    AuthenticationFeatureVector,
    feature_vector_to_numeric,
)


@dataclass(
    frozen=True,
    slots=True,
)
class AnomalyScore:
    vector: AuthenticationFeatureVector

    anomaly_score: float
    is_anomaly: bool


class AuthenticationIsolationForest:
    def __init__(
        self,
        *,
        contamination: float = 0.1,
        random_state: int = 42,
    ) -> None:
        if not (
            0 < contamination <= 0.5
        ):
            raise ValueError(
                "contamination must be "
                "greater than 0 and at most 0.5"
            )

        self._model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=200,
        )

        self._is_fitted = False

    def fit(
        self,
        vectors: list[
            AuthenticationFeatureVector
        ],
    ) -> None:
        if len(vectors) < 2:
            raise ValueError(
                "At least two feature "
                "vectors are required"
            )

        matrix = [
            feature_vector_to_numeric(
                vector
            )
            for vector in vectors
        ]

        self._model.fit(matrix)

        self._is_fitted = True

    def score(
        self,
        vectors: list[
            AuthenticationFeatureVector
        ],
    ) -> list[AnomalyScore]:
        if not self._is_fitted:
            raise RuntimeError(
                "Model must be fitted "
                "before scoring"
            )

        if not vectors:
            return []

        matrix = [
            feature_vector_to_numeric(
                vector
            )
            for vector in vectors
        ]

        predictions = (
            self._model.predict(
                matrix
            )
        )

        raw_scores = (
            self._model
            .decision_function(
                matrix
            )
        )

        return [
            AnomalyScore(
                vector=vector,
                # Higher number means
                # more anomalous.
                anomaly_score=(
                    -float(raw_score)
                ),
                is_anomaly=(
                    int(prediction)
                    == -1
                ),
            )
            for (
                vector,
                raw_score,
                prediction,
            ) in zip(
                vectors,
                raw_scores,
                predictions,
                strict=True,
            )
        ]

    @property
    def estimator(
        self,
    ) -> IsolationForest:
        if not self._is_fitted:
            raise RuntimeError(
                "Model must be fitted before "
                "accessing estimator"
            )

        return self._model