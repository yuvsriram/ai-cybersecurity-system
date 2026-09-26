from __future__ import annotations

import hashlib
from collections.abc import Iterable

from sqlalchemy import Select, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from cybersec.db.models.alert import AlertModel
from cybersec.domain.alerts import Alert


class AlertRepository:
    def __init__(
        self,
        session: Session,
    ) -> None:
        self._session = session

    def add_many(
        self,
        alerts: Iterable[Alert],
    ) -> int:
        inserted_ids = (
            self.add_many_returning_ids(
                alerts
            )
        )

        return len(inserted_ids)

    def add_many_returning_ids(
        self,
        alerts: Iterable[Alert],
    ) -> list[str]:
        inserted_ids: list[str] = []

        for alert in alerts:
            dedupe_key = _build_dedupe_key(
                alert
            )

            statement = (
                insert(AlertModel)
                .values(
                    id=alert.id,
                    dedupe_key=dedupe_key,
                    rule_id=alert.rule_id,
                    rule_version=(
                        alert.rule_version
                    ),
                    title=alert.title,
                    description=(
                        alert.description
                    ),
                    severity=alert.severity,
                    created_at=(
                        alert.created_at
                    ),
                    first_seen_at=(
                        alert.first_seen_at
                    ),
                    last_seen_at=(
                        alert.last_seen_at
                    ),
                    user_name=(
                        alert.user_name
                    ),
                    source_ip=(
                        alert.source_ip
                    ),
                    source_host=(
                        alert.source_host
                    ),
                    destination_host=(
                        alert.destination_host
                    ),
                    evidence_record_ids=list(
                        alert.evidence_record_ids
                    ),
                    evidence_event_fingerprints=list(
                        alert
                        .evidence_event_fingerprints
                    ),
                    evidence_event_codes=list(
                        alert.evidence_event_codes
                    ),
                    mitre_techniques=list(
                        alert.mitre_techniques
                    ),
                )
                .on_conflict_do_nothing(
                    index_elements=[
                        "dedupe_key"
                    ]
                )
                .returning(
                    AlertModel.id
                )
            )

            result = self._session.execute(
                statement
            )

            inserted_id = (
                result.scalar_one_or_none()
            )

            if inserted_id is not None:
                inserted_ids.append(
                    inserted_id
                )

        return inserted_ids

    def get_by_id(
        self,
        alert_id: str,
    ) -> AlertModel | None:
        return self._session.get(
            AlertModel,
            alert_id,
        )

    def list_alerts(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        rule_id: str | None = None,
    ) -> list[AlertModel]:
        statement: Select[
            tuple[AlertModel]
        ] = (
            select(AlertModel)
            .order_by(
                AlertModel
                .first_seen_at
                .desc(),
                AlertModel.id.desc(),
            )
            .limit(limit)
            .offset(offset)
        )

        if severity is not None:
            statement = (
                statement.where(
                    AlertModel.severity
                    == severity
                )
            )

        if rule_id is not None:
            statement = (
                statement.where(
                    AlertModel.rule_id
                    == rule_id
                )
            )

        return list(
            self._session.scalars(
                statement
            ).all()
        )


def _build_dedupe_key(
    alert: Alert,
) -> str:
    payload = "|".join(
        (
            alert.rule_id,
            alert.rule_version,
            alert.first_seen_at.isoformat(),
            alert.last_seen_at.isoformat(),
            alert.user_name or "",
            alert.source_ip or "",
            alert.source_host or "",
            ",".join(
                alert
                .evidence_event_fingerprints
            ),
        )
    )

    return hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()