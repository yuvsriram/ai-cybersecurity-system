from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Select,
    select,
)
from sqlalchemy.orm import Session

from cybersec.db.models.alert import (
    AlertModel,
)
from cybersec.db.models.case import (
    CaseAlertModel,
    CaseModel,
)
from cybersec.domain.cases import (
    CASE_STATUS_INVESTIGATING,
    CASE_STATUS_OPEN,
)


class CaseRepository:
    def __init__(
        self,
        session: Session,
    ) -> None:
        self._session = session

    def create(
        self,
        *,
        title: str,
        severity: str,
        summary: str | None = None,
        creation_source: str = "manual",
    ) -> CaseModel:
        now = _utc_now()

        case = CaseModel(
            id=str(uuid4()),
            title=title,
            summary=summary,
            status=CASE_STATUS_OPEN,
            severity=severity,
            creation_source=creation_source,
            created_at=now,
            updated_at=now,
            closed_at=None,
        )

        self._session.add(case)
        self._session.flush()

        return case

    def get_by_id(
        self,
        case_id: str,
    ) -> CaseModel | None:
        return self._session.get(
            CaseModel,
            case_id,
        )

    def list_cases(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        status: str | None = None,
        severity: str | None = None,
    ) -> list[CaseModel]:
        statement: Select[
            tuple[CaseModel]
        ] = (
            select(CaseModel)
            .order_by(
                CaseModel.updated_at.desc(),
                CaseModel.id.desc(),
            )
            .limit(limit)
            .offset(offset)
        )

        if status is not None:
            statement = statement.where(
                CaseModel.status == status
            )

        if severity is not None:
            statement = statement.where(
                CaseModel.severity
                == severity
            )

        return list(
            self._session.scalars(
                statement
            ).all()
        )

    def list_active_cases(
        self,
        *,
        limit: int = 500,
    ) -> list[CaseModel]:
        statement = (
            select(CaseModel)
            .where(
                CaseModel.status.in_(
                    (
                        CASE_STATUS_OPEN,
                        CASE_STATUS_INVESTIGATING,
                    )
                )
            )
            .order_by(
                CaseModel.updated_at.desc(),
                CaseModel.id.desc(),
            )
            .limit(limit)
        )

        return list(
            self._session.scalars(
                statement
            ).all()
        )

    def list_cases_for_alert(
        self,
        *,
        alert_id: str,
    ) -> list[CaseModel]:
        statement = (
            select(CaseModel)
            .join(
                CaseAlertModel,
                CaseAlertModel.case_id
                == CaseModel.id,
            )
            .where(
                CaseAlertModel.alert_id
                == alert_id
            )
            .order_by(
                CaseModel.updated_at.desc(),
                CaseModel.id.desc(),
            )
        )

        return list(
            self._session.scalars(
                statement
            ).all()
        )

    def add_alert(
        self,
        *,
        case_id: str,
        alert_id: str,
        correlation_reason: str | None = None,
    ) -> bool:
        existing = self._session.get(
            CaseAlertModel,
            {
                "case_id": case_id,
                "alert_id": alert_id,
            },
        )

        if existing is not None:
            return False

        case = self.get_by_id(
            case_id
        )

        if case is None:
            raise RuntimeError(
                "Case does not exist"
            )

        link = CaseAlertModel(
            case_id=case_id,
            alert_id=alert_id,
            added_at=_utc_now(),
            correlation_reason=(
                correlation_reason
            ),
        )

        self._session.add(link)

        case.updated_at = _utc_now()

        self._session.flush()

        return True

    def list_alerts(
        self,
        *,
        case_id: str,
    ) -> list[AlertModel]:
        statement = (
            select(AlertModel)
            .join(
                CaseAlertModel,
                CaseAlertModel.alert_id
                == AlertModel.id,
            )
            .where(
                CaseAlertModel.case_id
                == case_id
            )
            .order_by(
                AlertModel.first_seen_at,
                AlertModel.id,
            )
        )

        return list(
            self._session.scalars(
                statement
            ).all()
        )

    def get_alert_link(
        self,
        *,
        case_id: str,
        alert_id: str,
    ) -> CaseAlertModel | None:
        return self._session.get(
            CaseAlertModel,
            {
                "case_id": case_id,
                "alert_id": alert_id,
            },
        )

    def update_severity(
        self,
        *,
        case_id: str,
        severity: str,
    ) -> CaseModel:
        case = self.get_by_id(
            case_id
        )

        if case is None:
            raise RuntimeError(
                "Case does not exist"
            )

        case.severity = severity
        case.updated_at = _utc_now()

        self._session.flush()

        return case


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )