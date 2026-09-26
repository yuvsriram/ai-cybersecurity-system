from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Select,
    select,
)
from sqlalchemy.orm import Session

from cybersec.db.models.investigation import (
    InvestigationRunModel,
)
from cybersec.domain.investigations import (
    INVESTIGATION_STATUS_COMPLETED,
    INVESTIGATION_STATUS_FAILED,
    INVESTIGATION_STATUS_QUEUED,
    INVESTIGATION_STATUS_RUNNING,
)


class InvestigationRunRepository:
    def __init__(
        self,
        session: Session,
    ) -> None:
        self._session = session

    def create_queued(
        self,
        *,
        alert_id: str,
        provider: str,
        model: str,
        prompt_version: str = "1.0",
    ) -> InvestigationRunModel:
        run = InvestigationRunModel(
            id=str(uuid4()),
            alert_id=alert_id,
            status=(
                INVESTIGATION_STATUS_QUEUED
            ),
            provider=provider,
            model=model,
            prompt_version=prompt_version,
            created_at=_utc_now(),
            started_at=None,
            completed_at=None,
            result=None,
            error_message=None,
        )

        self._session.add(run)
        self._session.flush()

        return run

    def get_by_id(
        self,
        run_id: str,
    ) -> InvestigationRunModel | None:
        return self._session.get(
            InvestigationRunModel,
            run_id,
        )

    def claim_next_queued(
        self,
    ) -> InvestigationRunModel | None:
        statement = (
            select(
                InvestigationRunModel
            )
            .where(
                InvestigationRunModel.status
                == INVESTIGATION_STATUS_QUEUED
            )
            .order_by(
                InvestigationRunModel.created_at,
                InvestigationRunModel.id,
            )
            .with_for_update(
                skip_locked=True
            )
            .limit(1)
        )

        run = self._session.scalar(
            statement
        )

        if run is None:
            return None

        run.status = (
            INVESTIGATION_STATUS_RUNNING
        )

        run.started_at = _utc_now()
        run.completed_at = None
        run.result = None
        run.error_message = None

        self._session.flush()

        return run

    def mark_completed(
        self,
        *,
        run_id: str,
        result: dict,
    ) -> InvestigationRunModel:
        run = self._require_running(
            run_id
        )

        run.status = (
            INVESTIGATION_STATUS_COMPLETED
        )

        run.completed_at = _utc_now()
        run.result = result
        run.error_message = None

        self._session.flush()

        return run

    def mark_failed(
        self,
        *,
        run_id: str,
        error_message: str,
    ) -> InvestigationRunModel:
        run = self._require_running(
            run_id
        )

        run.status = (
            INVESTIGATION_STATUS_FAILED
        )

        run.completed_at = _utc_now()
        run.result = None
        run.error_message = (
            error_message
        )

        self._session.flush()

        return run

    def list_for_alert(
        self,
        *,
        alert_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[
        InvestigationRunModel
    ]:
        statement: Select[
            tuple[InvestigationRunModel]
        ] = (
            select(
                InvestigationRunModel
            )
            .where(
                InvestigationRunModel.alert_id
                == alert_id
            )
            .order_by(
                InvestigationRunModel
                .created_at
                .desc(),
                InvestigationRunModel.id.desc(),
            )
            .limit(limit)
            .offset(offset)
        )

        return list(
            self._session.scalars(
                statement
            ).all()
        )

    def _require_running(
        self,
        run_id: str,
    ) -> InvestigationRunModel:
        run = self.get_by_id(
            run_id
        )

        if run is None:
            raise RuntimeError(
                "Investigation run does not exist"
            )

        if (
            run.status
            != INVESTIGATION_STATUS_RUNNING
        ):
            raise RuntimeError(
                "Investigation run is not "
                f"running: {run.status}"
            )

        return run


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )