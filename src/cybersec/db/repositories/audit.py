from __future__ import annotations

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from cybersec.db.models.audit import (
    AuditEventModel,
)
from cybersec.core.security import (
    Principal,
)


class AuditRepository:
    def __init__(
        self,
        session: Session,
    ) -> None:
        self._session = session

    def record(
        self,
        *,
        principal: Principal,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        outcome: str = "success",
        detail: str | None = None,
        attributes: (
            dict[str, object]
            | None
        ) = None,
    ) -> AuditEventModel:
        event = AuditEventModel(
            actor_name=principal.name,
            actor_role=principal.role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            detail=detail,
            attributes=(
                attributes or {}
            ),
        )

        self._session.add(
            event
        )

        self._session.flush()

        return event

    def list_events(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        actor_name: str | None = None,
        action: str | None = None,
        resource_type: (
            str | None
        ) = None,
    ) -> list[
        AuditEventModel
    ]:
        statement: Select[
            tuple[AuditEventModel]
        ] = (
            select(
                AuditEventModel
            )
            .order_by(
                AuditEventModel
                .created_at
                .desc(),
                AuditEventModel
                .id
                .desc(),
            )
            .limit(limit)
            .offset(offset)
        )

        if actor_name is not None:
            statement = (
                statement.where(
                    AuditEventModel
                    .actor_name
                    == actor_name
                )
            )

        if action is not None:
            statement = (
                statement.where(
                    AuditEventModel.action
                    == action
                )
            )

        if (
            resource_type
            is not None
        ):
            statement = (
                statement.where(
                    AuditEventModel
                    .resource_type
                    == resource_type
                )
            )

        return list(
            self._session.scalars(
                statement
            ).all()
        )