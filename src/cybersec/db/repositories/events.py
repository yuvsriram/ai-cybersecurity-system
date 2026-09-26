from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import Select, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from cybersec.db.models.event import EventModel
from cybersec.domain.event_identity import (
    build_event_fingerprint,
)
from cybersec.domain.events import CanonicalEvent


class EventRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add_many(
        self,
        events: Iterable[CanonicalEvent],
    ) -> int:
        inserted = 0

        for event in events:
            event_fingerprint = build_event_fingerprint(
                source_dataset=event.source_dataset,
                raw_event=event.raw_event,
            )

            statement = (
                insert(EventModel)
                .values(
                    event_fingerprint=event_fingerprint,
                    schema_version=event.schema_version,
                    occurred_at=event.occurred_at,
                    event_code=event.event_code,
                    category=event.category,
                    action=event.action,
                    outcome=event.outcome,
                    source_provider=event.source_provider,
                    source_channel=event.source_channel,
                    source_dataset=event.source_dataset,
                    source_record_id=event.source_record_id,
                    host_name=event.host_name,
                    user_name=event.user_name,
                    user_domain=event.user_domain,
                    user_sid=event.user_sid,
                    source_host=event.source_host,
                    source_ip=event.source_ip,
                    destination_host=event.destination_host,
                    destination_ip=event.destination_ip,
                    raw_event=event.raw_event,
                    attributes=event.attributes,
                )
                .on_conflict_do_nothing(
                    constraint=(
                        "uq_security_events_event_fingerprint"
                    )
                )
                .returning(EventModel.id)
            )

            result = self._session.execute(statement)

            inserted_id = result.scalar_one_or_none()

            if inserted_id is not None:
                inserted += 1

        return inserted

    def get_by_id(
        self,
        event_id: int,
    ) -> EventModel | None:
        return self._session.get(
            EventModel,
            event_id,
        )

    def get_by_fingerprints(
        self,
        fingerprints: Iterable[str],
    ) -> list[EventModel]:
        ordered_fingerprints = list(
            fingerprints
        )

        if not ordered_fingerprints:
            return []

        statement = select(EventModel).where(
            EventModel.event_fingerprint.in_(
                ordered_fingerprints
            )
        )

        events = list(
            self._session.scalars(
                statement
            ).all()
        )

        events_by_fingerprint = {
            event.event_fingerprint: event
            for event in events
        }

        return [
            events_by_fingerprint[fingerprint]
            for fingerprint in ordered_fingerprints
            if fingerprint in events_by_fingerprint
        ]

    def list_events(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        event_code: str | None = None,
        user_name: str | None = None,
    ) -> list[EventModel]:
        statement: Select[tuple[EventModel]] = (
            select(EventModel)
            .order_by(
                EventModel.occurred_at.desc(),
                EventModel.id.desc(),
            )
            .limit(limit)
            .offset(offset)
        )

        if event_code is not None:
            statement = statement.where(
                EventModel.event_code == event_code
            )

        if user_name is not None:
            statement = statement.where(
                EventModel.user_name == user_name
            )

        return list(
            self._session.scalars(statement).all()
        )