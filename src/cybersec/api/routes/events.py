from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from cybersec.api.dependencies import get_db_session
from cybersec.api.schemas.events import EventResponse
from cybersec.db.repositories.events import EventRepository


router = APIRouter(
    prefix="/api/v1/events",
    tags=["events"],
)


@router.get(
    "",
    response_model=list[EventResponse],
)
def list_events(
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    event_code: str | None = None,
    user_name: str | None = None,
    session: Session = Depends(get_db_session),
) -> list[EventResponse]:
    repository = EventRepository(session)

    events = repository.list_events(
        limit=limit,
        offset=offset,
        event_code=event_code,
        user_name=user_name,
    )

    return [
        EventResponse.model_validate(event)
        for event in events
    ]


@router.get(
    "/{event_id}",
    response_model=EventResponse,
)
def get_event(
    event_id: int,
    session: Session = Depends(get_db_session),
) -> EventResponse:
    repository = EventRepository(session)

    event = repository.get_by_id(event_id)

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Event not found",
        )

    return EventResponse.model_validate(event)