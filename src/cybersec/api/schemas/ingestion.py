from __future__ import annotations

from pydantic import BaseModel, Field


class WindowsSecurityIngestionRequest(BaseModel):
    dataset_name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.-]+$",
    )

    content: str = Field(
        min_length=1,
        max_length=2_000_000,
    )


class IngestionResponse(BaseModel):
    parsed_records: int
    normalized_events: int
    unsupported_records: int

    detected_alerts: int

    inserted_events: int
    inserted_alerts: int