from __future__ import annotations

import hashlib


def build_event_fingerprint(
    *,
    source_dataset: str | None,
    raw_event: str,
) -> str:
    payload = "\x1f".join(
        (
            source_dataset or "",
            raw_event,
        )
    )

    return hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()