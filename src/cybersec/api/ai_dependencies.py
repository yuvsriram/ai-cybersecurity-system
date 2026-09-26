from __future__ import annotations

from cybersec.ai.factory import (
    build_provider,
)
from cybersec.ai.investigation import (
    InvestigationService,
)


def get_investigation_service(
) -> InvestigationService:
    return InvestigationService(
        build_provider()
    )