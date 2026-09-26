from __future__ import annotations

from dataclasses import dataclass
from typing import (
    Any,
    Literal,
    Mapping,
    Protocol,
    Sequence,
)


ChatRole = Literal[
    "system",
    "user",
    "assistant",
]


@dataclass(
    frozen=True,
    slots=True,
)
class ChatMessage:
    role: ChatRole
    content: str


class LLMProviderError(
    RuntimeError
):
    """Safe error raised by an LLM provider."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        category: str = (
            "provider_error"
        ),
    ) -> None:
        super().__init__(
            message
        )

        self.retryable = (
            retryable
        )

        self.category = (
            category
        )


class StructuredLLMProvider(
    Protocol
):
    def generate_structured(
        self,
        *,
        messages: Sequence[
            ChatMessage
        ],
        response_schema: Mapping[
            str,
            Any,
        ],
    ) -> str:
        """Return JSON matching response_schema."""