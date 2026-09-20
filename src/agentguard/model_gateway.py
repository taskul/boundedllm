"""Provider-neutral bounded model transport.

This module stays free of HTTP clients and deployment configuration so a host can
implement ``ModelProvider`` against whatever SDK it already uses. Concrete
transports live in ``agentguard.adapters``.
"""

import asyncio
from dataclasses import dataclass
from typing import Protocol

from agentguard.errors import Unavailable
from agentguard.limits import Limits


@dataclass(frozen=True)
class ModelRequest:
    model: str
    system: str
    user: str
    max_output_tokens: int


class ModelProvider(Protocol):
    """Adapt your approved model vendor here; return structured assistant JSON as a string."""

    async def complete(self, request: ModelRequest) -> str: ...


class ModelGateway:
    """No implicit retries: every call must have a prior shared cost reservation."""

    def __init__(self, limits: Limits, provider: ModelProvider):
        self.limits, self.provider = limits, provider

    async def complete(self, system: str, user: str) -> str:
        if (
            self.limits.model_name not in self.limits.allowed_models
            or len(system) + len(user) > self.limits.max_context_chars
        ):
            raise Unavailable("MODEL_CONTEXT_REJECTED")
        request = ModelRequest(self.limits.model_name, system, user, self.limits.output_tokens_per_call)
        try:
            async with asyncio.timeout(self.limits.model_timeout_seconds):
                result = await self.provider.complete(request)
        except TimeoutError as exc:
            raise Unavailable("MODEL_TIMEOUT") from exc
        except Exception as exc:
            raise Unavailable("MODEL_FAILURE") from exc
        if not isinstance(result, str) or len(result) > self.limits.max_output_chars * 6:
            raise Unavailable("MODEL_TOO_LARGE")
        return result
