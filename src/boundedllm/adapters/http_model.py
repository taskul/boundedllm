"""A generic HTTPS model transport for deployments without a vendor SDK.

Kept out of the core so importing ``boundedllm`` costs no HTTP client and no
deployment configuration. A host that already uses a vendor SDK should implement
``ModelProvider`` against it directly rather than route through this contract.
"""

import httpx

from boundedllm.config import Settings
from boundedllm.errors import Unavailable
from boundedllm.model_gateway import ModelRequest
from boundedllm.network import bounded_json


class HTTPModelProvider:
    """Generic enterprise endpoint contract, not a vendor-specific API implementation."""

    def __init__(self, settings: Settings, client: httpx.AsyncClient):
        if not settings.model_url:
            raise ValueError("model_url required")
        self.settings = settings
        self.client = client

    async def complete(self, request: ModelRequest) -> str:
        headers = {}
        if self.settings.model_api_key:
            headers["Authorization"] = "Bearer " + self.settings.model_api_key.get_secret_value()
        data = await bounded_json(
            self.client,
            "POST",
            self.settings.model_url,
            max_bytes=131072,
            headers=headers,
            json={
                "model": request.model,
                "system": request.system,
                "user": request.user,
                "max_output_tokens": request.max_output_tokens,
                "temperature": 0,
            },
        )
        if set(data) != {"text"} or not isinstance(data["text"], str):
            raise Unavailable("MODEL_RESPONSE_SCHEMA")
        return data["text"]
