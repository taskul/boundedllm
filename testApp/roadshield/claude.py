"""RoadShield's Claude wiring, built on the shipped contrib adapter.

This file used to hand-roll an HTTP client for the Messages API. It now uses
``boundedllm.contrib.anthropic``, which is the point of having contrib at all: the
lab exercises the same adapter a customer would install, against the real API, so
a defect shows up here before it ships.

What stays local is the schema. The contrib adapter's default permits any tool
name, because it cannot know a host's registry. RoadShield knows its registry is
exactly two tools, so it pins them with ``const`` and lets Claude's decoder reject
an invented name before the request is even parsed. The guard re-validates
everything afterwards regardless; this only makes the common case cheaper.
"""

from boundedllm.contrib.anthropic import AnthropicProvider
from pydantic import SecretStr

# Tighter than the contrib default: the tool names are closed, and each tool's
# arguments are closed too. A proposal outside this shape never reaches the
# gateway, and the gateway would deny it anyway.
ROADSHIELD_SCHEMA = {
    "type": "object",
    "properties": {
        "answer": {"type": "string"},
        "tool_call": {
            "anyOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "properties": {
                        "name": {"const": "get_account_summary"},
                        "arguments": {
                            "type": "object",
                            "properties": {"account_id": {"type": "string"}},
                            "required": ["account_id"],
                            "additionalProperties": False,
                        },
                    },
                    "required": ["name", "arguments"],
                    "additionalProperties": False,
                },
                {
                    "type": "object",
                    "properties": {
                        "name": {"const": "waive_fee"},
                        "arguments": {
                            "type": "object",
                            "properties": {
                                "account_id": {"type": "string"},
                                "amount_cents": {"type": "integer"},
                                "reason": {"type": "string"},
                            },
                            "required": ["account_id", "amount_cents", "reason"],
                            "additionalProperties": False,
                        },
                    },
                    "required": ["name", "arguments"],
                    "additionalProperties": False,
                },
            ]
        },
    },
    "required": ["answer", "tool_call"],
    "additionalProperties": False,
}


class ClaudeProvider(AnthropicProvider):
    """The contrib adapter with RoadShield's closed tool schema.

    Counters are kept for the lab's status endpoint and tests; they hold no
    request content, only how many calls were made and the last request object.
    """

    def __init__(self, api_key: SecretStr, client, model: str = "claude-opus-5"):
        super().__init__(client, model=model, strict_schema=ROADSHIELD_SCHEMA)
        self.api_key = api_key
        self.call_count = 0
        self.last_request = None

    async def complete(self, request):
        self.call_count += 1
        self.last_request = request
        return await super().complete(request)


def build_client(api_key: SecretStr, tls_context):
    """An Anthropic client that uses the OS trust store and no ambient proxy.

    Managed enterprise roots work without disabling verification, and
    ``trust_env=False`` keeps a proxy variable in the environment from silently
    redirecting model traffic.
    """
    # The Anthropic SDK 1.x is built on httpx2, and passing an httpx client is
    # rejected at construction. Import it under the same name so the shape below
    # reads normally and the distinction stays visible in one place.
    import httpx2 as httpx
    from anthropic import AsyncAnthropic

    return AsyncAnthropic(
        api_key=api_key.get_secret_value(),
        http_client=httpx.AsyncClient(
            timeout=httpx.Timeout(20, connect=5),
            follow_redirects=False,
            trust_env=False,
            verify=tls_context,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=5),
        ),
    )
