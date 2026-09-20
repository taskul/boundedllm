"""A ``ModelProvider`` for Claude, using the official Anthropic SDK.

The engine needs one thing from a provider: assistant JSON matching
``{"answer": str, "tool_call": null | {"name": str, "arguments": object}}``
returned as a string. Structured outputs make Claude's decoder enforce that
shape, and ``boundedllm.parsing`` validates it again after the network boundary —
the constraint is a convenience, never the reason the contract holds.

Install with::

    pip install "boundedllm[anthropic]"

What this adapter deliberately does not do:

* **No retries on a non-transport error.** The SDK retries connection failures and
  429/5xx. A refusal or a malformed response is not retried, because a second
  attempt at the same prompt costs money and usually returns the same thing.
* **No tool definitions sent to the model.** Tools are proposals here, authorized
  by the host afterwards. Giving Claude a tool schema it can call directly would
  move the decision to the wrong side of the boundary.
* **No conversation history.** The engine composes the full prompt for each turn
  from data it has already authorized. History is the host's concern, and
  replaying it here would bypass the per-turn retrieval ACL.
"""

from boundedllm.errors import Unavailable
from boundedllm.model_gateway import ModelRequest

# The decoder is constrained to the same contract the parser enforces. Both are
# kept here so a change to one is visible next to the other.
ASSISTANT_SCHEMA = {
    "type": "object",
    "properties": {
        "answer": {"type": "string"},
        "tool_call": {
            "anyOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "arguments": {"type": "object"},
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


class AnthropicProvider:
    """Adapt Claude to the provider contract.

    ``client`` is an ``anthropic.AsyncAnthropic``. Construct it once in your
    application and pass it in, so the credential lives in one place and the
    connection pool is shared.

    ``effort`` maps to ``output_config.effort``. Guard turns are short and
    structured, so the default is deliberately low: raising it costs tokens and
    latency without improving adherence to a constrained schema.
    """

    def __init__(
        self,
        client,
        *,
        model: str = "claude-opus-5",
        effort: str = "low",
        strict_schema: dict | None = None,
    ):
        self.client = client
        self.model = model
        self.effort = effort
        self.schema = strict_schema or ASSISTANT_SCHEMA

    async def complete(self, request: ModelRequest) -> str:
        try:
            response = await self.client.messages.create(
                model=request.model or self.model,
                max_tokens=request.max_output_tokens,
                system=request.system,
                messages=[{"role": "user", "content": request.user}],
                output_config={
                    "format": {"type": "json_schema", "schema": self.schema},
                    "effort": self.effort,
                },
            )
        except Exception as exc:
            # The gateway wraps this too; raising the typed error here keeps the
            # reason legible when the provider is used outside the engine.
            raise Unavailable("MODEL_FAILURE") from exc

        # A safety decline is a stop reason, not an exception, and arrives with
        # HTTP 200. Reading .content without checking would treat it as an answer.
        if getattr(response, "stop_reason", None) == "refusal":
            raise Unavailable("MODEL_REFUSED")
        if response.stop_reason == "max_tokens":
            # Truncated JSON would fail the parser anyway; this names the cause.
            raise Unavailable("MODEL_TRUNCATED")

        blocks = [block for block in response.content if getattr(block, "type", None) == "text"]
        if len(blocks) != 1 or not isinstance(blocks[0].text, str):
            raise Unavailable("MODEL_RESPONSE_SCHEMA")
        return blocks[0].text


def build_provider(api_key: str, *, model: str = "claude-opus-5", effort: str = "low"):
    """Convenience constructor for a host that has no Anthropic client yet.

    Prefer building and owning the client yourself in a long-lived application so
    the connection pool is shared and the credential has a single home.
    """
    try:
        from anthropic import AsyncAnthropic
    except ImportError as exc:  # pragma: no cover - exercised by the extras install
        raise RuntimeError("install boundedllm[anthropic]") from exc

    return AnthropicProvider(AsyncAnthropic(api_key=api_key), model=model, effort=effort)
