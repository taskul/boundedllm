"""The Claude adapter sends what we expect and never puts the key in a body.

RoadShield now uses the shipped ``agentguard.contrib.anthropic`` adapter rather
than a hand-rolled client, so this exercises the real adapter through a mocked
transport: the SDK builds the request, and the assertions are about what actually
goes on the wire.
"""

import asyncio
import json

# The SDK is built on httpx2; an httpx client is rejected at construction.
import httpx2 as httpx
from agentguard.errors import Unavailable
from agentguard.model_gateway import ModelRequest
from anthropic import AsyncAnthropic
from pydantic import SecretStr

from roadshield.claude import ROADSHIELD_SCHEMA, ClaudeProvider

SECRET = "test-secret-never-logged"


def run(handler, model="claude-opus-5"):
    async def exercise():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport, follow_redirects=False, trust_env=False) as http:
            client = AsyncAnthropic(api_key=SECRET, http_client=http)
            provider = ClaudeProvider(SecretStr(SECRET), client, model)
            return await provider.complete(ModelRequest(model, "SYSTEM", "USER", 300))

    return asyncio.run(exercise())


def ok_response(text='{"answer":"Covered","tool_call":null}', stop_reason="end_turn"):
    return {
        "id": "msg_01",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5",
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 5},
        "content": [{"type": "text", "text": text}],
    }


def test_the_request_carries_the_system_prompt_and_the_closed_tool_schema():
    observed = {}

    def handler(request: httpx.Request) -> httpx.Response:
        observed["url"] = str(request.url)
        observed["key"] = request.headers.get("x-api-key")
        observed["version"] = request.headers.get("anthropic-version")
        observed["body"] = json.loads(request.content)
        return httpx.Response(200, json=ok_response())

    assert run(handler) == '{"answer":"Covered","tool_call":null}'
    body = observed["body"]

    assert observed["url"] == "https://api.anthropic.com/v1/messages"
    assert observed["key"] == SECRET
    assert observed["version"]  # the SDK pins this; we only require it to be sent
    assert body["system"] == "SYSTEM"
    assert body["messages"] == [{"role": "user", "content": "USER"}]

    # The decoder is constrained to RoadShield's two tools by name, so an invented
    # tool cannot even be generated. The gateway would deny it regardless.
    schema = body["output_config"]["format"]["schema"]
    assert schema == ROADSHIELD_SCHEMA
    names = {
        option["properties"]["name"]["const"]
        for option in schema["properties"]["tool_call"]["anyOf"]
        if option.get("type") != "null"
    }
    assert names == {"get_account_summary", "waive_fee"}

    # Tools are proposals the host authorizes; Claude is never given a callable one.
    assert "tools" not in body
    # The credential belongs in a header and must never appear in the payload.
    assert SECRET not in json.dumps(body)


def test_a_refusal_is_not_returned_as_an_answer():
    """A safety decline arrives as HTTP 200 with content present."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=ok_response(text="{}", stop_reason="refusal"))

    try:
        run(handler)
        raise AssertionError("a refusal was returned as an answer")
    except Unavailable as exc:
        assert exc.code == "MODEL_REFUSED"


def test_a_truncated_response_is_rejected_rather_than_parsed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=ok_response(text='{"answer":"tru', stop_reason="max_tokens"))

    try:
        run(handler)
        raise AssertionError("truncated output was accepted")
    except Unavailable as exc:
        assert exc.code == "MODEL_TRUNCATED"


def test_an_api_error_surfaces_as_unavailable():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"type": "error", "error": {"type": "api_error"}})

    try:
        run(handler)
        raise AssertionError("an upstream failure was not reported")
    except Unavailable as exc:
        assert exc.code == "MODEL_FAILURE"
