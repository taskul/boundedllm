"""Bound outbound reads before buffering; clients never follow redirects or ambient proxies."""

import json

import httpx

from boundedllm.errors import Unavailable
from boundedllm.parsing import unique_object


async def bounded_json(client: httpx.AsyncClient, method: str, url: str, *, max_bytes: int, **kwargs) -> dict:
    try:
        async with client.stream(method, url, **kwargs) as response:
            response.raise_for_status()
            if "application/json" not in response.headers.get("content-type", "").lower():
                raise Unavailable("UPSTREAM_CONTENT_TYPE")
            data = bytearray()
            async for chunk in response.aiter_bytes():
                if len(data) + len(chunk) > max_bytes:
                    raise Unavailable("UPSTREAM_TOO_LARGE")
                data.extend(chunk)
            result = json.loads(data, object_pairs_hook=unique_object)
            if not isinstance(result, dict):
                raise Unavailable("UPSTREAM_SCHEMA")
            return result
    except (httpx.HTTPError, ValueError, RecursionError) as exc:
        raise Unavailable("UPSTREAM_FAILURE") from exc
