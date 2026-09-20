"""Fail-closed structured output parsing: no repair, coercion, or duplicate JSON keys."""

import json

from pydantic import ValidationError

from agentguard.errors import OutputBlocked
from agentguard.models import AssistantOutput


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def parse_assistant_output(raw: str) -> AssistantOutput:
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
        return AssistantOutput.model_validate(value)
    except (ValueError, ValidationError, RecursionError) as exc:
        # Malformed action JSON must not be released as a fabricated success message.
        raise OutputBlocked("MODEL_SCHEMA_INVALID") from exc
