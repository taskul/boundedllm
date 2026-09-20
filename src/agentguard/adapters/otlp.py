"""At-least-once delivery of signed ledger records to an OTLP/HTTP collector.

The request path writes the ledger and its outbox in one database transaction.
This worker drains that outbox and marks records exported only after the
collector acknowledges them, so a delivery failure never loses evidence and a
retry never loses a record. Collectors and SIEMs deduplicate on ``event_id``.

Kept out of the core because it needs an HTTP client and a concrete store.
"""

import json
import time
from typing import Protocol

import httpx

from agentguard.adapters.sql.store import SQLStore
from agentguard.config import require_https


class SecurityEventSink(Protocol):
    """Small adapter surface for an OTel Collector or enterprise SIEM gateway."""

    def export(self, events: list[dict]) -> None: ...


class OpenTelemetryHTTPSink:
    """Send metadata-only events using OTLP/HTTP JSON to ``/v1/logs``."""

    def __init__(self, endpoint: str, authorization: str | None = None):
        self.endpoint = require_https(endpoint)
        self.authorization = authorization

    def export(self, events: list[dict]) -> None:
        if not events:
            return
        records = []
        for envelope in events:
            payload = json.loads(envelope["payload"])
            attributes = [
                {"key": "security.event_id", "value": {"stringValue": envelope["event_id"]}},
                {"key": "security.tenant_id", "value": {"stringValue": envelope["tenant_id"]}},
                {"key": "security.sequence", "value": {"intValue": str(envelope["sequence"])}},
                {"key": "security.record_hash", "value": {"stringValue": envelope["record_hash"]}},
                {"key": "security.key_id", "value": {"stringValue": envelope["key_id"]}},
            ]
            records.append(
                {
                    "timeUnixNano": str(int(payload["timestamp"] * 1_000_000_000)),
                    "observedTimeUnixNano": str(time.time_ns()),
                    "severityText": str(payload.get("severity", "INFO")).upper(),
                    "body": {"stringValue": envelope["payload"]},
                    "attributes": attributes,
                }
            )
        body = {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            {
                                "key": "service.name",
                                "value": {"stringValue": "agentguard"},
                            }
                        ]
                    },
                    "scopeLogs": [
                        {
                            "scope": {"name": "agentguard.audit"},
                            "logRecords": records,
                        }
                    ],
                }
            ]
        }
        headers = {"Content-Type": "application/json"}
        if self.authorization:
            headers["Authorization"] = self.authorization
        with httpx.Client(
            timeout=httpx.Timeout(15, connect=5),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            with client.stream("POST", self.endpoint, headers=headers, json=body) as response:
                response.raise_for_status()
                received = 0
                for chunk in response.iter_bytes():
                    received += len(chunk)
                    if received > 65536:
                        raise ValueError("OTLP acknowledgement exceeded 64 KiB")


def export_pending(store: SQLStore, tenant_id: str, sink: SecurityEventSink, limit: int = 100) -> int:
    """Deliver one bounded batch and acknowledge its exact hashes after success."""
    events = store.pending_audit_exports(tenant_id, limit)
    if not events:
        return 0
    try:
        sink.export(events)
    except Exception:
        store.mark_audit_export_failed(tenant_id, events)
        raise
    store.mark_audit_exported(tenant_id, events)
    return len(events)
