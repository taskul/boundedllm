"""``Ledger`` ports that write security events where your SOC already looks.

Three shapes, in increasing order of what they guarantee:

* ``StructuredLogLedger`` — JSON lines to the standard library logger. Correct for
  a deployment whose log pipeline is already the system of record. Loses events if
  the process dies with buffers unflushed.
* ``TeeLedger`` — writes to several ledgers, with one designated authoritative.
  The usual configuration: a durable store that must succeed, plus a SIEM feed
  that must not be able to fail a request.
* ``BufferedHTTPLedger`` — batches to an HTTP collector. Fastest and least
  durable; read its warning before choosing it.

**The property that matters.** A side effect must never be able to exist without
the record that authorized it. The bundled SQL adapter achieves that by writing
the event in the same transaction as the mutation it describes, then draining an
outbox to the SIEM. A ledger that posts over the network cannot make that
promise: the request can commit and the POST can fail. If your evidence has to be
complete, keep a transactional ledger authoritative and treat the network one as
a copy — which is what ``TeeLedger`` is for.
"""

import asyncio
import json
import logging
import time

from boundedllm.errors import Unavailable
from boundedllm.models import RequestContext

LOGGER = logging.getLogger("boundedllm.security")

# Mirrors boundedllm.audit.ALLOWED_FIELDS. An event carries metadata, fingerprints,
# and reason codes; it never carries prompt text, document bodies, or credentials.
# A ledger that widens this is the fastest way to turn a security log into a
# secondary copy of the data the system exists to protect.
SEVERITY_TO_LEVEL = {
    "critical": logging.CRITICAL,
    "high": logging.ERROR,
    "medium": logging.WARNING,
    "low": logging.INFO,
    "info": logging.INFO,
}


def _envelope(ctx: RequestContext, event: str, fields: dict, signer=None) -> dict:
    """Build the record. The subject is pseudonymized when a signer is supplied."""
    subject = ctx.principal.subject
    return {
        "timestamp": time.time(),
        "event_type": event,
        "request_id": ctx.request_id,
        "tenant_id": ctx.principal.tenant_id,
        "subject_fingerprint": signer.fingerprint(subject) if signer else None,
        **fields,
    }


class StructuredLogLedger:
    """One JSON object per event on the standard logger.

    Use when your log shipper is already the audited path. Configure the handler
    yourself; this deliberately installs nothing, so it cannot fight with the
    host's logging configuration.
    """

    def __init__(self, signer=None, logger: logging.Logger | None = None):
        self.signer = signer
        self.logger = logger or LOGGER

    async def event(self, ctx: RequestContext, event: str, **fields) -> None:
        record = _envelope(ctx, event, fields, self.signer)
        level = SEVERITY_TO_LEVEL.get(str(fields.get("severity", "info")), logging.INFO)
        # Serialization happens here so a field that cannot be encoded surfaces as
        # a loud failure rather than a silently dropped security event.
        self.logger.log(level, json.dumps(record, sort_keys=True, default=str))


class TeeLedger:
    """Fan out to several ledgers; only the authoritative one can fail the request.

    ``primary`` is the system of record and its failure propagates. ``mirrors``
    are best-effort copies whose failure is logged and swallowed, because a SIEM
    being unreachable should not take a customer-facing service down with it.

    This asymmetry is the whole point. Making every sink mandatory turns each one
    into a new way to fail closed; making none mandatory means a committed action
    can end up with no evidence at all.
    """

    def __init__(self, primary, *mirrors, logger: logging.Logger | None = None):
        self.primary = primary
        self.mirrors = mirrors
        self.logger = logger or LOGGER

    async def event(self, ctx: RequestContext, event: str, **fields) -> None:
        await self.primary.event(ctx, event, **fields)
        for mirror in self.mirrors:
            try:
                await mirror.event(ctx, event, **fields)
            except Exception:
                # Losing a mirrored copy is an operational problem to alert on,
                # not a reason to fail a request the primary already recorded.
                self.logger.warning(
                    "security event mirror failed", extra={"boundedllm_event": event}, exc_info=True
                )


class BufferedHTTPLedger:
    """Batch events to an HTTPS collector.

    **Read this before using it as your only ledger.** Events are held in memory
    until the batch fills or ``flush_interval`` elapses. A crash loses whatever is
    buffered, and the buffer is bounded so a slow collector drops events rather
    than exhausting memory. That is the correct trade for a telemetry feed and the
    wrong one for evidence. Pair it with a durable primary through ``TeeLedger``.

    ``client`` is an ``httpx.AsyncClient`` you construct with
    ``follow_redirects=False`` and ``trust_env=False``.
    """

    def __init__(
        self,
        client,
        endpoint: str,
        *,
        signer=None,
        headers: dict | None = None,
        batch_size: int = 100,
        max_buffer: int = 10000,
        flush_interval: float = 5.0,
    ):
        if not endpoint.startswith("https://"):
            raise ValueError("collector endpoint must be HTTPS")
        self.client = client
        self.endpoint = endpoint
        self.signer = signer
        self.headers = headers or {}
        self.batch_size = batch_size
        self.max_buffer = max_buffer
        self.flush_interval = flush_interval
        self._buffer: list[dict] = []
        self._lock = asyncio.Lock()
        self._last_flush = time.monotonic()
        self.dropped = 0

    async def event(self, ctx: RequestContext, event: str, **fields) -> None:
        record = _envelope(ctx, event, fields, self.signer)
        async with self._lock:
            if len(self._buffer) >= self.max_buffer:
                # Count what was lost so the gap is visible instead of silent.
                self.dropped += 1
                LOGGER.error("security event buffer full; dropped %d so far", self.dropped)
                return
            self._buffer.append(record)
            due = (
                len(self._buffer) >= self.batch_size
                or time.monotonic() - self._last_flush >= self.flush_interval
            )
            batch = self._buffer[:] if due else []
            if due:
                self._buffer.clear()
                self._last_flush = time.monotonic()
        if batch:
            await self._send(batch)

    async def flush(self) -> None:
        """Drain the buffer. Call this during shutdown or the tail is lost."""
        async with self._lock:
            batch, self._buffer = self._buffer[:], []
            self._last_flush = time.monotonic()
        if batch:
            await self._send(batch)

    async def _send(self, batch: list[dict]) -> None:
        try:
            response = await self.client.post(self.endpoint, json={"events": batch}, headers=self.headers)
            response.raise_for_status()
        except Exception as exc:
            LOGGER.error("security event delivery failed for %d events", len(batch), exc_info=True)
            raise Unavailable("LEDGER_DELIVERY_FAILED") from exc
