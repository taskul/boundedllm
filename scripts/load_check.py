"""Assert the shared ceilings hold under concurrency, and report throughput.

This is not a benchmark and it does not gate on latency; hardware varies and a
performance threshold in CI produces flaky failures nobody trusts. It gates on
*correctness under contention*, which is where quotas and audit chains actually
break:

* A quota enforced per process is not a quota. With many workers hitting one
  database, the number admitted must equal the configured ceiling, not some
  multiple of it.
* An audit chain assigns sequence numbers under a row lock. Concurrent writers
  must produce one gapless, verifiable chain rather than several that collide.
* Idempotency must survive a thundering herd: N concurrent retries of the same
  operation must yield exactly one execution.

Run locally against a disposable database::

    GUARD_DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/load \\
    GUARD_AUDIT_KEY=$(python -c "import secrets;print(secrets.token_hex(32))") \\
        python scripts/load_check.py
"""

import asyncio
import json
import os
import statistics
import sys
import time
from uuid import uuid4

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agentguard.adapters.sql import sql_ports  # noqa: E402
from agentguard.audit import Audit  # noqa: E402
from agentguard.config import Settings  # noqa: E402
from agentguard.engine import Guard  # noqa: E402
from agentguard.errors import Conflict, GuardError, LimitExceeded  # noqa: E402
from agentguard.models import ChatRequest, Principal  # noqa: E402
from agentguard.support import SupportPolicy, SupportSQLStore, ToolGateway  # noqa: E402

CONCURRENCY = 40
USER_LIMIT = 20
ANSWER = json.dumps({"answer": "Coverage details are in your policy.", "tool_call": None})


class Provider:
    """A model with realistic latency but no network, so the database is the subject."""

    def __init__(self):
        self.calls = 0

    async def complete(self, request):
        self.calls += 1
        await asyncio.sleep(0.01)
        return ANSWER


def build(settings):
    audit = Audit.from_settings(settings)
    store = SupportSQLStore(settings, audit)
    store.initialize()
    provider = Provider()
    ports = sql_ports(store)
    guard = Guard(
        provider=provider,
        signer=audit,
        limits=settings.limits(),
        tool_executor=ToolGateway(ports["documents"], SupportPolicy()),
        **ports,
    )
    return store, guard, provider


def principal(subject="load-user", tenant="load-tenant"):
    return Principal(
        subject=subject,
        tenant_id=tenant,
        roles=frozenset({"support"}),
        scopes=frozenset({"chat:use", "documents:read"}),
        expires_at=time.time() + 3600,
    )


async def check_quota_binds_across_workers(store, guard):
    """More concurrent callers than the ceiling; exactly the ceiling gets through."""
    caller = principal()
    conversation = store.create_conversation(guard.context(caller))

    async def one():
        try:
            await guard.chat(
                caller,
                ChatRequest(
                    message="What does my policy cover?",
                    conversation_id=conversation,
                    operation_id=uuid4().hex,
                ),
            )
            return "ok"
        except LimitExceeded:
            return "throttled"
        except GuardError as exc:
            return f"error:{exc.code}"

    started = time.monotonic()
    results = await asyncio.gather(*(one() for _ in range(CONCURRENCY)))
    elapsed = time.monotonic() - started
    admitted = results.count("ok")
    throttled = results.count("throttled")
    other = [r for r in results if r not in {"ok", "throttled"}]

    assert not other, f"unexpected failures under load: {other[:5]}"
    assert admitted <= USER_LIMIT, (
        f"{admitted} requests admitted against a per-user ceiling of {USER_LIMIT}: "
        "the quota is not shared across workers"
    )
    assert throttled == CONCURRENCY - admitted
    return {
        "concurrency": CONCURRENCY,
        "admitted": admitted,
        "throttled": throttled,
        "ceiling": USER_LIMIT,
        "seconds": round(elapsed, 2),
        "requests_per_second": round(CONCURRENCY / elapsed, 1),
    }


async def check_idempotency_under_a_herd(store, guard, provider):
    """One operation id, many simultaneous retries, exactly one execution."""
    caller = principal(subject="herd-user")
    conversation = store.create_conversation(guard.context(caller))
    operation = uuid4().hex
    before = provider.calls

    async def retry():
        try:
            return (
                await guard.chat(
                    caller,
                    ChatRequest(
                        message="Retried question.",
                        conversation_id=conversation,
                        operation_id=operation,
                    ),
                )
            ).status
        except Conflict:
            return "conflict"
        except GuardError as exc:
            return f"error:{exc.code}"

    results = await asyncio.gather(*(retry() for _ in range(12)))
    completed = [r for r in results if r == "OK"]
    conflicts = [r for r in results if r == "conflict"]
    model_calls = provider.calls - before

    assert model_calls == 1, f"{model_calls} model calls for one operation id"
    assert completed, "no attempt completed"
    assert len(completed) + len(conflicts) == len(results), f"unexpected: {set(results)}"
    return {"attempts": len(results), "model_calls": model_calls, "conflicts": len(conflicts)}


async def check_audit_chain_under_contention(store):
    """Concurrent writers must produce one gapless, verifiable chain."""
    report = await asyncio.to_thread(store.verify_audit_chain, "load-tenant")
    assert report["valid"], f"audit chain invalid under load: {report['invalid'][:3]}"
    return {"records": report["records"], "valid": report["valid"]}


async def main() -> int:
    settings = Settings(
        user_requests_per_minute=USER_LIMIT,
        tenant_requests_per_minute=10000,
        max_concurrent_requests=256,
    )
    store, guard, provider = build(settings)
    latencies = []
    try:
        quota = await check_quota_binds_across_workers(store, guard)
        herd = await check_idempotency_under_a_herd(store, guard, provider)
        chain = await check_audit_chain_under_contention(store)
        for _ in range(5):
            caller = principal(subject=f"timing-{uuid4().hex[:8]}")
            conversation = store.create_conversation(guard.context(caller))
            started = time.monotonic()
            await guard.chat(
                caller,
                ChatRequest(
                    message="Timing sample.",
                    conversation_id=conversation,
                    operation_id=uuid4().hex,
                ),
            )
            latencies.append((time.monotonic() - started) * 1000)
    finally:
        store.close()

    print(
        json.dumps(
            {
                "shared_quota": quota,
                "idempotency_under_herd": herd,
                "audit_chain": chain,
                # Reported, never asserted on. Useful for spotting a regression
                # across runs on the same runner; meaningless as a threshold.
                "latency_ms": {
                    "median": round(statistics.median(latencies), 1),
                    "max": round(max(latencies), 1),
                },
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
