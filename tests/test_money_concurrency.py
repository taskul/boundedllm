"""The monetary paths under real contention, on the database that locks.

``_account``, ``_action``, and ``propose_waiver`` serialize on
``with_for_update()``, which is a silent no-op on SQLite. Every test outside this
file therefore exercises them with no locking whatsoever. That is exactly how the
duplicate-execution defect in ``claim_operation`` survived review: correct-looking
code, a green suite, and the wrong backend underneath it.

These assert on the account balance, not on a returned status. A refusal that
still moved money is a passing status check and a loss.

Run with a disposable database::

    TEST_POSTGRES_URL=postgresql+psycopg://postgres:postgres@localhost:5432/guard_test \\
        uv run pytest -m postgres tests/test_money_concurrency.py
"""

import json
import os
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import insert, select, text

from boundedllm.adapters.sql import sql_ports
from boundedllm.adapters.sql.schema import audit_events, metadata
from boundedllm.audit import Audit
from boundedllm.config import Settings
from boundedllm.engine import Guard
from boundedllm.models import ChatRequest, Principal, TurnFlags
from boundedllm.support import SupportPolicy, SupportSQLStore, ToolGateway
from boundedllm.support.models import WaiveFeeArgs
from boundedllm.support.schema import accounts, actions

pytestmark = pytest.mark.postgres

POSTGRES_URL = os.getenv("TEST_POSTGRES_URL")
THREADS = 8
START_BALANCE = 10000

requires_postgres = pytest.mark.skipif(
    not POSTGRES_URL, reason="set TEST_POSTGRES_URL to a disposable PostgreSQL database"
)


class WaiveProvider:
    """Always proposes a waiver, so every turn reaches the monetary path."""

    def __init__(self, cents=4000):
        self.payload = json.dumps(
            {
                "answer": "",
                "tool_call": {
                    "name": "waive_fee",
                    "arguments": {
                        "account_id": "acct_abcdefghij",
                        "amount_cents": cents,
                        "reason": "Customer service adjustment",
                    },
                },
            }
        )

    async def complete(self, request):
        return self.payload


@pytest.fixture
def clean_database():
    """Drop and rebuild the schema so each test starts from a known balance."""
    from sqlalchemy import create_engine

    engine = create_engine(POSTGRES_URL, future=True)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()
    yield


def build(waive_cents=4000, fee_cents=START_BALANCE):
    settings = Settings(
        database_url=POSTGRES_URL,
        audit_key=secrets.token_hex(32),
        user_requests_per_minute=1000,
        tenant_requests_per_minute=10000,
    )
    audit = Audit.from_settings(settings)
    store = SupportSQLStore(settings, audit)
    store.initialize()
    metadata.create_all(store.engine)
    policy = SupportPolicy()
    ports = sql_ports(store)
    guard = Guard(
        provider=WaiveProvider(waive_cents),
        signer=audit,
        limits=settings.limits(),
        tool_executor=ToolGateway(ports["documents"], policy),
        **ports,
    )
    caller = Principal(
        subject="payer",
        tenant_id="tenant-a",
        roles=frozenset({"support"}),
        scopes=frozenset({"chat:use", "accounts:read", "fees:waive", "actions:approve"}),
        expires_at=2**31,
    )
    with store.transaction("tenant-a") as conn:
        conn.execute(
            insert(accounts).values(
                tenant_id="tenant-a",
                account_id="acct_abcdefghij",
                owner_subject="payer",
                status="active",
                currency="USD",
                fee_cents=fee_cents,
                version=1,
            )
        )
    return store, guard, policy, caller


def balance(store, account_id="acct_abcdefghij", tenant="tenant-a"):
    with store.transaction(tenant) as conn:
        return conn.execute(
            select(accounts.c.fee_cents).where(
                accounts.c.tenant_id == tenant, accounts.c.account_id == account_id
            )
        ).scalar_one()


def executed_events(store, tenant="tenant-a"):
    """Count committed execution records. One consent must yield one receipt."""
    with store.transaction(tenant) as conn:
        payloads = (
            conn.execute(select(audit_events.c.payload).where(audit_events.c.tenant_id == tenant))
            .scalars()
            .all()
        )
    return sum(1 for payload in payloads if json.loads(payload)["event_type"] == "tool_executed")


def race(work, threads=THREADS):
    """Run ``work`` on N threads released together, collecting every outcome."""
    barrier = threading.Barrier(threads)

    def run(index):
        barrier.wait()
        try:
            return ("ok", work(index))
        except Exception as exc:  # noqa: BLE001 - the outcome is what we assert on
            return (type(exc).__name__, getattr(exc, "code", str(exc)))

    with ThreadPoolExecutor(max_workers=threads) as pool:
        return list(pool.map(run, range(threads)))


async def propose(guard, store, caller, conversation):
    response = await guard.chat(
        caller,
        ChatRequest(
            message="Please waive my fee.",
            conversation_id=conversation,
            operation_id=secrets.token_hex(16),
        ),
    )
    assert response.status == "REQUIRE_APPROVAL", response.status
    return response.pending_action_id


@requires_postgres
@pytest.mark.asyncio
async def test_concurrent_approvals_of_one_action_pay_out_exactly_once(clean_database):
    """Eight simultaneous approvals of one pending waiver. One decrement."""
    store, guard, policy, caller = build()
    conversation = store.create_conversation(guard.context(caller))
    action_id = await propose(guard, store, caller, conversation)
    assert balance(store) == START_BALANCE

    ctx = guard.context(caller)
    results = race(lambda _: store.approve(ctx, action_id, policy))

    receipts = [value for kind, value in results if kind == "ok"]
    assert receipts, f"no approval completed: {results}"
    # Consent is consumed once. Every later caller is handed the same receipt
    # rather than a second payout.
    assert all(r == receipts[0] for r in receipts), receipts
    assert balance(store) == START_BALANCE - 4000, "the waiver was applied more than once"
    # The balance alone is a weak assertion here: _execute writes an absolute
    # value computed from the row it read, so two executions racing off the same
    # read would both write the same number and the money would look correct.
    # The ledger is what distinguishes one execution from two.
    assert executed_events(store) == 1, "the ledger records more than one execution"
    store.close()


@requires_postgres
@pytest.mark.asyncio
async def test_two_pending_waivers_cannot_both_drain_one_account(clean_database):
    """Two independent protections keep this balance from going negative.

    Each waiver is valid on its own against the starting balance, so policy
    admits both at proposal time. Approving both would overdraw the account.

    Mutation testing establishes that *either* protection alone is sufficient,
    which is worth recording because it is not obvious from reading the code:

        version pin disabled        -> safe (the policy re-check refuses)
        policy re-check disabled    -> safe (the version pin refuses)
        both disabled               -> balance reaches -2000

    So this test fails only when both layers are gone. Do not "simplify" either
    one on the grounds that the other covers it; that is how a single change
    later removes the last remaining guard.
    """
    store, guard, policy, caller = build(waive_cents=6000)
    conversation = store.create_conversation(guard.context(caller))
    first = await propose(guard, store, caller, conversation)
    second = await propose(guard, store, caller, conversation)
    assert first != second, "two operations collapsed into one action"

    ctx = guard.context(caller)
    pending = [first, second]
    results = race(lambda i: store.approve(ctx, pending[i % 2], policy))

    executed = [value for kind, value in results if kind == "ok"]
    refused = [kind for kind, _ in results if kind != "ok"]
    final = balance(store)

    assert final >= 0, f"the account was overdrawn to {final}"
    assert final == START_BALANCE - 6000, f"expected exactly one 6000 waiver, balance is {final}"
    assert refused, f"the second waiver was never refused: {results}"
    assert all(r == executed[0] for r in executed), executed
    store.close()


@requires_postgres
@pytest.mark.asyncio
async def test_concurrent_proposals_for_one_operation_create_one_action(clean_database):
    """propose_waiver races on the unique (tenant, subject, operation_id) index."""
    store, guard, policy, caller = build()
    conversation = store.create_conversation(guard.context(caller))
    operation = secrets.token_hex(16)
    request = ChatRequest(
        message="Please waive my fee.", conversation_id=conversation, operation_id=operation
    )
    args = WaiveFeeArgs(account_id="acct_abcdefghij", amount_cents=4000, reason="Customer service adjustment")
    flags = TurnFlags(risk_action="continue", untrusted_content_present=True)
    ctx = guard.context(caller)

    results = race(lambda _: store.propose_waiver(ctx, request, args, flags, policy))

    with store.transaction("tenant-a") as conn:
        rows = conn.execute(
            select(actions.c.id).where(actions.c.tenant_id == "tenant-a", actions.c.operation_id == operation)
        ).all()
    assert len(rows) == 1, f"{len(rows)} action rows for one operation id"

    succeeded = [value for kind, value in results if kind == "ok" and isinstance(value, dict)]
    assert succeeded, results
    identifiers = {r.get("pending_action_id") for r in succeeded}
    assert len(identifiers) == 1, f"racers were given different actions: {identifiers}"
    assert balance(store) == START_BALANCE, "a proposal moved money without approval"
    store.close()


@requires_postgres
@pytest.mark.asyncio
async def test_a_reader_never_observes_a_partially_applied_waiver(clean_database):
    """_account takes a row lock, so a concurrent read sees before or after."""
    store, guard, policy, caller = build()
    conversation = store.create_conversation(guard.context(caller))
    action_id = await propose(guard, store, caller, conversation)

    ctx = guard.context(caller)
    observed = []

    def work(index):
        if index % 2 == 0:
            return store.approve(ctx, action_id, policy)
        account = store.get_account(caller, "acct_abcdefghij")
        observed.append(account.fee_cents)
        return account.fee_cents

    race(work)
    assert set(observed) <= {START_BALANCE, START_BALANCE - 4000}, (
        f"a torn balance was observed: {sorted(set(observed))}"
    )
    assert balance(store) == START_BALANCE - 4000
    store.close()


@requires_postgres
@pytest.mark.asyncio
async def test_an_expired_session_cannot_win_an_approval_race(clean_database):
    """Liveness is re-checked inside _execute, after the lock is held.

    A principal that expires between proposal and execution must not have its
    waiver applied just because it reached the front of the queue.
    """
    store, guard, policy, caller = build()
    conversation = store.create_conversation(guard.context(caller))
    action_id = await propose(guard, store, caller, conversation)

    expired = Principal(
        subject="payer",
        tenant_id="tenant-a",
        roles=frozenset({"support"}),
        scopes=frozenset({"chat:use", "accounts:read", "fees:waive", "actions:approve"}),
        expires_at=1.0,
    )
    # Built directly, not through guard.context(), which would reject the expired
    # principal up front. The point is whether the store still refuses it deeper in.
    from boundedllm.models import RequestContext

    ctx = RequestContext(request_id=secrets.token_hex(16), principal=expired)
    results = race(lambda _: store.approve(ctx, action_id, policy))

    assert not [value for kind, value in results if kind == "ok"], results
    assert balance(store) == START_BALANCE, "an expired session moved money"
    store.close()
