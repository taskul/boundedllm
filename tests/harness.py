"""Composition helpers shared by the regression and adversarial suites.

Kept separate so an adversarial test can state the attack and nothing else. A
test that spends twenty lines on setup tends to get written to match whatever the
code already does, which is the failure mode this suite exists to avoid.
"""

import secrets
import time
from uuid import uuid4

from sqlalchemy import insert

from agentguard.adapters.sql import sql_ports
from agentguard.audit import Audit
from agentguard.config import Settings
from agentguard.engine import Guard
from agentguard.model_gateway import ModelRequest
from agentguard.models import Principal
from agentguard.support import SupportPolicy, SupportSQLStore, ToolGateway
from agentguard.support.schema import accounts

ALL_SCOPES = frozenset(
    {
        "chat:use",
        "documents:read",
        "documents:write",
        "documents:publish",
        "accounts:read",
        "fees:waive",
        "actions:approve",
    }
)


class ScriptedProvider:
    """Returns exactly what a test tells it to, including hostile output.

    The model is the untrusted component, so a test must be able to make it say
    anything. Replies may be a single string or a list consumed in order.
    """

    def __init__(self, replies):
        self.replies = [replies] if isinstance(replies, str) else list(replies)
        self.calls = 0
        self.last_request: ModelRequest | None = None
        self.seen: list[str] = []

    async def complete(self, request: ModelRequest) -> str:
        self.calls += 1
        self.last_request = request
        self.seen.append(request.user)
        index = min(self.calls - 1, len(self.replies) - 1)
        return self.replies[index]


def principal(
    subject="user-a",
    tenant="tenant-a",
    roles=("support",),
    scopes=ALL_SCOPES,
    ttl=300,
) -> Principal:
    return Principal(
        subject=subject,
        tenant_id=tenant,
        roles=frozenset(roles),
        scopes=frozenset(scopes),
        expires_at=time.time() + ttl,
    )


def build(tmp_path, replies, *, settings=None, policy=None, tool_executor=None, scanner=None):
    """Return (store, guard, provider, policy) wired through the port contract."""
    settings = settings or Settings(
        database_url=f"sqlite:///{tmp_path / 'guard.db'}", audit_key=secrets.token_hex(32)
    )
    audit = Audit.from_settings(settings)
    store = SupportSQLStore(settings, audit)
    store.initialize()
    provider = ScriptedProvider(replies)
    ports = sql_ports(store)
    policy = policy or SupportPolicy()
    guard = Guard(
        provider=provider,
        signer=audit,
        limits=settings.limits(),
        scanner=scanner,
        tool_executor=tool_executor or ToolGateway(ports["documents"], policy),
        **ports,
    )
    return store, guard, provider, policy


def seed_account(
    store,
    tenant="tenant-a",
    owner="user-a",
    account_id="acct_abcdefghij",
    fee_cents=10000,
    status="active",
):
    with store.transaction(tenant) as conn:
        conn.execute(
            insert(accounts).values(
                tenant_id=tenant,
                account_id=account_id,
                owner_subject=owner,
                status=status,
                currency="USD",
                fee_cents=fee_cents,
                version=1,
            )
        )


def conversation_for(store, guard, caller) -> str:
    return store.create_conversation(guard.context(caller))


def new_operation() -> str:
    return uuid4().hex
