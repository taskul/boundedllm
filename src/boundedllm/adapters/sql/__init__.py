"""Batteries-included SQL implementation of every core port.

Use this when you want the package to own its storage. A host that already has a
document store, an audit pipeline, or an authorization service should implement
``boundedllm.ports`` against those instead; nothing in the core knows this module
exists.

The store is synchronous SQLAlchemy, so this adapter is where the threading
policy lives. Every call crosses into a worker thread through
``asyncio.to_thread``, which means the default executor's thread count is the
real concurrency ceiling for database work. Raise it deliberately for a
high-throughput deployment:

    import asyncio, concurrent.futures
    loop = asyncio.get_running_loop()
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=64))

Putting that decision here, rather than in the request path, is the point of the
port boundary: swapping in an async driver changes this file and nothing else.
"""

import asyncio
from pathlib import Path

from boundedllm.adapters.sql.schema import metadata
from boundedllm.adapters.sql.store import SQLStore
from boundedllm.models import ChatRequest, ChatResponse, Document, Principal, RequestContext

ALEMBIC_INI = Path(__file__).with_name("alembic.ini")

__all__ = ["ALEMBIC_INI", "SQLAdapter", "SQLStore", "metadata", "migrate", "sql_ports", "stamp"]


def _alembic_config():
    from alembic.config import Config

    config = Config(str(ALEMBIC_INI))
    # script_location resolves against the ini's own directory so migrations are
    # found inside an installed wheel, not just in a source checkout.
    config.set_main_option("script_location", str(ALEMBIC_INI.parent / "migrations"))
    return config


def migrate(revision: str = "head") -> None:
    """Run versioned migrations against GUARD_DATABASE_URL.

    This is the production path. ``SQLStore.initialize`` is a development
    convenience that creates tables directly and leaves no reviewable history,
    which is not something a DBA team will accept on a real database.
    """
    from alembic import command

    command.upgrade(_alembic_config(), revision)


def stamp(revision: str = "head") -> None:
    """Record a revision without running it, for a database created before Alembic."""
    from alembic import command

    command.stamp(_alembic_config(), revision)


class SQLAdapter:
    """Implements Ledger, Quotas, Operations, and Documents over one SQL store."""

    def __init__(self, store: SQLStore):
        self.store = store

    # Ledger ---------------------------------------------------------------
    async def event(self, ctx: RequestContext, event: str, **fields) -> None:
        await asyncio.to_thread(self.store.event, ctx, event, **fields)

    # Quotas ---------------------------------------------------------------
    async def throttle(self, principal: Principal) -> None:
        await asyncio.to_thread(self.store.throttle, principal)

    async def reserve_model_cost(self, ctx: RequestContext) -> None:
        await asyncio.to_thread(self.store.reserve_model_cost, ctx)

    # Operations -----------------------------------------------------------
    async def claim(self, ctx: RequestContext, request: ChatRequest) -> ChatResponse | None:
        return await asyncio.to_thread(self.store.claim_operation, ctx, request)

    async def finish(
        self,
        ctx: RequestContext,
        operation_id: str,
        response: ChatResponse | None,
        docs: list[Document] | None = None,
    ) -> None:
        await asyncio.to_thread(self.store.finish_operation, ctx, operation_id, response, docs)

    # Documents ------------------------------------------------------------
    async def search(
        self,
        principal: Principal,
        query: str,
        limit: int,
        max_level: int,
        conversation_id: str,
        attachment_ids: list[str],
    ) -> list[Document]:
        return await asyncio.to_thread(
            self.store.search, principal, query, limit, max_level, conversation_id, attachment_ids
        )

    async def quarantine(self, ctx: RequestContext, doc_id: str, signals: list[str]) -> None:
        await asyncio.to_thread(self.store.quarantine_document, ctx, doc_id, signals)

    async def attachment_results(
        self, principal: Principal, conversation_id: str, attachment_ids: list[str]
    ) -> list[dict]:
        return await asyncio.to_thread(
            self.store.attachment_results, principal, conversation_id, attachment_ids
        )

    # Convenience used by host tool executors, which are async by contract.
    async def get_account(self, principal: Principal, account_id: str):
        return await asyncio.to_thread(self.store.get_account, principal, account_id)

    async def propose_waiver(self, ctx, request, args, flags, policy) -> dict:
        return await asyncio.to_thread(self.store.propose_waiver, ctx, request, args, flags, policy)


def sql_ports(store: SQLStore) -> dict:
    """Spread into ``Guard(...)`` so one adapter satisfies every port by name.

    guard = Guard(provider=provider, signer=audit, **sql_ports(store))
    """
    adapter = SQLAdapter(store)
    return {
        "ledger": adapter,
        "quotas": adapter,
        "operations": adapter,
        "documents": adapter,
    }
