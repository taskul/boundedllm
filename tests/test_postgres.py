"""PostgreSQL-only behavior: row-level security, locking, and the production gate.

Production runs on PostgreSQL with RLS, and none of that is exercised by the
SQLite suite. RLS in particular is the last line under every ACL predicate in the
repository: if a query is ever written without a tenant filter, this is what
decides whether that becomes a cross-tenant read.

Run with a disposable database::

    TEST_POSTGRES_URL=postgresql+psycopg://postgres:postgres@localhost:5432/guard_test \\
        uv run pytest -m postgres

Every test drops and recreates its own schema, so never point this at data you
care about.
"""

import os
import secrets

import pytest
from sqlalchemy import create_engine, insert, select, text
from sqlalchemy.exc import DBAPIError

from boundedllm.adapters.sql.schema import documents, metadata
from boundedllm.audit import Audit
from boundedllm.config import Settings
from boundedllm.errors import Unavailable
from boundedllm.support.store import SupportSQLStore

pytestmark = pytest.mark.postgres

POSTGRES_URL = os.getenv("TEST_POSTGRES_URL")
APP_ROLE = "guard_app_ci"
APP_PASSWORD = "guard_app_ci_password"

requires_postgres = pytest.mark.skipif(
    not POSTGRES_URL, reason="set TEST_POSTGRES_URL to a disposable PostgreSQL database"
)


def admin_engine():
    return create_engine(POSTGRES_URL, future=True)


def app_url() -> str:
    """The same database reached as a least-privilege, non-owner role."""
    head, _, tail = POSTGRES_URL.partition("://")
    _, _, hostpart = tail.partition("@")
    return f"{head}://{APP_ROLE}:{APP_PASSWORD}@{hostpart}"


@pytest.fixture
def fresh_schema():
    """Recreate the schema and a non-owner application role for one test."""
    engine = admin_engine()
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
        conn.execute(
            text(
                f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{APP_ROLE}') "
                f"THEN CREATE ROLE {APP_ROLE} LOGIN PASSWORD '{APP_PASSWORD}'; END IF; END $$;"
            )
        )
    metadata.create_all(engine)
    import boundedllm.support.schema  # noqa: F401  registers the domain tables

    metadata.create_all(engine)
    with engine.begin() as conn:
        for table in metadata.tables.values():
            conn.execute(text(f'ALTER TABLE "{table.name}" ENABLE ROW LEVEL SECURITY'))
            conn.execute(text(f'ALTER TABLE "{table.name}" FORCE ROW LEVEL SECURITY'))
            conn.execute(text(f'DROP POLICY IF EXISTS guard_tenant_policy ON "{table.name}"'))
            conn.execute(
                text(
                    f'CREATE POLICY guard_tenant_policy ON "{table.name}" '
                    "USING (tenant_id = current_setting('app.tenant_id', true)) "
                    "WITH CHECK (tenant_id = current_setting('app.tenant_id', true))"
                )
            )
        conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}"))
        conn.execute(
            text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {APP_ROLE}")
        )
    yield engine
    engine.dispose()


def seed_document(engine, tenant, doc_id, body):
    with engine.begin() as conn:
        conn.execute(
            insert(documents).values(
                tenant_id=tenant,
                doc_id=doc_id,
                classification="public",
                level=0,
                source="policy_wiki",
                body=body,
                upload_state="ready",
                content_hash="a" * 64,
                retention_policy="standard",
                provenance_verified=0,
                created_at=0.0,
            )
        )


@requires_postgres
def test_row_level_security_hides_other_tenants_from_a_raw_query(fresh_schema):
    """The decisive test: a query with no tenant filter must still return nothing.

    Every ACL predicate in the repository is written correctly today. RLS is what
    holds when one is not, so it has to be verified against the actual database
    rather than assumed from the policy statement.
    """
    seed_document(fresh_schema, "tenant-a", "doc-a", "Tenant A confidential text")
    seed_document(fresh_schema, "tenant-b", "doc-b", "Tenant B confidential text")

    app = create_engine(app_url(), future=True)
    with app.connect() as conn:
        with conn.begin():
            conn.execute(text("SELECT set_config('app.tenant_id', 'tenant-a', true)"))
            # Deliberately no tenant predicate. RLS supplies it.
            rows = conn.execute(select(documents.c.doc_id, documents.c.body)).mappings().all()
    assert {row["doc_id"] for row in rows} == {"doc-a"}
    assert all("Tenant B" not in row["body"] for row in rows)
    app.dispose()


@requires_postgres
def test_an_unset_tenant_context_returns_nothing_rather_than_everything(fresh_schema):
    """current_setting(..., true) yields NULL, and NULL comparison is not true.

    A policy that failed open here would turn a missing SET into a full export.
    """
    seed_document(fresh_schema, "tenant-a", "doc-a", "Tenant A confidential text")
    app = create_engine(app_url(), future=True)
    with app.connect() as conn, conn.begin():
        rows = conn.execute(select(documents.c.doc_id)).all()
    assert rows == []
    app.dispose()


@requires_postgres
def test_the_tenant_context_does_not_survive_into_a_pooled_reuse(fresh_schema):
    """SET LOCAL is transaction-scoped, so a pooled connection cannot leak a tenant."""
    seed_document(fresh_schema, "tenant-a", "doc-a", "Tenant A confidential text")
    app = create_engine(app_url(), future=True)
    with app.connect() as conn:
        with conn.begin():
            conn.execute(text("SELECT set_config('app.tenant_id', 'tenant-a', true)"))
            assert conn.execute(select(documents.c.doc_id)).all()
        with conn.begin():
            # Same physical connection, new transaction, no tenant set.
            assert conn.execute(select(documents.c.doc_id)).all() == []
    app.dispose()


@requires_postgres
def test_a_write_cannot_be_addressed_to_another_tenant(fresh_schema):
    """WITH CHECK stops a row being inserted outside the active tenant."""
    app = create_engine(app_url(), future=True)
    with app.connect() as conn, conn.begin():
        conn.execute(text("SELECT set_config('app.tenant_id', 'tenant-a', true)"))
        # Postgres raises a check-violation for a WITH CHECK failure.
        with pytest.raises(DBAPIError):
            conn.execute(
                insert(documents).values(
                    tenant_id="tenant-b",
                    doc_id="smuggled",
                    classification="public",
                    level=0,
                    source="policy_wiki",
                    body="written into another tenant",
                    upload_state="ready",
                    content_hash="b" * 64,
                    retention_policy="standard",
                    provenance_verified=0,
                    created_at=0.0,
                )
            )
    app.dispose()


@requires_postgres
def test_verify_production_refuses_an_over_privileged_database_role(fresh_schema):
    """The owner bypasses RLS unless FORCE is set, so owning the tables is refused."""
    settings = Settings(
        environment="production",
        database_url=POSTGRES_URL,
        audit_key=secrets.token_hex(32),
        allowed_tenants=frozenset({"tenant-a"}),
        model_url="https://model.example.com/v1/complete",
        dlp_backend="reviewed",
    )
    store = SupportSQLStore(settings, Audit.from_settings(settings))
    with pytest.raises(Unavailable) as refused:
        store.verify_production()
    assert refused.value.code in {
        "DATABASE_ROLE_TOO_POWERFUL",
        "DATABASE_RLS_REQUIRED",
        "DATABASE_TLS_REQUIRED",
    }
    store.close()


@requires_postgres
def test_the_audit_chain_holds_under_concurrent_writers(fresh_schema):
    """The per-tenant head row is what serializes sequence assignment.

    Two workers appending at once must produce one gapless chain, not two chains
    that both claim the same sequence number.
    """
    import threading

    settings = Settings(database_url=POSTGRES_URL, audit_key=secrets.token_hex(32))
    audit = Audit.from_settings(settings)
    stores = [SupportSQLStore(settings, audit) for _ in range(4)]
    from boundedllm.models import Principal, RequestContext

    def append(store):
        for _ in range(10):
            ctx = RequestContext(
                request_id=secrets.token_hex(16),
                principal=Principal(
                    subject="user-a", tenant_id="tenant-a", scopes=frozenset(), expires_at=2**31
                ),
            )
            store.event(ctx, "input_risk", status="continue")

    threads = [threading.Thread(target=append, args=(store,)) for store in stores]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    report = stores[0].verify_audit_chain("tenant-a")
    assert report["records"] == 40
    assert report["valid"] is True, report["invalid"]
    for store in stores:
        store.close()


@requires_postgres
@pytest.mark.asyncio
async def test_concurrent_retries_of_one_operation_execute_exactly_once(fresh_schema):
    """Idempotency has to hold on PostgreSQL, where it previously did not.

    ``INSERT ... ON CONFLICT DO NOTHING`` reports ``rowcount == -1`` on
    PostgreSQL rather than 0 or 1. The claim check compared rowcount to 0, so the
    "another worker owns this operation" branch was unreachable and every
    concurrent retry of one operation id ran the turn again. SQLite hid it:
    ``BEGIN IMMEDIATE`` serializes writers and its rowcount is accurate, so the
    whole SQLite suite stayed green while the production database duplicated work.
    """
    import asyncio
    import json
    from uuid import uuid4

    from boundedllm.adapters.sql import sql_ports
    from boundedllm.engine import Guard
    from boundedllm.errors import Conflict, GuardError
    from boundedllm.models import ChatRequest, Principal

    class CountingProvider:
        def __init__(self):
            self.calls = 0

        async def complete(self, request):
            self.calls += 1
            await asyncio.sleep(0.02)  # widen the window a real retry storm has
            return json.dumps({"answer": "Coverage is described in your policy.", "tool_call": None})

    settings = Settings(
        database_url=POSTGRES_URL,
        audit_key=secrets.token_hex(32),
        user_requests_per_minute=500,
    )
    audit = Audit.from_settings(settings)
    store = SupportSQLStore(settings, audit)
    store.initialize()
    provider = CountingProvider()
    guard = Guard(provider=provider, signer=audit, limits=settings.limits(), **sql_ports(store))

    caller = Principal(
        subject="retry-user",
        tenant_id="tenant-a",
        roles=frozenset({"support"}),
        scopes=frozenset({"chat:use"}),
        expires_at=2**31,
    )
    conversation = store.create_conversation(guard.context(caller))
    operation = uuid4().hex

    async def attempt():
        try:
            return (
                await guard.chat(
                    caller,
                    ChatRequest(
                        message="What does my policy cover?",
                        conversation_id=conversation,
                        operation_id=operation,
                    ),
                )
            ).status
        except Conflict:
            return "conflict"
        except GuardError as exc:
            return f"error:{exc.code}"

    results = await asyncio.gather(*(attempt() for _ in range(12)))
    assert provider.calls == 1, f"{provider.calls} executions for one operation id"
    assert "conflict" in results, "no concurrent attempt was refused"
    assert not [r for r in results if r.startswith("error:")], results
    store.close()
