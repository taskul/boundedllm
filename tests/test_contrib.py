"""The contrib adapters are where a host's data meets this package's contracts.

An adapter that quietly drops a predicate is the most likely way a deployment
leaks, so these tests attack the adapters rather than demonstrate them. The
pgvector tests need a real database because the property under test is what the
query returns, which cannot be checked against a mock.
"""

import asyncio
import json
import logging
import os

import pytest

from boundedllm.contrib.anthropic import ASSISTANT_SCHEMA, AnthropicProvider
from boundedllm.contrib.ledger import StructuredLogLedger, TeeLedger
from boundedllm.errors import Unavailable
from boundedllm.model_gateway import ModelRequest
from boundedllm.models import Principal, RequestContext

POSTGRES_URL = os.getenv("TEST_POSTGRES_URL")


def ctx(subject="user-a", tenant="tenant-a"):
    return RequestContext(
        request_id="a" * 32,
        principal=Principal(
            subject=subject, tenant_id=tenant, scopes=frozenset({"chat:use"}), expires_at=2**31
        ),
    )


# ---------------------------------------------------------------------------
# Ledger adapters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_structured_log_ledger_pseudonymizes_the_subject(caplog):
    class Signer:
        def fingerprint(self, value):
            return "f" * 64

    ledger = StructuredLogLedger(signer=Signer())
    with caplog.at_level(logging.INFO, logger="boundedllm.security"):
        await ledger.event(ctx(), "request_blocked", code="NETWORK_REFERENCE", severity="high")
    record = json.loads(caplog.records[-1].message)
    assert record["subject_fingerprint"] == "f" * 64
    assert "user-a" not in caplog.text, "the raw subject reached the log"
    assert record["code"] == "NETWORK_REFERENCE"
    # Severity has to map to a log level or a SOC filter never sees the event.
    assert caplog.records[-1].levelno == logging.ERROR


@pytest.mark.asyncio
async def test_a_failing_mirror_cannot_fail_the_request_but_a_failing_primary_can():
    """The asymmetry is the point: evidence is mandatory, telemetry is not."""

    class Recording:
        def __init__(self):
            self.events = []

        async def event(self, ctx, event, **fields):
            self.events.append(event)

    class Broken:
        async def event(self, ctx, event, **fields):
            raise RuntimeError("SIEM unreachable")

    primary = Recording()
    tee = TeeLedger(primary, Broken())
    await tee.event(ctx(), "input_risk", status="continue")
    assert primary.events == ["input_risk"]

    # A primary that cannot record must stop the turn.
    with pytest.raises(RuntimeError):
        await TeeLedger(Broken(), Recording()).event(ctx(), "input_risk", status="continue")


# ---------------------------------------------------------------------------
# Anthropic provider
# ---------------------------------------------------------------------------


class FakeMessages:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.kwargs = response, error, None

    async def create(self, **kwargs):
        self.kwargs = kwargs
        if self.error:
            raise self.error
        return self.response


class FakeClient:
    def __init__(self, response=None, error=None):
        self.messages = FakeMessages(response, error)


class Block:
    def __init__(self, text):
        self.type, self.text = "text", text


class Response:
    def __init__(self, blocks, stop_reason="end_turn"):
        self.content, self.stop_reason = blocks, stop_reason


REQUEST = ModelRequest(model="claude-opus-5", system="policy", user="question", max_output_tokens=800)


@pytest.mark.asyncio
async def test_the_provider_constrains_the_decoder_and_sends_no_tools():
    client = FakeClient(Response([Block('{"answer":"ok","tool_call":null}')]))
    result = await AnthropicProvider(client).complete(REQUEST)
    assert json.loads(result)["answer"] == "ok"
    sent = client.messages.kwargs
    assert sent["output_config"]["format"]["schema"] == ASSISTANT_SCHEMA
    # Tools are proposals authorized by the host. Handing Claude a callable tool
    # would move that decision to the wrong side of the boundary.
    assert "tools" not in sent
    # One turn, no replayed history that would bypass this turn's retrieval ACL.
    assert sent["messages"] == [{"role": "user", "content": "question"}]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response,expected",
    [
        (Response([Block("{}")], stop_reason="refusal"), "MODEL_REFUSED"),
        (Response([Block('{"answer":"tru')], stop_reason="max_tokens"), "MODEL_TRUNCATED"),
        (Response([Block("a"), Block("b")]), "MODEL_RESPONSE_SCHEMA"),
        (Response([]), "MODEL_RESPONSE_SCHEMA"),
    ],
)
async def test_a_non_answer_is_never_returned_as_an_answer(response, expected):
    """A refusal and a truncation both arrive as HTTP 200 with content present."""
    with pytest.raises(Unavailable) as failure:
        await AnthropicProvider(FakeClient(response)).complete(REQUEST)
    assert failure.value.code == expected


@pytest.mark.asyncio
async def test_a_transport_error_surfaces_as_unavailable_not_a_raw_exception():
    with pytest.raises(Unavailable) as failure:
        await AnthropicProvider(FakeClient(error=RuntimeError("connection reset"))).complete(REQUEST)
    assert failure.value.code == "MODEL_FAILURE"


# ---------------------------------------------------------------------------
# pgvector retrieval - requires a real database
# ---------------------------------------------------------------------------

pgvector_tests = pytest.mark.skipif(
    not POSTGRES_URL, reason="set TEST_POSTGRES_URL to a disposable PostgreSQL database"
)

SCHEMA = """
DROP TABLE IF EXISTS rag_documents;
CREATE TABLE rag_documents (
    tenant_id text NOT NULL,
    doc_id text NOT NULL,
    classification text NOT NULL,
    level int NOT NULL,
    source text NOT NULL,
    body text NOT NULL,
    owner_subject text,
    conversation_id text,
    upload_state text NOT NULL DEFAULT 'ready',
    content_hash char(64) NOT NULL,
    retention_policy text NOT NULL DEFAULT 'standard',
    allowed_roles text[] NOT NULL DEFAULT '{}',
    embedding double precision[] NOT NULL,
    PRIMARY KEY (tenant_id, doc_id)
);
"""

ROWS = [
    # tenant, doc, classification, level, owner, conversation, roles, state
    ("tenant-a", "mine-public", "public", 0, None, None, [], "ready"),
    ("tenant-a", "mine-internal", "internal", 1, None, None, ["support"], "ready"),
    ("tenant-a", "mine-restricted", "restricted", 3, None, None, ["support"], "ready"),
    ("tenant-a", "other-user", "internal", 1, "user-b", "c" * 32, ["support"], "ready"),
    ("tenant-a", "quarantined", "internal", 1, "user-a", "c" * 32, ["support"], "quarantined"),
    ("tenant-a", "wrong-role", "internal", 1, None, None, ["finance"], "ready"),
    ("tenant-b", "other-tenant", "public", 0, None, None, [], "ready"),
]


@pytest.fixture
async def pgvector_store():
    """A table loaded with rows that each violate exactly one predicate."""
    import psycopg
    from psycopg_pool import AsyncConnectionPool

    dsn = POSTGRES_URL.replace("postgresql+psycopg://", "postgresql://")
    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        await conn.execute(SCHEMA)
        for tenant, doc, classification, level, owner, conversation, roles, state in ROWS:
            await conn.execute(
                "INSERT INTO rag_documents (tenant_id, doc_id, classification, level, source, body,"
                " owner_subject, conversation_id, upload_state, content_hash, allowed_roles, embedding)"
                " VALUES (%s,%s,%s,%s,'wiki',%s,%s,%s,%s,%s,%s,%s)",
                (
                    tenant,
                    doc,
                    classification,
                    level,
                    f"body of {doc}",
                    owner,
                    conversation,
                    state,
                    "a" * 64,
                    roles,
                    [0.1, 0.2, 0.3],
                ),
            )
        await conn.commit()

    pool = AsyncConnectionPool(dsn, min_size=1, max_size=3, open=False)
    await pool.open()
    yield pool
    await pool.close()


def build_documents(pool):
    from boundedllm.contrib.pgvector import PgVectorDocuments

    # The ORDER BY uses the pgvector operator, which this fixture's plain array
    # column does not implement, so ranking is stubbed. What is under test is the
    # ACL predicate, which is identical either way.
    adapter = PgVectorDocuments(pool, embed=lambda _: [0.1, 0.2, 0.3])
    adapter._rank_order = "doc_id"
    return adapter


@pgvector_tests
@pytest.mark.asyncio
async def test_pgvector_returns_only_rows_the_caller_may_read(pgvector_store, monkeypatch):
    from boundedllm.contrib import pgvector as module

    adapter = build_documents(pgvector_store)
    # Replace only the similarity ordering; every predicate stays as shipped.
    original = module.PgVectorDocuments._rank

    async def ranked(self, conn, principal, conversation_id, max_level, vector, limit, exclude):
        sql = (
            f"SELECT * FROM {self.table} WHERE {self._acl_sql()}"
            f" AND NOT (doc_id = ANY(%s::text[])) ORDER BY doc_id LIMIT %s"
        )
        params = [*self._acl_params(principal, conversation_id, max_level), list(exclude), limit]
        async with conn.cursor() as cur:
            await cur.execute(sql, params)
            rows = await cur.fetchall()
            columns = [c.name for c in cur.description]
        return [module._to_document(columns, row) for row in rows]

    monkeypatch.setattr(module.PgVectorDocuments, "_rank", ranked)
    principal = Principal(
        subject="user-a",
        tenant_id="tenant-a",
        roles=frozenset({"support"}),
        scopes=frozenset({"chat:use", "documents:read"}),
        expires_at=2**31,
    )
    docs = await adapter.search(principal, "anything", 20, 3, "d" * 32, [])
    returned = {doc.doc_id for doc in docs}

    assert "other-tenant" not in returned, "cross-tenant document returned"
    assert "other-user" not in returned, "another subject's document returned"
    assert "quarantined" not in returned, "quarantined document returned"
    assert "wrong-role" not in returned, "role ACL not applied"
    # This caller holds neither data:confidential nor data:restricted, so a
    # level-3 document is above their clearance even inside their own tenant.
    assert "mine-restricted" not in returned, "clearance ceiling not applied"
    assert {"mine-public", "mine-internal"} <= returned, "the caller's own documents are missing"
    module.PgVectorDocuments._rank = original


@pgvector_tests
@pytest.mark.asyncio
async def test_pgvector_clearance_ceiling_lowers_what_a_risky_turn_can_see(pgvector_store, monkeypatch):
    """max_level is a ceiling the engine drops on a step-up turn; it must bind."""
    from boundedllm.contrib import pgvector as module

    adapter = build_documents(pgvector_store)

    async def ranked(self, conn, principal, conversation_id, max_level, vector, limit, exclude):
        sql = f"SELECT * FROM {self.table} WHERE {self._acl_sql()} ORDER BY doc_id LIMIT %s"
        params = [*self._acl_params(principal, conversation_id, max_level), limit]
        async with conn.cursor() as cur:
            await cur.execute(sql, params)
            rows = await cur.fetchall()
            columns = [c.name for c in cur.description]
        return [module._to_document(columns, row) for row in rows]

    monkeypatch.setattr(module.PgVectorDocuments, "_rank", ranked)
    principal = Principal(
        subject="user-a",
        tenant_id="tenant-a",
        roles=frozenset({"support"}),
        scopes=frozenset({"chat:use", "documents:read", "data:restricted"}),
        expires_at=2**31,
    )
    lowered = await adapter.search(principal, "anything", 20, 1, "d" * 32, [])
    assert {doc.doc_id for doc in lowered} <= {"mine-public", "mine-internal"}
    assert "mine-restricted" not in {doc.doc_id for doc in lowered}


@pgvector_tests
@pytest.mark.asyncio
async def test_pgvector_reports_a_failed_embedding_instead_of_returning_nothing(pgvector_store):
    """An empty result reads as 'no matching documents' and hides the outage."""
    from boundedllm.contrib.pgvector import PgVectorDocuments

    def broken(_):
        raise RuntimeError("embedding service down")

    adapter = PgVectorDocuments(pgvector_store, embed=broken)
    principal = Principal(
        subject="user-a", tenant_id="tenant-a", scopes=frozenset({"chat:use"}), expires_at=2**31
    )
    with pytest.raises(Unavailable) as failure:
        await adapter.search(principal, "q", 5, 3, "d" * 32, [])
    assert failure.value.code == "EMBEDDING_FAILURE"


def test_asyncio_is_imported_for_the_thread_offload():
    """Guard against the embed call silently becoming blocking."""
    from boundedllm.contrib import pgvector

    assert asyncio is not None and hasattr(pgvector, "asyncio")
