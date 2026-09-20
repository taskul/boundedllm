"""A ``Documents`` port over PostgreSQL with pgvector.

Vector search is where retrieval ACLs are most often lost. The usual mistake is
to rank first and filter afterwards: the nearest neighbours are computed across
every tenant, then the caller's rows are kept. That returns correct data and is
still a breach, because the ranking itself was computed over someone else's
documents and the result set silently changes based on their content.

This adapter puts every predicate in the ``WHERE`` clause so the index never
considers a row the caller cannot read. ``secure_search`` in the core re-checks
what comes back, but that is a tripwire for a mistake here, not a substitute for
getting it right.

Schema this expects (adjust the names, keep the shape)::

    CREATE TABLE rag_documents (
        tenant_id       text        NOT NULL,
        doc_id          text        NOT NULL,
        classification  text        NOT NULL,
        level           int         NOT NULL,
        source          text        NOT NULL,
        body            text        NOT NULL,
        owner_subject   text,
        conversation_id text,
        upload_state    text        NOT NULL DEFAULT 'ready',
        content_hash    char(64)    NOT NULL,
        retention_policy text       NOT NULL DEFAULT 'standard',
        allowed_roles   text[]      NOT NULL DEFAULT '{}',
        embedding       vector(1536) NOT NULL,
        PRIMARY KEY (tenant_id, doc_id)
    );
    CREATE INDEX ON rag_documents USING hnsw (embedding vector_cosine_ops);

Enable row-level security on it as well. The predicates below are the first line;
RLS is what holds if a future query forgets one.
"""

import asyncio
import re
from collections.abc import Callable, Sequence

from boundedllm.errors import Unavailable
from boundedllm.models import Document, Principal, RequestContext

# Ranking is bounded before the ACL filter is applied, so a caller cannot make the
# database scan the whole table by asking a very broad question.
CANDIDATE_MULTIPLIER = 4
MAX_CANDIDATES = 200


class PgVectorDocuments:
    """Retrieval over pgvector with tenant, owner, conversation, role, and class filters.

    ``embed`` turns the query into a vector. It runs in a worker thread, so a
    synchronous embedding client is fine; an async one should be wrapped to match.

    ``pool`` is an ``psycopg_pool.AsyncConnectionPool``. Give it credentials that
    can only read this table.
    """

    def __init__(
        self,
        pool,
        embed: Callable[[str], Sequence[float]],
        *,
        table: str = "rag_documents",
        quarantine_table: str | None = None,
    ):
        # The table name is interpolated into SQL, so it is fixed at construction
        # by the application and never derived from a request. Identifiers cannot
        # be parameterized; values always are.
        for name in (table, quarantine_table or table):
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", name):
                raise ValueError(f"table must be a plain unquoted identifier: {name!r}")
        self.pool = pool
        self.embed = embed
        self.table = table
        self.quarantine_table = quarantine_table or table

    async def search(
        self,
        principal: Principal,
        query: str,
        limit: int,
        max_level: int,
        conversation_id: str,
        attachment_ids: list[str],
    ) -> list[Document]:
        if limit <= 0:
            return []
        try:
            vector = await asyncio.to_thread(self.embed, query)
        except Exception as exc:
            # A failed embedding must not degrade into an unfiltered keyword
            # search or an empty result that reads as "no matching documents".
            raise Unavailable("EMBEDDING_FAILURE") from exc

        attachment_ids = list(dict.fromkeys(attachment_ids))
        try:
            async with self.pool.connection() as conn:
                attached = (
                    await self._fetch(conn, principal, conversation_id, max_level, attachment_ids)
                    if attachment_ids
                    else []
                )
                if len(attached) != len(attachment_ids):
                    # One generic outcome whether the document belongs to someone
                    # else or does not exist, so the response is not an oracle.
                    raise Unavailable("ATTACHMENT_NOT_AVAILABLE")
                remaining = limit - len(attached)
                ranked = (
                    await self._rank(
                        conn, principal, conversation_id, max_level, vector, remaining, attachment_ids
                    )
                    if remaining > 0
                    else []
                )
        except Unavailable:
            raise
        except Exception as exc:
            raise Unavailable("RETRIEVAL_FAILURE") from exc
        return attached + ranked

    # psycopg uses %s placeholders, not the $1 form asyncpg takes. Values are
    # always bound; only the table identifier is interpolated, and it is fixed at
    # construction rather than derived from a request.
    ACL_SQL = """
        tenant_id = %s
        AND level <= %s
        AND (classification = 'public' OR allowed_roles && %s::text[])
        AND (owner_subject IS NULL OR owner_subject = %s)
        AND (conversation_id IS NULL OR conversation_id = %s)
        AND upload_state = 'ready'
    """

    def _acl_sql(self) -> str:
        """The predicate every read shares. Written once so it cannot drift apart."""
        return self.ACL_SQL

    def _acl_params(self, principal: Principal, conversation_id: str, max_level: int) -> list:
        return [
            principal.tenant_id,
            min(_clearance(principal), max_level),
            sorted(principal.roles),
            principal.subject,
            conversation_id,
        ]

    async def _fetch(self, conn, principal, conversation_id, max_level, doc_ids) -> list[Document]:
        # noqa rationale: the only interpolation is the identifier validated in
        # __init__; every value below is a bound parameter.
        sql = f"SELECT * FROM {self.table} WHERE {self._acl_sql()} AND doc_id = ANY(%s::text[])"  # noqa: S608
        params = [*self._acl_params(principal, conversation_id, max_level), list(doc_ids)]
        async with conn.cursor() as cur:
            await cur.execute(sql, params)
            rows = await cur.fetchall()
            columns = [column.name for column in cur.description]
        by_id = {row[columns.index("doc_id")]: _to_document(columns, row) for row in rows}
        # Preserve the caller's order so an attachment list is reported consistently.
        return [by_id[doc_id] for doc_id in doc_ids if doc_id in by_id]

    async def _rank(
        self, conn, principal, conversation_id, max_level, vector, limit, exclude
    ) -> list[Document]:
        # The ACL is inside the ranked query, not applied to its output. Ordering
        # over rows the caller cannot read would leak their content through rank.
        sql = f"""
            SELECT * FROM {self.table}
            WHERE {self._acl_sql()} AND NOT (doc_id = ANY(%s::text[]))
            ORDER BY embedding <=> %s::vector
            LIMIT %s
        """  # noqa: S608  validated identifier only; values are bound
        candidates = min(max(limit * CANDIDATE_MULTIPLIER, limit), MAX_CANDIDATES)
        params = [
            *self._acl_params(principal, conversation_id, max_level),
            list(exclude),
            list(vector),
            candidates,
        ]
        async with conn.cursor() as cur:
            await cur.execute(sql, params)
            rows = await cur.fetchall()
            columns = [column.name for column in cur.description]
        return [_to_document(columns, row) for row in rows[:limit]]

    async def quarantine(self, ctx: RequestContext, doc_id: str, signals: list[str]) -> None:
        """Persist a fail-closed state so a known poisoned upload cannot be retried."""
        sql = f"""
            UPDATE {self.quarantine_table} SET upload_state = 'quarantined'
            WHERE tenant_id = %s AND doc_id = %s AND owner_subject = %s AND upload_state = 'ready'
        """  # noqa: S608  validated identifier only; values are bound
        try:
            async with self.pool.connection() as conn, conn.cursor() as cur:
                await cur.execute(sql, [ctx.principal.tenant_id, doc_id, ctx.principal.subject])
        except Exception as exc:
            raise Unavailable("QUARANTINE_FAILURE") from exc

    async def attachment_results(
        self, principal: Principal, conversation_id: str, attachment_ids: list[str]
    ) -> list[dict]:
        if not attachment_ids:
            return []
        sql = f"""
            SELECT doc_id, upload_state FROM {self.quarantine_table}
            WHERE tenant_id = %s AND owner_subject = %s AND conversation_id = %s
              AND doc_id = ANY(%s::text[])
        """  # noqa: S608  validated identifier only; values are bound
        try:
            async with self.pool.connection() as conn, conn.cursor() as cur:
                await cur.execute(
                    sql, [principal.tenant_id, principal.subject, conversation_id, list(attachment_ids)]
                )
                states = dict(await cur.fetchall())
        except Exception as exc:
            raise Unavailable("RETRIEVAL_FAILURE") from exc
        return [
            {
                "document_id": doc_id,
                "status": "quarantined" if states.get(doc_id) == "quarantined" else "rejected",
                "code": "POISONED_DOCUMENT" if states.get(doc_id) == "quarantined" else "RESOURCE_NOT_FOUND",
            }
            for doc_id in attachment_ids
        ]


def _clearance(principal: Principal) -> int:
    if "data:restricted" in principal.scopes:
        return 3
    if "data:confidential" in principal.scopes:
        return 2
    return 1


def _to_document(columns: list[str], row) -> Document:
    values = dict(zip(columns, row, strict=False))
    return Document(
        doc_id=values["doc_id"],
        tenant_id=values["tenant_id"],
        classification=values["classification"],
        allowed_roles=frozenset(values.get("allowed_roles") or ()),
        source=values["source"],
        body=values["body"],
        owner_subject=values.get("owner_subject"),
        conversation_id=values.get("conversation_id"),
        upload_state=values.get("upload_state", "ready"),
        content_hash=values["content_hash"],
        retention_policy=values.get("retention_policy", "standard"),
        # Never read from the row: a publisher cannot mark its own content trusted.
        provenance_verified=False,
    )
