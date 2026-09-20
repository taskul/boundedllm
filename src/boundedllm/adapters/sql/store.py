"""SQL repository with query-side ACLs and transactional monetary consent and execution.

Sync database work runs in asyncio.to_thread in the engine/API. PostgreSQL uses
row locks and transaction-local RLS context; SQLite serializes writers for the demo.
"""

import hashlib
import hmac
import json
import re
import time
from contextlib import contextmanager
from uuid import uuid4

from sqlalchemy import and_, create_engine, delete, exists, func, insert, inspect, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from boundedllm.adapters.sql.schema import (
    audit_events,
    audit_heads,
    audit_outbox,
    conversations,
    document_roles,
    documents,
    metadata,
    operations,
    quotas,
    security_cases,
)
from boundedllm.audit import Audit
from boundedllm.authz import clearance, require_live, require_scope
from boundedllm.config import Settings
from boundedllm.errors import Conflict, Denied, LimitExceeded, OutputBlocked, Unavailable
from boundedllm.models import (
    CLASS_LEVEL,
    ChatRequest,
    ChatResponse,
    Document,
    IngestRequest,
    Principal,
    RequestContext,
)

# Rows fetched per round trip when a whole-ledger pass is unavoidable. Bounds
# resident memory without turning one verification into thousands of queries.
AUDIT_SCAN_CHUNK = 1000
# Ceiling on reported chain breaks. The first failures locate the tampering; a
# corrupt ledger must not turn its own integrity report into a memory exhaustion.
MAX_REPORTED_INVALID = 100


class SQLStore:
    """Shared state works across workers; no identity, quota, or approval lives only in memory."""

    def __init__(self, settings: Settings, audit: Audit):
        self.settings, self.audit = settings, audit
        url = settings.database_url.get_secret_value()
        kwargs = {"pool_pre_ping": True}
        if url.startswith("sqlite:"):
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 5}
        self.engine = create_engine(url, **kwargs)
        self.postgres = self.engine.dialect.name == "postgresql"
        if self.engine.dialect.name not in {"sqlite", "postgresql"}:
            raise ValueError("only SQLite and PostgreSQL supported")

    def initialize(self) -> None:
        """Administrative migration command only; production startup never creates tables."""
        metadata.create_all(self.engine)
        self._migrate_additive_columns()

    def _migrate_additive_columns(self) -> None:
        """Upgrade early releases in place without deleting customer or audit data.

        These are deliberately additive migrations. Production deployments should
        run ``boundedllm init-db`` with the migration role before application rollout.
        """
        existing = {column["name"] for column in inspect(self.engine).get_columns("guard_documents")}
        audit_existing = {column["name"] for column in inspect(self.engine).get_columns("guard_audit")}
        document_columns = {
            "owner_subject": "VARCHAR(128)",
            "conversation_id": "VARCHAR(32)",
            "upload_state": "VARCHAR(16) NOT NULL DEFAULT 'ready'",
            "content_hash": "VARCHAR(64) NOT NULL DEFAULT ''",
            "retention_policy": "VARCHAR(128) NOT NULL DEFAULT 'standard'",
        }
        audit_columns = {
            "sequence": "INTEGER NOT NULL DEFAULT 0",
            "previous_hash": f"VARCHAR(64) NOT NULL DEFAULT '{'0' * 64}'",
            "record_hash": f"VARCHAR(64) NOT NULL DEFAULT '{'0' * 64}'",
            "key_id": "VARCHAR(128) NOT NULL DEFAULT 'legacy-v0'",
        }
        with self.engine.begin() as conn:
            for name, definition in document_columns.items():
                if name not in existing:
                    conn.exec_driver_sql(f'ALTER TABLE guard_documents ADD COLUMN "{name}" {definition}')
            for name, definition in audit_columns.items():
                if name not in audit_existing:
                    conn.exec_driver_sql(f'ALTER TABLE guard_audit ADD COLUMN "{name}" {definition}')

            # Content hashes are safe correlation values and allow integrity checks
            # without retaining raw upload bytes or copying text into logs.
            rows = conn.execute(
                select(documents.c.tenant_id, documents.c.doc_id, documents.c.body).where(
                    documents.c.content_hash == ""
                )
            ).mappings()
            for row in rows:
                conn.execute(
                    update(documents)
                    .where(
                        documents.c.tenant_id == row["tenant_id"],
                        documents.c.doc_id == row["doc_id"],
                    )
                    .values(content_hash=hashlib.sha256(row["body"].encode()).hexdigest())
                )
            # Early uploads had no owner binding, so ownership cannot be recovered
            # safely. Quarantine them and require a fresh authenticated upload.
            conn.execute(
                update(documents)
                .where(
                    documents.c.source == "customer_upload_pdf",
                    documents.c.owner_subject.is_(None),
                )
                .values(upload_state="quarantined", retention_policy="legacy-unowned")
            )

            # Older events receive a deterministic legacy chain. Their original
            # signatures remain untouched, so verification still reveals old-key
            # or modified records instead of silently blessing them.
            tenants = conn.execute(select(audit_events.c.tenant_id).distinct()).scalars().all()
            for tenant in tenants:
                prior = "0" * 64
                sequence = 0
                rows = (
                    conn.execute(
                        select(audit_events)
                        .where(audit_events.c.tenant_id == tenant)
                        .order_by(
                            audit_events.c.sequence,
                            audit_events.c.created_at,
                            audit_events.c.event_id,
                        )
                    )
                    .mappings()
                    .all()
                )
                if rows and not any(row["sequence"] == 0 for row in rows):
                    last = max(rows, key=lambda row: row["sequence"])
                    sequence, prior = last["sequence"], last["record_hash"]
                    constructor = pg_insert if self.postgres else sqlite_insert
                    conn.execute(
                        constructor(audit_heads)
                        .values(tenant_id=tenant, last_sequence=sequence, last_hash=prior)
                        .on_conflict_do_update(
                            index_elements=[audit_heads.c.tenant_id],
                            set_={"last_sequence": sequence, "last_hash": prior},
                        )
                    )
                    continue
                for row in rows:
                    sequence += 1
                    # Pre-versioned records are tested against the configured key.
                    # A rotated or modified legacy signature remains visibly invalid.
                    key_id = row["key_id"] if row["sequence"] else self.audit.key_id
                    record_hash = hashlib.sha256(
                        f"{prior}.{row['payload']}.{row['signature']}".encode()
                    ).hexdigest()
                    conn.execute(
                        update(audit_events)
                        .where(
                            audit_events.c.tenant_id == tenant,
                            audit_events.c.event_id == row["event_id"],
                        )
                        .values(
                            sequence=sequence,
                            previous_hash=prior,
                            record_hash=record_hash,
                            key_id=key_id,
                        )
                    )
                    prior = record_hash
                constructor = pg_insert if self.postgres else sqlite_insert
                conn.execute(
                    constructor(audit_heads)
                    .values(tenant_id=tenant, last_sequence=sequence, last_hash=prior)
                    .on_conflict_do_update(
                        index_elements=[audit_heads.c.tenant_id],
                        set_={"last_sequence": sequence, "last_hash": prior},
                    )
                )
        # create_all skipped indexes belonging to pre-existing tables.
        for index in documents.indexes | audit_events.indexes | audit_outbox.indexes:
            index.create(self.engine, checkfirst=True)

    def verify_production(self) -> None:
        """Refuse broad DB privileges or missing RLS; this is a runtime check, not a checkbox."""
        if not self.postgres:
            raise Unavailable("POSTGRES_REQUIRED")
        with self.engine.connect() as conn:
            role = conn.execute(
                text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user")
            )
            if any(role.one()):
                raise Unavailable("DATABASE_ROLE_TOO_POWERFUL")
            for table in metadata.tables.values():
                row = conn.execute(
                    text(
                        "SELECT relrowsecurity, relforcerowsecurity, pg_get_userbyid(relowner)=current_user "
                        "FROM pg_class WHERE oid=to_regclass(:name)"
                    ),
                    {"name": table.name},
                ).first()
                if row is None or not row[0] or not row[1] or row[2]:
                    raise Unavailable("DATABASE_RLS_REQUIRED")
            if (
                conn.execute(text("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()")).scalar()
                is not True
            ):
                raise Unavailable("DATABASE_TLS_REQUIRED")

    @contextmanager
    def transaction(self, tenant: str):
        """Set verified tenancy locally; pooled connections cannot retain another request's tenant."""
        with self.engine.connect() as conn:
            if self.postgres:
                with conn.begin():
                    conn.execute(
                        text("SELECT set_config('app.tenant_id', :tenant, true)"), {"tenant": tenant}
                    )
                    conn.execute(text("SET LOCAL statement_timeout = '5000ms'"))
                    conn.execute(text("SET LOCAL lock_timeout = '3000ms'"))
                    yield conn
            else:
                # BEGIN IMMEDIATE is required: a deferred SQLite transaction does not
                # serialize the initial read/compare/write of quotas and approvals.
                conn.exec_driver_sql("BEGIN IMMEDIATE")
                try:
                    yield conn
                    conn.commit()
                except BaseException:
                    conn.rollback()
                    raise

    def _audit(self, conn, ctx: RequestContext, event: str, **fields) -> None:
        constructor = pg_insert if self.postgres else sqlite_insert
        conn.execute(
            constructor(audit_heads)
            .values(tenant_id=ctx.principal.tenant_id, last_sequence=0, last_hash="0" * 64)
            .on_conflict_do_nothing()
        )
        head = (
            conn.execute(
                select(audit_heads)
                .where(audit_heads.c.tenant_id == ctx.principal.tenant_id)
                .with_for_update()
            )
            .mappings()
            .one()
        )
        record = self.audit.record(
            ctx,
            event,
            sequence=head["last_sequence"] + 1,
            previous_hash=head["last_hash"],
            **fields,
        )
        conn.execute(insert(audit_events).values(**record))
        envelope = json.dumps(record, sort_keys=True, separators=(",", ":"))
        conn.execute(
            insert(audit_outbox).values(
                tenant_id=record["tenant_id"],
                event_id=record["event_id"],
                sequence=record["sequence"],
                record_hash=record["record_hash"],
                envelope=envelope,
                state="pending",
                attempts=0,
                created_at=record["created_at"],
            )
        )
        conn.execute(
            update(audit_heads)
            .where(audit_heads.c.tenant_id == ctx.principal.tenant_id)
            .values(last_sequence=record["sequence"], last_hash=record["record_hash"])
        )

    def event(self, ctx: RequestContext, event: str, **fields) -> None:
        with self.transaction(ctx.principal.tenant_id) as conn:
            self._audit(conn, ctx, event, **fields)

    def list_audit_events(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
        event_type: str | None = None,
        severity: str | None = None,
        model: str | None = None,
        subject_fingerprint: str | None = None,
        since: float | None = None,
        until: float | None = None,
        before_sequence: int | None = None,
    ) -> list[dict]:
        """Read redacted security metadata for a trusted admin adapter."""
        limit = max(1, min(limit, 1000))
        stmt = select(audit_events).where(audit_events.c.tenant_id == tenant_id)
        if before_sequence is not None:
            stmt = stmt.where(audit_events.c.sequence < before_sequence)
        if since is not None:
            stmt = stmt.where(audit_events.c.created_at >= since)
        if until is not None:
            stmt = stmt.where(audit_events.c.created_at <= until)
        filtered = any((event_type, severity, model, subject_fingerprint))
        stmt = stmt.order_by(audit_events.c.sequence.desc()).limit(10000 if filtered else limit)
        with self.transaction(tenant_id) as conn:
            rows = conn.execute(stmt).mappings().all()
        result = []
        for row in rows:
            payload = json.loads(row["payload"])
            if event_type and payload.get("event_type") != event_type:
                continue
            if severity and payload.get("severity") != severity:
                continue
            if model and payload.get("model") != model:
                continue
            if subject_fingerprint and payload.get("subject_fingerprint") != subject_fingerprint:
                continue
            result.append(
                {
                    **payload,
                    "signature": row["signature"],
                    "record_hash": row["record_hash"],
                }
            )
            if len(result) == limit:
                break
        if result:
            with self.transaction(tenant_id) as conn:
                case_rows = (
                    conn.execute(select(security_cases).where(security_cases.c.tenant_id == tenant_id))
                    .mappings()
                    .all()
                )
            wanted = {event["event_id"] for event in result}
            cases = {row["event_id"]: dict(row) for row in case_rows if row["event_id"] in wanted}
        else:
            cases = {}
        for event in result:
            event["case"] = cases.get(event["event_id"])
        return result

    def get_audit_event(self, tenant_id: str, event_id: str) -> dict | None:
        with self.transaction(tenant_id) as conn:
            row = (
                conn.execute(
                    select(audit_events).where(
                        audit_events.c.tenant_id == tenant_id,
                        audit_events.c.event_id == event_id,
                    )
                )
                .mappings()
                .first()
            )
            case = (
                conn.execute(
                    select(security_cases).where(
                        security_cases.c.tenant_id == tenant_id,
                        security_cases.c.event_id == event_id,
                    )
                )
                .mappings()
                .first()
            )
        if row is None:
            return None
        return {
            **json.loads(row["payload"]),
            "signature": row["signature"],
            "record_hash": row["record_hash"],
            "case": dict(case) if case else None,
        }

    def update_security_case(
        self,
        ctx: RequestContext,
        event_id: str,
        state: str,
        case_id: str | None = None,
    ) -> dict:
        """Acknowledge or link an event without storing analyst free-form text."""
        require_scope(ctx.principal, "security:audit")
        if state not in {"open", "acknowledged", "resolved"}:
            raise ValueError("invalid security case state")
        if case_id is not None and (not re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,128}", case_id)):
            raise ValueError("invalid case identifier")
        tenant_id = ctx.principal.tenant_id
        actor = self.audit.fingerprint(ctx.principal.subject)
        values = {
            "tenant_id": tenant_id,
            "event_id": event_id,
            "state": state,
            "case_id": case_id,
            "actor_fingerprint": actor,
            "updated_at": time.time(),
        }
        with self.transaction(tenant_id) as conn:
            if not conn.execute(
                select(audit_events.c.event_id).where(
                    audit_events.c.tenant_id == tenant_id,
                    audit_events.c.event_id == event_id,
                )
            ).first():
                raise Denied("RESOURCE_NOT_FOUND")
            constructor = pg_insert if self.postgres else sqlite_insert
            conn.execute(
                constructor(security_cases)
                .values(**values)
                .on_conflict_do_update(
                    index_elements=[security_cases.c.tenant_id, security_cases.c.event_id],
                    set_={
                        "state": state,
                        "case_id": case_id,
                        "actor_fingerprint": actor,
                        "updated_at": values["updated_at"],
                    },
                )
            )
            self._audit(
                conn,
                ctx,
                "security_event_updated",
                related_event_id=event_id,
                case_id=case_id,
                state=state,
                actor_fingerprint=actor,
                severity="info",
            )
        return values

    def audit_stats(self, tenant_id: str) -> dict:
        # Event type lives in signed JSON for portability, so the breakdown needs
        # every row. Stream it instead of materializing the tenant's whole ledger:
        # the security console is the last thing that should run out of memory
        # during an incident, and a mature tenant holds millions of records.
        counts: dict[str, int] = {}
        with self.transaction(tenant_id) as conn:
            count = conn.execute(
                select(func.count()).select_from(audit_events).where(audit_events.c.tenant_id == tenant_id)
            ).scalar_one()
            rows = conn.execution_options(stream_results=True, yield_per=AUDIT_SCAN_CHUNK).execute(
                select(audit_events.c.payload).where(audit_events.c.tenant_id == tenant_id)
            )
            for payload in rows.scalars():
                name = json.loads(payload)["event_type"]
                counts[name] = counts.get(name, 0) + 1
        return {"tenant_id": tenant_id, "count": count, "event_types": counts}

    def export_audit_events(self, tenant_id: str, limit: int = 1000) -> list[dict]:
        """Return signed envelopes suitable for immutable archive or offline verification."""
        with self.transaction(tenant_id) as conn:
            rows = (
                conn.execute(
                    select(audit_events)
                    .where(audit_events.c.tenant_id == tenant_id)
                    .order_by(audit_events.c.sequence)
                    .limit(max(1, min(limit, 10000)))
                )
                .mappings()
                .all()
            )
        return [dict(row) for row in rows]

    def verify_audit_chain(self, tenant_id: str) -> dict:
        """Detect changed, removed, reordered, duplicated, and wrong-key records."""
        previous = "0" * 64
        expected_sequence = 1
        invalid: list[dict] = []
        unverifiable = 0
        records = 0
        chain_broken = False
        # Verification is inherently a full pass, but it streams so that ledger
        # size bounds duration rather than resident memory.
        with self.transaction(tenant_id) as conn:
            head = (
                conn.execute(select(audit_heads).where(audit_heads.c.tenant_id == tenant_id))
                .mappings()
                .first()
            )
            rows = conn.execution_options(stream_results=True, yield_per=AUDIT_SCAN_CHUNK).execute(
                select(audit_events)
                .where(audit_events.c.tenant_id == tenant_id)
                .order_by(audit_events.c.sequence)
            )
            for row in rows.mappings():
                records += 1
                chain_valid = row["sequence"] == expected_sequence and row["previous_hash"] == previous
                computed_hash = hashlib.sha256(
                    f"{row['previous_hash']}.{row['payload']}.{row['signature']}".encode()
                ).hexdigest()
                chain_valid = chain_valid and hmac.compare_digest(computed_hash, row["record_hash"])
                if row["key_id"] in self.audit.verification_keys:
                    signature_valid = self.audit.verify(dict(row))
                else:
                    signature_valid = None
                    unverifiable += 1
                if not chain_valid or signature_valid is False:
                    chain_broken = chain_broken or not chain_valid
                    if len(invalid) < MAX_REPORTED_INVALID:
                        invalid.append(
                            {
                                "sequence": row["sequence"],
                                "event_id": row["event_id"],
                                "chain_valid": chain_valid,
                                "signature_valid": signature_valid,
                            }
                        )
                previous = row["record_hash"]
                expected_sequence += 1
        if head is None:
            # A tenant that has never written an event has nothing to verify, and
            # the head row is created lazily with the first one. Reporting that as
            # invalid fails the documented cron check on every fresh deployment,
            # which is how an integrity alarm gets muted. Records without a head is
            # still a failure: it means the head was removed.
            head_valid = records == 0
        else:
            head_valid = head["last_sequence"] == records and hmac.compare_digest(head["last_hash"], previous)
        return {
            "tenant_id": tenant_id,
            "records": records,
            "valid": not invalid and head_valid and unverifiable == 0,
            "chain_valid": not chain_broken and head_valid,
            "head_valid": head_valid,
            "unverifiable_key_versions": unverifiable,
            "invalid": invalid,
            # A truncated list still proves tampering; the flag keeps an operator
            # from reading "100 problems" as the complete extent of the damage.
            "invalid_truncated": len(invalid) >= MAX_REPORTED_INVALID,
        }

    def create_audit_checkpoint(self, ctx: RequestContext) -> dict:
        """Sign the current head into the chain and enqueue it for external anchoring."""
        tenant_id = ctx.principal.tenant_id
        with self.transaction(tenant_id) as conn:
            head = (
                conn.execute(
                    select(audit_heads).where(audit_heads.c.tenant_id == tenant_id).with_for_update()
                )
                .mappings()
                .first()
            )
            if head is None:
                checkpoint_sequence, checkpoint_hash = 0, "0" * 64
            else:
                checkpoint_sequence = head["last_sequence"]
                checkpoint_hash = head["last_hash"]
            self._audit(
                conn,
                ctx,
                "audit_checkpoint",
                checkpoint_sequence=checkpoint_sequence,
                checkpoint_hash=checkpoint_hash,
                severity="info",
            )
        return {
            "tenant_id": tenant_id,
            "checkpoint_sequence": checkpoint_sequence,
            "checkpoint_hash": checkpoint_hash,
        }

    def pending_audit_exports(self, tenant_id: str, limit: int = 100) -> list[dict]:
        """Return an at-least-once batch; event_id is the SIEM deduplication key."""
        limit = max(1, min(limit, 1000))
        with self.transaction(tenant_id) as conn:
            rows = (
                conn.execute(
                    select(audit_outbox)
                    .where(
                        audit_outbox.c.tenant_id == tenant_id,
                        audit_outbox.c.state == "pending",
                    )
                    .order_by(audit_outbox.c.created_at)
                    .limit(limit)
                )
                .mappings()
                .all()
            )
        return [json.loads(row["envelope"]) for row in rows]

    def mark_audit_exported(self, tenant_id: str, events: list[dict]) -> None:
        """Acknowledge only the exact signed records accepted by the downstream sink."""
        now = time.time()
        with self.transaction(tenant_id) as conn:
            for event in events:
                if event["tenant_id"] != tenant_id:
                    raise ValueError("cross-tenant audit acknowledgement rejected")
                acknowledged = conn.execute(
                    update(audit_outbox)
                    .where(
                        audit_outbox.c.tenant_id == event["tenant_id"],
                        audit_outbox.c.event_id == event["event_id"],
                        audit_outbox.c.record_hash == event["record_hash"],
                    )
                    .values(state="exported", attempts=audit_outbox.c.attempts + 1, exported_at=now)
                )
                if acknowledged.rowcount != 1:
                    raise Conflict("AUDIT_EXPORT_ACK_MISMATCH")

    def mark_audit_export_failed(self, tenant_id: str, events: list[dict]) -> None:
        """Keep failed deliveries pending while recording bounded retry attempts."""
        with self.transaction(tenant_id) as conn:
            for event in events:
                if event["tenant_id"] != tenant_id:
                    raise ValueError("cross-tenant audit retry rejected")
                conn.execute(
                    update(audit_outbox)
                    .where(
                        audit_outbox.c.tenant_id == tenant_id,
                        audit_outbox.c.event_id == event["event_id"],
                        audit_outbox.c.record_hash == event["record_hash"],
                        audit_outbox.c.state == "pending",
                    )
                    .values(attempts=audit_outbox.c.attempts + 1)
                )

    def list_quarantined_documents(self, tenant_id: str, limit: int = 100) -> list[dict]:
        """Expose metadata for SOC review without returning extracted document text."""
        with self.transaction(tenant_id) as conn:
            rows = (
                conn.execute(
                    select(
                        documents.c.doc_id,
                        documents.c.owner_subject,
                        documents.c.conversation_id,
                        documents.c.classification,
                        documents.c.source,
                        documents.c.content_hash,
                        documents.c.retention_policy,
                        documents.c.created_at,
                    )
                    .where(
                        documents.c.tenant_id == tenant_id,
                        documents.c.upload_state == "quarantined",
                    )
                    .order_by(documents.c.created_at.desc())
                    .limit(max(1, min(limit, 1000)))
                )
                .mappings()
                .all()
            )
        return [
            {
                **{
                    key: value
                    for key, value in row.items()
                    if key not in {"owner_subject", "conversation_id"}
                },
                "owner_fingerprint": self.audit.fingerprint(row["owner_subject"] or "shared"),
                "conversation_fingerprint": self.audit.fingerprint(row["conversation_id"] or "shared"),
                "upload_state": "quarantined",
            }
            for row in rows
        ]

    def inspect_quarantined_document(self, tenant_id: str, doc_id: str) -> dict | None:
        rows = self.list_quarantined_documents(tenant_id, 1000)
        return next((row for row in rows if row["doc_id"] == doc_id), None)

    def _conversation(self, conn, principal: Principal, conversation_id: str):
        row = (
            conn.execute(
                select(conversations).where(
                    conversations.c.tenant_id == principal.tenant_id,
                    conversations.c.id == conversation_id,
                    conversations.c.subject == principal.subject,
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            raise Denied("RESOURCE_NOT_FOUND")
        return row

    def create_conversation(self, ctx: RequestContext) -> str:
        require_scope(ctx.principal, "chat:use")
        identifier = uuid4().hex
        with self.transaction(ctx.principal.tenant_id) as conn:
            conn.execute(
                insert(conversations).values(
                    tenant_id=ctx.principal.tenant_id,
                    id=identifier,
                    subject=ctx.principal.subject,
                    created_at=time.time(),
                )
            )
            self._audit(conn, ctx, "conversation_created")
        return identifier

    def _quota(
        self, conn, tenant: str, subject: str, dimension: str, bucket: int, ceiling: int, amount: int
    ) -> None:
        values = dict(tenant_id=tenant, subject=subject, dimension=dimension, bucket=bucket, used=0)
        constructor = pg_insert if self.postgres else sqlite_insert
        conn.execute(constructor(quotas).values(**values).on_conflict_do_nothing())
        predicate = and_(
            quotas.c.tenant_id == tenant,
            quotas.c.subject == subject,
            quotas.c.dimension == dimension,
            quotas.c.bucket == bucket,
        )
        used = conn.execute(select(quotas.c.used).where(predicate).with_for_update()).scalar_one()
        if used + amount > ceiling:
            raise LimitExceeded("SHARED_QUOTA")
        conn.execute(update(quotas).where(predicate).values(used=used + amount))

    def throttle(self, principal: Principal) -> None:
        require_live(principal)
        minute = int(time.time() // 60)
        with self.transaction(principal.tenant_id) as conn:
            # Fixed lock order avoids deadlocks between workers.
            self._quota(
                conn,
                principal.tenant_id,
                "",
                "tenant_requests",
                minute,
                self.settings.tenant_requests_per_minute,
                1,
            )
            self._quota(
                conn,
                principal.tenant_id,
                principal.subject,
                "user_requests",
                minute,
                self.settings.user_requests_per_minute,
                1,
            )

    def reserve_model_cost(self, ctx: RequestContext) -> None:
        require_live(ctx.principal)
        with self.transaction(ctx.principal.tenant_id) as conn:
            self._quota(
                conn,
                ctx.principal.tenant_id,
                "",
                "model_cost",
                int(time.time() // 86400),
                self.settings.tenant_daily_cost_units,
                self.settings.model_call_cost_units,
            )
            # Charge the configured worst-case amount even if the provider times out.
            self._audit(conn, ctx, "model_cost_reserved", cost_units=self.settings.model_call_cost_units)

    def _operation_predicate(self, principal: Principal, operation_id: str):
        return and_(
            operations.c.tenant_id == principal.tenant_id,
            operations.c.subject == principal.subject,
            operations.c.operation_id == operation_id,
        )

    def claim_operation(self, ctx: RequestContext, request: ChatRequest) -> ChatResponse | None:
        require_scope(ctx.principal, "chat:use")
        digest = self.audit.fingerprint(request.model_dump_json())
        with self.transaction(ctx.principal.tenant_id) as conn:
            self._conversation(conn, ctx.principal, request.conversation_id)
            values = dict(
                tenant_id=ctx.principal.tenant_id,
                subject=ctx.principal.subject,
                operation_id=request.operation_id,
                conversation_id=request.conversation_id,
                input_digest=digest,
                state="running",
                created_at=time.time(),
            )
            constructor = pg_insert if self.postgres else sqlite_insert
            # RETURNING, not rowcount. PostgreSQL reports rowcount -1 for
            # INSERT ... ON CONFLICT DO NOTHING, so a rowcount == 0 test is never
            # true there and every concurrent retry of one operation id claims the
            # operation and runs the turn again. RETURNING yields a row only when
            # this statement actually inserted, which is the fact we need.
            claimed_insert = conn.execute(
                constructor(operations)
                .values(**values)
                .on_conflict_do_nothing()
                .returning(operations.c.operation_id)
            ).first()
            row = (
                conn.execute(
                    select(operations)
                    .where(self._operation_predicate(ctx.principal, request.operation_id))
                    .with_for_update()
                )
                .mappings()
                .one()
            )
            # Accept any retained key version so an in-flight retry still resolves
            # to its cached response after a signing-key rotation.
            if not self.audit.matches(request.model_dump_json(), row["input_digest"]):
                raise Conflict("OPERATION_CONTENT_CHANGED")
            if row["state"] == "complete":
                # A cached answer is data from an earlier authorization decision.
                # Re-check every source document before replaying it after ACL changes.
                for doc_id in json.loads(row["output_doc_ids"] or "[]"):
                    if not conn.execute(
                        select(documents.c.doc_id).where(
                            self._document_access_predicate(
                                ctx.principal, request.conversation_id, clearance(ctx.principal)
                            ),
                            documents.c.doc_id == doc_id,
                        )
                    ).first():
                        raise Denied("RESOURCE_NOT_FOUND")
                return ChatResponse.model_validate_json(row["response"]).model_copy(
                    update={"request_id": ctx.request_id}
                )
            if claimed_insert is None:
                if row["state"] == "failed":
                    raise Unavailable("FAILED_OPERATION_REQUIRES_RECONCILIATION")
                raise Conflict("OPERATION_IN_PROGRESS")
            self._audit(
                conn, ctx, "operation_started", operation_id=request.operation_id, input_fingerprint=digest
            )
        return None

    def finish_operation(
        self,
        ctx: RequestContext,
        operation_id: str,
        response: ChatResponse | None,
        docs: list[Document] | None = None,
    ) -> None:
        with self.transaction(ctx.principal.tenant_id) as conn:
            conn.execute(
                update(operations)
                .where(self._operation_predicate(ctx.principal, operation_id))
                .values(
                    state="complete" if response else "failed",
                    response=response.model_dump_json() if response else None,
                    output_doc_ids=json.dumps([doc.doc_id for doc in (docs or [])]),
                )
            )
            self._audit(
                conn,
                ctx,
                "operation_finished",
                operation_id=operation_id,
                state="complete" if response else "failed",
            )

    def ingest(self, ctx: RequestContext, request: IngestRequest) -> None:
        require_scope(ctx.principal, "documents:write")
        if request.owner_subject is None:
            # Publishing tenant-wide knowledge is a separate privilege from a
            # customer attaching a document they own to their conversation.
            require_scope(ctx.principal, "documents:publish")
        if CLASS_LEVEL[request.classification] > clearance(ctx.principal):
            raise Denied("CLASSIFICATION_DENIED")
        if not set(request.allowed_roles) <= ctx.principal.roles or (
            request.classification != "public" and not request.allowed_roles
        ):
            raise Denied("ACL_DENIED")
        if request.owner_subject is not None and request.owner_subject != ctx.principal.subject:
            raise Denied("OWNER_DENIED")
        if (request.owner_subject is None) != (request.conversation_id is None):
            raise Denied("DOCUMENT_BINDING_REQUIRED")
        with self.transaction(ctx.principal.tenant_id) as conn:
            if request.conversation_id is not None:
                self._conversation(conn, ctx.principal, request.conversation_id)
            existing = (
                conn.execute(
                    select(documents.c.owner_subject, documents.c.conversation_id).where(
                        documents.c.tenant_id == ctx.principal.tenant_id,
                        documents.c.doc_id == request.doc_id,
                    )
                )
                .mappings()
                .first()
            )
            if existing and (
                existing["owner_subject"] != request.owner_subject
                or existing["conversation_id"] != request.conversation_id
            ):
                # Document identifiers cannot be used to replace shared policy or
                # another subject's content, even when the caller knows the ID.
                raise Denied("RESOURCE_NOT_FOUND")
            # Re-ingestion replaces ACLs and content in one transaction; the next
            # retrieval sees the new ACL. Caller cannot declare trusted provenance.
            conn.execute(
                delete(document_roles).where(
                    document_roles.c.tenant_id == ctx.principal.tenant_id,
                    document_roles.c.doc_id == request.doc_id,
                )
            )
            conn.execute(
                delete(documents).where(
                    documents.c.tenant_id == ctx.principal.tenant_id, documents.c.doc_id == request.doc_id
                )
            )
            conn.execute(
                insert(documents).values(
                    tenant_id=ctx.principal.tenant_id,
                    doc_id=request.doc_id,
                    classification=request.classification,
                    level=CLASS_LEVEL[request.classification],
                    source=request.source,
                    body=request.body,
                    owner_subject=request.owner_subject,
                    conversation_id=request.conversation_id,
                    upload_state="ready",
                    content_hash=hashlib.sha256(request.body.encode()).hexdigest(),
                    retention_policy=request.retention_policy,
                    provenance_verified=0,
                    created_at=time.time(),
                )
            )
            for role in set(request.allowed_roles):
                conn.execute(
                    insert(document_roles).values(
                        tenant_id=ctx.principal.tenant_id, doc_id=request.doc_id, role=role
                    )
                )
            self._audit(
                conn,
                ctx,
                "document_ingested",
                document_ids=[request.doc_id],
                classification=request.classification,
                upload_state="ready",
                content_hash=hashlib.sha256(request.body.encode()).hexdigest(),
                retention_policy=request.retention_policy,
                conversation_fingerprint=(
                    self.audit.fingerprint(request.conversation_id)
                    if request.conversation_id is not None
                    else None
                ),
            )

    def _document_access_predicate(self, principal: Principal, conversation_id: str, max_level: int):
        """Build the complete ACL predicate before document text is selected."""
        role_acl = exists(
            select(1).where(
                document_roles.c.tenant_id == documents.c.tenant_id,
                document_roles.c.doc_id == documents.c.doc_id,
                document_roles.c.role.in_(sorted(principal.roles)),
            )
        )
        return and_(
            documents.c.tenant_id == principal.tenant_id,
            documents.c.level <= min(clearance(principal), max_level),
            or_(documents.c.classification == "public", role_acl),
            or_(documents.c.owner_subject.is_(None), documents.c.owner_subject == principal.subject),
            or_(documents.c.conversation_id.is_(None), documents.c.conversation_id == conversation_id),
            documents.c.upload_state == "ready",
        )

    def search(
        self,
        principal: Principal,
        query: str,
        limit: int,
        max_level: int,
        conversation_id: str = "",
        attachment_ids: list[str] | None = None,
    ) -> list[Document]:
        require_scope(principal, "documents:read")
        if limit == 0:
            return []
        # Keyword search is a working baseline; vector adapters must apply these
        # same predicates before ranking. SQL parameters handle all query text.
        terms = list(dict.fromkeys(query.split()))[:8]
        attachment_ids = list(dict.fromkeys(attachment_ids or []))
        if len(attachment_ids) > limit:
            raise LimitExceeded("ATTACHMENT_LIMIT")
        access = self._document_access_predicate(principal, conversation_id, max_level)
        base = select(documents).where(access)
        with self.transaction(principal.tenant_id) as conn:
            attached_rows = []
            if attachment_ids:
                found = {
                    row["doc_id"]: row
                    for row in conn.execute(base.where(documents.c.doc_id.in_(attachment_ids))).mappings()
                }
                # A generic not-found response avoids revealing another user's document.
                if any(doc_id not in found for doc_id in attachment_ids):
                    quarantined = set(
                        conn.execute(
                            select(documents.c.doc_id).where(
                                documents.c.tenant_id == principal.tenant_id,
                                documents.c.owner_subject == principal.subject,
                                documents.c.conversation_id == conversation_id,
                                documents.c.upload_state == "quarantined",
                                documents.c.doc_id.in_(attachment_ids),
                            )
                        ).scalars()
                    )
                    if quarantined:
                        raise OutputBlocked("POISONED_DOCUMENT")
                    raise Denied("RESOURCE_NOT_FOUND")
                attached_rows = [found[doc_id] for doc_id in attachment_ids]
            if terms:
                base = base.where(or_(*(documents.c.body.icontains(term, autoescape=True) for term in terms)))
            if attachment_ids:
                base = base.where(documents.c.doc_id.not_in(attachment_ids))
            stmt = base.order_by(documents.c.doc_id).limit(
                min(limit, self.settings.max_docs) - len(attached_rows)
            )
            rows = attached_rows + list(conn.execute(stmt).mappings().all())
            result = []
            for row in rows:
                roles = frozenset(
                    conn.execute(
                        select(document_roles.c.role).where(
                            document_roles.c.tenant_id == principal.tenant_id,
                            document_roles.c.doc_id == row["doc_id"],
                        )
                    ).scalars()
                )
                result.append(
                    Document(
                        doc_id=row["doc_id"],
                        tenant_id=row["tenant_id"],
                        classification=row["classification"],
                        allowed_roles=roles,
                        source=row["source"],
                        body=row["body"],
                        owner_subject=row["owner_subject"],
                        conversation_id=row["conversation_id"],
                        upload_state=row["upload_state"],
                        content_hash=row["content_hash"],
                        retention_policy=row["retention_policy"],
                        provenance_verified=bool(row["provenance_verified"]),
                    )
                )
            return result

    def quarantine_document(self, ctx: RequestContext, doc_id: str, signals: list[str]) -> None:
        """Persist a fail-closed state so a known poisoned upload cannot be retried."""
        with self.transaction(ctx.principal.tenant_id) as conn:
            changed = conn.execute(
                update(documents)
                .where(
                    documents.c.tenant_id == ctx.principal.tenant_id,
                    documents.c.doc_id == doc_id,
                    documents.c.owner_subject == ctx.principal.subject,
                    documents.c.upload_state == "ready",
                )
                .values(upload_state="quarantined")
            )
            if changed.rowcount:
                self._audit(
                    conn,
                    ctx,
                    "document_quarantined",
                    document_ids=[doc_id],
                    signals=signals,
                    status="block",
                    upload_state="quarantined",
                    severity="high",
                )

    def attachment_results(
        self, principal: Principal, conversation_id: str, attachment_ids: list[str]
    ) -> list[dict]:
        """Return only statuses for attachments owned by this exact conversation."""
        if not attachment_ids:
            return []
        with self.transaction(principal.tenant_id) as conn:
            rows = conn.execute(
                select(documents.c.doc_id, documents.c.upload_state).where(
                    documents.c.tenant_id == principal.tenant_id,
                    documents.c.owner_subject == principal.subject,
                    documents.c.conversation_id == conversation_id,
                    documents.c.doc_id.in_(attachment_ids),
                )
            ).mappings()
            states = {row["doc_id"]: row["upload_state"] for row in rows}
        return [
            {
                "document_id": doc_id,
                "status": "quarantined" if states.get(doc_id) == "quarantined" else "rejected",
                "code": "POISONED_DOCUMENT" if states.get(doc_id) == "quarantined" else "RESOURCE_NOT_FOUND",
            }
            for doc_id in attachment_ids
        ]

    def delete_document(self, ctx: RequestContext, doc_id: str) -> None:
        require_scope(ctx.principal, "documents:write")
        with self.transaction(ctx.principal.tenant_id) as conn:
            row = conn.execute(
                select(documents.c.owner_subject).where(
                    documents.c.tenant_id == ctx.principal.tenant_id,
                    documents.c.doc_id == doc_id,
                )
            ).first()
            if row is None or (
                row.owner_subject not in (None, ctx.principal.subject)
                and "documents:admin" not in ctx.principal.scopes
            ):
                raise Denied("RESOURCE_NOT_FOUND")
            if row.owner_subject is None and "documents:admin" not in ctx.principal.scopes:
                raise Denied("MISSING_SCOPE")
            conn.execute(
                delete(document_roles).where(
                    document_roles.c.tenant_id == ctx.principal.tenant_id, document_roles.c.doc_id == doc_id
                )
            )
            conn.execute(
                delete(documents).where(
                    documents.c.tenant_id == ctx.principal.tenant_id, documents.c.doc_id == doc_id
                )
            )
            self._audit(conn, ctx, "document_deleted", document_ids=[doc_id])

    def _purge_domain_rows(self, conn, ctx: RequestContext, conversation_id: str) -> None:
        """Hook for a domain subclass to drop its own rows in the same transaction.

        The generic repository knows nothing about an application's tables, so it
        cannot delete them directly. Overriding this keeps that cleanup inside the
        one transaction that removes the conversation, instead of leaving a second
        delete to run afterwards and fail separately.
        """

    def delete_conversation(self, ctx: RequestContext, conversation_id: str) -> None:
        require_scope(ctx.principal, "chat:use")
        with self.transaction(ctx.principal.tenant_id) as conn:
            self._conversation(conn, ctx.principal, conversation_id)
            self._purge_domain_rows(conn, ctx, conversation_id)
            owned_doc_ids = select(documents.c.doc_id).where(
                documents.c.tenant_id == ctx.principal.tenant_id,
                documents.c.owner_subject == ctx.principal.subject,
                documents.c.conversation_id == conversation_id,
            )
            conn.execute(
                delete(document_roles).where(
                    document_roles.c.tenant_id == ctx.principal.tenant_id,
                    document_roles.c.doc_id.in_(owned_doc_ids),
                )
            )
            conn.execute(
                delete(documents).where(
                    documents.c.tenant_id == ctx.principal.tenant_id,
                    documents.c.owner_subject == ctx.principal.subject,
                    documents.c.conversation_id == conversation_id,
                )
            )
            conn.execute(
                delete(operations).where(
                    operations.c.tenant_id == ctx.principal.tenant_id,
                    operations.c.conversation_id == conversation_id,
                )
            )
            conn.execute(
                delete(conversations).where(
                    conversations.c.tenant_id == ctx.principal.tenant_id,
                    conversations.c.id == conversation_id,
                )
            )
            # Executed financial receipts remain under the organization's separate
            # ledger retention policy. Removing replay tombstones is an explicit choice.
            self._audit(conn, ctx, "conversation_deleted")

    def purge_expired_documents(self, ctx: RequestContext, retention_policy: str, before: float) -> int:
        """Delete expired content while retaining metadata-only audit evidence."""
        require_scope(ctx.principal, "documents:admin")
        if before > time.time() or not retention_policy:
            raise ValueError("retention cutoff must be in the past")
        tenant_id = ctx.principal.tenant_id
        with self.transaction(tenant_id) as conn:
            doc_ids = list(
                conn.execute(
                    select(documents.c.doc_id).where(
                        documents.c.tenant_id == tenant_id,
                        documents.c.retention_policy == retention_policy,
                        documents.c.created_at < before,
                    )
                ).scalars()
            )
            if doc_ids:
                conn.execute(
                    delete(document_roles).where(
                        document_roles.c.tenant_id == tenant_id,
                        document_roles.c.doc_id.in_(doc_ids),
                    )
                )
                conn.execute(
                    delete(documents).where(
                        documents.c.tenant_id == tenant_id,
                        documents.c.doc_id.in_(doc_ids),
                    )
                )
            self._audit(
                conn,
                ctx,
                "retention_purge",
                count=len(doc_ids),
                retention_policy=retention_policy,
                status="OK",
                severity="info",
            )
        return len(doc_ids)

    def close(self):
        self.engine.dispose()
