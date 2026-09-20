"""Administrative schema commands and a deterministic offline demonstration."""

import argparse
import asyncio
import json
import re
import secrets
import sys
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from sqlalchemy import insert
from sqlalchemy.exc import SQLAlchemyError

from agentguard.adapters.sql import sql_ports
from agentguard.audit import Audit
from agentguard.config import Settings
from agentguard.engine import Guard
from agentguard.errors import GuardError
from agentguard.model_gateway import ModelRequest
from agentguard.models import ChatRequest, IngestRequest, Principal
from agentguard.support import SupportPolicy, SupportSQLStore, ToolGateway
from agentguard.support.schema import accounts

# Distinct exit codes so a monitor can tell the outcomes apart:
#   1 the command could not run (bad arguments, unreachable database)
#   2 the ledger failed verification
#   3 a guard control refused the operation, e.g. an over-privileged role
EXIT_INTEGRITY_FAILED = 2
EXIT_GUARD_REFUSED = 3


class DemoProvider:
    """Predictable local fixture, never a production model or authentication bypass."""

    async def complete(self, request: ModelRequest) -> str:
        if "waive" in request.user.lower():
            return json.dumps(
                {
                    "answer": "",
                    "tool_call": {
                        "name": "waive_fee",
                        "arguments": {
                            "account_id": "acct_abcdefghij",
                            "amount_cents": 4500,
                            "reason": "Customer service adjustment",
                        },
                    },
                }
            )
        return json.dumps({"answer": "Support hours are 09:00-17:00 UTC on weekdays.", "tool_call": None})


async def demo():
    with tempfile.TemporaryDirectory(prefix="agentguard-demo-") as directory:
        settings = Settings(
            database_url=f"sqlite:///{Path(directory) / 'demo.db'}", audit_key=secrets.token_hex(32)
        )
        audit = Audit(settings.audit_key.get_secret_value())
        store = SupportSQLStore(settings, audit)
        store.initialize()
        ports = sql_ports(store)
        policy = SupportPolicy()
        guard = Guard(
            provider=DemoProvider(),
            signer=audit,
            limits=settings.limits(),
            tool_executor=ToolGateway(ports["documents"], policy),
            **ports,
        )
        principal = Principal(
            subject="demo-user",
            tenant_id="demo-tenant",
            roles=frozenset({"support"}),
            scopes=frozenset(
                {
                    "chat:use",
                    "documents:read",
                    "documents:write",
                    "documents:publish",
                    "accounts:read",
                    "fees:waive",
                    "actions:approve",
                }
            ),
            expires_at=time.time() + 600,
        )
        ctx = guard.context(principal)
        conversation = store.create_conversation(ctx)
        store.ingest(
            ctx,
            IngestRequest(
                doc_id="support-hours",
                classification="internal",
                allowed_roles=["support"],
                source="policy_wiki",
                body="Support hours are 09:00-17:00 UTC on weekdays.",
            ),
        )
        # Account onboarding belongs to your existing trusted enterprise service,
        # never to a model proposal or an unauthenticated HTTP endpoint.
        with store.transaction(principal.tenant_id) as conn:
            conn.execute(
                insert(accounts).values(
                    tenant_id=principal.tenant_id,
                    account_id="acct_abcdefghij",
                    owner_subject=principal.subject,
                    status="active",
                    currency="USD",
                    fee_cents=10000,
                    version=1,
                )
            )
        try:
            first = await guard.chat(
                principal,
                ChatRequest(
                    message="What are support hours?", conversation_id=conversation, operation_id=uuid4().hex
                ),
            )
            print(first.model_dump_json(indent=2))
            action = await guard.chat(
                principal,
                ChatRequest(
                    message="Please waive my fee.", conversation_id=conversation, operation_id=uuid4().hex
                ),
            )
            print(action.model_dump_json(indent=2))
            if action.pending_action_id:
                print(store.pending_action(principal, action.pending_action_id).model_dump_json(indent=2))
                # The demo explicitly simulates a human's separate confirmation.
                print(json.dumps(store.approve(ctx, action.pending_action_id, policy), indent=2))
                print(json.dumps(store.approve(ctx, action.pending_action_id, policy), indent=2))
                print("Fee remaining:", store.get_account(principal, "acct_abcdefghij").fee_cents)
        finally:
            store.close()


IDENTIFIER = r"[A-Za-z0-9_.:@/-]{1,128}"


def identifier(value: str) -> str:
    """Reject identifiers the data model would refuse before they reach a query."""
    if not re.fullmatch(IDENTIFIER, value):
        raise argparse.ArgumentTypeError("must be 1-128 characters from [A-Za-z0-9_.:@/-]")
    return value


def operator_principal(tenant: str, operator: str, scopes: set[str]) -> Principal:
    """Bind a privileged command to the human running it.

    The CLI authenticates through database credentials and shell access, not a
    token, so it cannot verify who is at the keyboard. Recording the operator the
    caller names is still the difference between an audit trail that says a
    destructive purge happened and one that says who to ask about it. Deployments
    that need this to be unforgeable should run these commands through a job
    runner that injects the operator from its own verified identity.
    """
    return Principal(
        subject=operator,
        tenant_id=tenant,
        roles=frozenset({"security_admin"}),
        scopes=frozenset(scopes),
        expires_at=time.time() + 60,
    )


def main():
    """Entry point. Guard failures exit non-zero with a reason code, not a traceback.

    An administrative command runs in CI, cron, and change windows, where a
    stack trace is noise that also prints absolute filesystem paths into a build
    log. The reason code is the stable contract; the exit status is what a
    monitor reads.
    """
    try:
        _run()
    except GuardError as exc:
        print(f"{exc.code}", file=sys.stderr)
        raise SystemExit(EXIT_GUARD_REFUSED) from None
    except SQLAlchemyError as exc:
        # Running a command before "agentguard migrate" is the common first-run
        # mistake, and the raw driver error is a wall of SQL and absolute paths.
        # Say what to do instead, and keep the filesystem out of the log.
        missing = "no such table" in str(exc).lower() or "does not exist" in str(exc).lower()
        if missing:
            print(
                "database schema is missing or out of date; run 'agentguard migrate' first",
                file=sys.stderr,
            )
        else:
            print("database unavailable; check GUARD_DATABASE_URL and connectivity", file=sys.stderr)
        raise SystemExit(1) from None


def _run():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("demo", "init-db", "enable-rls", "check-production"):
        commands.add_parser(name)

    migrate_parser = commands.add_parser(
        "migrate", help="Apply versioned Alembic migrations (the production path)"
    )
    migrate_parser.add_argument("--revision", default="head")
    stamp_parser = commands.add_parser(
        "stamp", help="Record a revision without running it, for a pre-Alembic database"
    )
    stamp_parser.add_argument("--revision", default="head")

    audit_parser = commands.add_parser("audit", help="Inspect the metadata-only security ledger")
    audit_commands = audit_parser.add_subparsers(dest="audit_command", required=True)
    for name in ("list", "verify", "stats", "export", "checkpoint"):
        child = audit_commands.add_parser(name)
        child.add_argument("--tenant", required=True, type=identifier)
        child.add_argument("--limit", type=int, default=1000 if name == "export" else 100)
        if name == "list":
            child.add_argument("--event-type")
            child.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"])
            child.add_argument("--model")
            child.add_argument("--subject-fingerprint")
            child.add_argument("--since", type=float, help="Unix timestamp, inclusive lower bound")
            child.add_argument("--until", type=float, help="Unix timestamp, inclusive upper bound")
        if name == "export":
            child.add_argument("--output", type=Path, required=True)
        if name == "checkpoint":
            child.add_argument(
                "--operator", required=True, type=identifier, help="Identity recorded in the ledger"
            )
    show = audit_commands.add_parser("show")
    show.add_argument("event_id")
    show.add_argument("--tenant", required=True, type=identifier)

    quarantine = commands.add_parser("quarantine", help="Inspect quarantined document metadata")
    quarantine_commands = quarantine.add_subparsers(dest="quarantine_command", required=True)
    quarantine_list = quarantine_commands.add_parser("list")
    quarantine_list.add_argument("--tenant", required=True, type=identifier)
    quarantine_list.add_argument("--limit", type=int, default=100)
    quarantine_inspect = quarantine_commands.add_parser("inspect")
    quarantine_inspect.add_argument("document_id")
    quarantine_inspect.add_argument("--tenant", required=True, type=identifier)

    outbox = commands.add_parser("outbox-export", help="Deliver pending records to OTLP/HTTP")
    outbox.add_argument("--tenant", required=True, type=identifier)
    outbox.add_argument("--limit", type=int, default=100)

    retention = commands.add_parser("retention-purge", help="Delete expired document content")
    retention.add_argument("--tenant", required=True, type=identifier)
    retention.add_argument(
        "--operator", required=True, type=identifier, help="Identity recorded in the ledger"
    )
    retention.add_argument(
        "--yes", action="store_true", help="Confirm this irreversible deletion of document content"
    )
    retention.add_argument("--policy", required=True)
    retention.add_argument("--before-unix", type=float, required=True)
    args = parser.parse_args()
    if args.command == "demo":
        asyncio.run(demo())
        return
    settings = Settings()
    store = SupportSQLStore(settings, Audit.from_settings(settings))
    try:
        if args.command == "init-db":
            # Development convenience. Production runs "migrate", which leaves a
            # reviewable history instead of creating tables from live models.
            store.initialize()
        elif args.command == "migrate":
            from agentguard.adapters.sql import migrate

            migrate(args.revision)
            print(json.dumps({"migrated_to": args.revision}))
            return
        elif args.command == "stamp":
            from agentguard.adapters.sql import stamp

            stamp(args.revision)
            print(json.dumps({"stamped": args.revision}))
            return
        elif args.command == "enable-rls":
            if not store.postgres:
                raise ValueError("RLS requires PostgreSQL")
            import agentguard.support.schema  # noqa: F401  registers domain tables
            from agentguard.adapters.sql.schema import metadata

            with store.engine.begin() as conn:
                for table in metadata.tables.values():
                    # Table names come exclusively from static package metadata.
                    conn.exec_driver_sql(f'ALTER TABLE "{table.name}" ENABLE ROW LEVEL SECURITY')
                    conn.exec_driver_sql(f'ALTER TABLE "{table.name}" FORCE ROW LEVEL SECURITY')
                    conn.exec_driver_sql(f'DROP POLICY IF EXISTS guard_tenant_policy ON "{table.name}"')
                    conn.exec_driver_sql(
                        f'CREATE POLICY guard_tenant_policy ON "{table.name}" '
                        "USING (tenant_id = current_setting('app.tenant_id', true)) "
                        "WITH CHECK (tenant_id = current_setting('app.tenant_id', true))"
                    )
        elif args.command == "check-production":
            store.verify_production()
        elif args.command == "audit":
            if args.audit_command == "list":
                value = store.list_audit_events(
                    args.tenant,
                    limit=args.limit,
                    event_type=args.event_type,
                    severity=args.severity,
                    model=args.model,
                    subject_fingerprint=args.subject_fingerprint,
                    since=args.since,
                    until=args.until,
                )
            elif args.audit_command == "show":
                value = store.get_audit_event(args.tenant, args.event_id)
                if value is None:
                    raise SystemExit("audit event not found")
            elif args.audit_command == "verify":
                value = store.verify_audit_chain(args.tenant)
                if not value["valid"]:
                    # A scheduled integrity check is worthless if a tampered
                    # ledger still exits 0. Report the evidence, then fail.
                    print(json.dumps(value, indent=2, sort_keys=True))
                    raise SystemExit(EXIT_INTEGRITY_FAILED)
            elif args.audit_command == "stats":
                value = store.audit_stats(args.tenant)
            elif args.audit_command == "checkpoint":
                from agentguard.models import RequestContext

                value = store.create_audit_checkpoint(
                    RequestContext(
                        request_id=uuid4().hex,
                        principal=operator_principal(args.tenant, args.operator, {"security:audit"}),
                    )
                )
            else:
                rows = store.export_audit_events(args.tenant, args.limit)
                # Exclusive creation avoids accidentally overwriting prior evidence.
                with args.output.open("x", encoding="utf-8", newline="\n") as handle:
                    for row in rows:
                        handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
                value = {"exported": len(rows), "output": str(args.output)}
            print(json.dumps(value, indent=2, sort_keys=True))
            return
        elif args.command == "quarantine":
            if args.quarantine_command == "list":
                value = store.list_quarantined_documents(args.tenant, args.limit)
            else:
                value = store.inspect_quarantined_document(args.tenant, args.document_id)
                if value is None:
                    raise SystemExit("quarantined document not found")
            print(json.dumps(value, indent=2, sort_keys=True))
            return
        elif args.command == "outbox-export":
            if not settings.otel_logs_endpoint:
                raise SystemExit("GUARD_OTEL_LOGS_ENDPOINT is required")
            from agentguard.telemetry import OpenTelemetryHTTPSink, export_pending

            authorization = (
                settings.otel_authorization.get_secret_value() if settings.otel_authorization else None
            )
            count = export_pending(
                store,
                args.tenant,
                OpenTelemetryHTTPSink(settings.otel_logs_endpoint, authorization),
                args.limit,
            )
            print(json.dumps({"exported": count, "tenant_id": args.tenant}))
            return
        elif args.command == "retention-purge":
            from agentguard.models import RequestContext

            if not args.yes:
                raise SystemExit("refusing to delete document content without --yes")
            count = store.purge_expired_documents(
                RequestContext(
                    request_id=uuid4().hex,
                    principal=operator_principal(args.tenant, args.operator, {"documents:admin"}),
                ),
                args.policy,
                args.before_unix,
            )
            print(json.dumps({"deleted": count, "tenant_id": args.tenant}))
            return
        print("Completed:", args.command)
    finally:
        store.close()


if __name__ == "__main__":
    main()
