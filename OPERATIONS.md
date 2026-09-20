# Operations runbook

This document states the facts an operator needs and the decisions a deployment
has to make. It does not set your recovery targets: those follow from the value
of the data and the contracts you have signed, and a number invented here would
only look authoritative.

## Deployment gate

Run these before a rollout is considered done. Each fails loudly; none of them is
advisory.

```powershell
boundedllm migrate                 # versioned schema, never at application startup
boundedllm enable-rls              # as the table-owning migration role
boundedllm check-production        # as the application role, which must NOT own the tables
boundedllm audit verify --tenant <tenant>   # exit 2 means the chain is broken
```

`check-production` refuses a superuser, a `BYPASSRLS` role, an application role
that owns its own tables, any table without `FORCE ROW LEVEL SECURITY`, and a
connection without TLS. Ownership matters because a table owner bypasses RLS
unless it is forced, so the application role must be distinct from the migration
role.

## Roles and least privilege

| Role | Owns tables | Runs | Needs |
|---|---|---|---|
| migration | yes | `migrate`, `enable-rls` | DDL, used only during rollout |
| application | no | the service | `SELECT, INSERT, UPDATE, DELETE` |
| audit reader | no | `audit list/verify/export` | `SELECT` on `guard_audit*` |
| retention | no | `retention-purge` | `DELETE` on `guard_documents*` |

Give the application role no DDL. A migration that runs as the application role
means an application-level compromise can rewrite its own constraints.

## Backup and recovery

**What the database holds.** Conversations, documents and their ACLs, accounts,
pending and executed actions with receipts, quotas, and the signed audit ledger
with its outbox. Losing the ledger loses the evidence that the rest was
authorized, so it is the most valuable table, not the least.

**Backup.** Take PITR-capable backups (`pg_basebackup` plus WAL archiving, or the
managed equivalent). Store them encrypted, in a different failure domain from the
primary, with retention at least as long as your audit retention obligation. Back
up the **audit signing keys separately** from the database: a restored ledger you
cannot verify is not evidence.

**Restore drill.** Restore into an isolated database and run, in order:

```powershell
boundedllm check-production
boundedllm audit verify --tenant <tenant>   # must exit 0
```

A restore that reports `"valid": false` means the backup is torn or the key set
is wrong. Diagnose before promoting it. Test this on a schedule; an untested
backup is a hypothesis.

**Choosing RPO.** The ledger is append-only and chained, so a restore to any
point in time yields a valid prefix — losing the last N seconds loses evidence,
not consistency. Financial receipts commit in the same transaction as their audit
record, so a restored database never shows money moved without the record that
authorized it.

**Choosing RTO.** The service is stateless apart from the database and the
per-process concurrency counter, so recovery time is essentially database
recovery time plus rollout. Run `migrate` before bringing instances back.

**After any restore**, reconcile operations left in `failed` state. Those are
turns whose outcome is genuinely unknown; the design refuses to retry them
automatically because a duplicate execution is worse than a delayed one.

## Audit key ceremony

The signing key proves the ledger has not been altered. Treat it as evidence
material.

**Generating.** At least 32 random bytes from a CSPRNG, produced inside the
secret manager or an HSM, never on a laptop and never in shell history.

**Rotating.**

1. Generate the new key and add it to the secret store.
2. Set `GUARD_AUDIT_KEY` to the new value, `GUARD_AUDIT_KEY_ID` to a new
   identifier, and add the **previous** key to `GUARD_AUDIT_PREVIOUS_KEYS`.
3. Roll out. Verify: `boundedllm audit verify --tenant <tenant>` must still exit 0
   and report `unverifiable_key_versions: 0`.

**Retaining.** Keep every retired key for as long as you retain the records it
signed. Retention is not optional bookkeeping: pending approval arguments and
operation idempotency digests are verified against retained keys, so dropping one
early strands unredeemed approvals and turns in-flight retries into conflicts.

**Correlation across rotation.** `subject_fingerprint` is derived from the
signing key by default, so it changes when the key does and an analyst loses the
thread across the boundary. Set `GUARD_AUDIT_PSEUDONYM_KEY` to a separate,
long-lived secret if that continuity matters. That key is a re-identification
risk of its own — it maps a fingerprint back to a subject for anyone who holds it
and the subject list — so scope it at least as tightly as the signing key.

**Compromise.** A leaked signing key means records after the leak can be forged.
Rotate immediately, then treat the chain from the last externally anchored
checkpoint forward as unverified. This is what `audit checkpoint` and archiving
signed exports to retention-locked storage are for: they bound the damage to the
window since the last anchor.

## Capacity and limits

**`max_concurrent_requests` is per process.** It protects one worker's memory. It
is not a shared ceiling, and N replicas allow N times that number. Shared limits
live behind the `Quotas` port and are durable:
`user_requests_per_minute`, `tenant_requests_per_minute`, and
`tenant_daily_cost_units`. Set edge rate limits as well; the first defence should
not be a database round trip.

**The database thread pool is the real throughput ceiling.** The bundled SQL
adapter is synchronous SQLAlchemy behind `asyncio.to_thread`, so the event loop's
default executor bounds concurrent database work. Size it deliberately:

```python
import asyncio, concurrent.futures
loop = asyncio.get_running_loop()
loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=64))
```

Keep it at or below the database connection pool; more threads than connections
converts throughput into lock contention.

**Model cost** is reserved before each call at the configured worst case and is
not refunded on a provider timeout. That is deliberate: a failed call still costs
money upstream.

## Monitoring

Alert on these. They are the signals that mean something is wrong rather than
merely busy.

| Signal | Why |
|---|---|
| `audit verify` exit 2 | Ledger tampered, torn, or missing a key |
| `request_blocked` rate change | An attack campaign, or a control misfiring on real traffic |
| `document_quarantined` | Poisoned content reached retrieval |
| Outbox depth / `attempts` rising | Ledger is not reaching the SIEM |
| `ACL_INVARIANT_VIOLATION` | A retrieval adapter is returning unauthorized rows — page someone |
| `DLP_FAILURE` | Scanner down; turns are failing closed, which is correct but visible |
| Operations stuck in `failed` | Unreconciled turns of unknown outcome |
| `SHARED_QUOTA` / `REQUEST_BUDGET` | Runaway agent loop or cost abuse |

`ACL_INVARIANT_VIOLATION` deserves special handling: it means a port returned a
document the caller was not entitled to and the tripwire caught it. Treat it as a
potential data-exposure incident, not a bug report.

## Incident response

1. **Contain.** Revoke the affected principal's tokens at the identity provider.
   The service holds no session state of its own; `expires_at` on the principal is
   checked at each step, so revocation takes effect within token lifetime. Shorten
   `max_token_lifetime_seconds` if that window is too wide.
2. **Preserve.** `boundedllm audit export --tenant <tenant> --output <file>` writes
   signed envelopes to a new file; it refuses to overwrite existing evidence.
   Copy it to retention-locked storage before further work.
3. **Scope.** `boundedllm audit list --tenant <tenant> --severity high --since <ts>`
   and `audit show <event_id>`. Events carry fingerprints, not content, so
   correlating a subject requires the pseudonym key and the subject list together.
4. **Quarantine.** `boundedllm quarantine list --tenant <tenant>` for documents held
   back from retrieval. Metadata and hashes only; extracted text is never returned.
5. **Record.** `POST /api/security/events/{id}/case` links an event to your case
   system. The ledger stores the state and an external case id, never analyst
   free text.

## What this deployment still owes

A real OIDC provider, TLS termination, edge rate limits, secret management, an
SBOM and dependency scanning, log shipping, retention enforcement, and an
independent security review. None of those are in this repository, and the
package assumes all of them.
