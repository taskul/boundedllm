# BoundedLLM

**Bounds what a compromised agent can reach and do.**

The model is treated as an untrusted proposal generator that may already have been
manipulated. Verified identity, tenant isolation, retrieval ACLs, action policy,
human consent, idempotency, quotas, transactions, and egress are deterministic
application code, so they hold whether or not an injection succeeded.

This is deliberately not a prompt-injection detector. It does not compete with a
classifier on detection rates, and the bundled heuristics are signals rather than
controls — [`SECURITY.md`](SECURITY.md) draws that line explicitly and lists what
this package does not do. The claim it does make is the one nobody else makes
well: when the model is turned against you, the blast radius is bounded by code
that never asked the model anything.

| | |
|---|---|
| Start here | [`QUICKSTART.md`](QUICKSTART.md) — ten minutes, three steps |
| Core install | `pydantic` only — no database, HTTP client, or web framework |
| Storage | Yours, via five protocols in `agentguard.ports`; a SQL adapter is bundled |
| Assurance | No third-party audit yet; see [`SECURITY.md`](SECURITY.md#assurance-status) |
| Operating it | [`OPERATIONS.md`](OPERATIONS.md) — keys, backups, limits, incidents |
| Changes | [`CHANGELOG.md`](CHANGELOG.md) — semver, 0.x minors may break |

The design rests on seven invariants:

1. The model never authenticates a caller.
2. The model never grants permission.
3. Retrieval predicates include tenant, owner, conversation, role, state, and classification before data is loaded.
4. Prompts contain no security secrets.
5. Tool proposals are strict JSON and are re-authorized against database facts.
6. Complete output is untrusted and is inspected before release.
7. Outbound links, images, HTML, URI schemes, and bare hostnames are rejected by default.

It also handles the cases that illustrative examples in this area usually skip. Operation IDs make retries idempotent across HTTP requests. Approval and the monetary update commit together. An account version change invalidates a stale approval. Malformed model JSON is never repaired into a success. Hidden Unicode payloads are quarantined. A cached response is re-checked against current source-document visibility before it is replayed.

## Run the offline demo

The demo uses a temporary SQLite database and a deterministic fixture model. It is useful for understanding the flow and never bypasses authentication in the API.

```powershell
uv sync --system-certs
.venv\Scripts\python.exe -m agentguard.cli demo
```

The package is also installed as `agentguard demo` after `uv sync`. The output shows a read response, a pending fee-waiver action, the exact stored action, a receipt after approval, and the same receipt on a replay. The fee is decremented once.

## Embed it in an existing service

The core owns no storage. It depends on five small contracts in `agentguard.ports`,
which you implement over the systems you already run — your document store, your
vector index, your audit pipeline, your rate limiter. Importing `agentguard` pulls
in Pydantic and nothing else: no database driver, no HTTP client, no web framework.

```python
from agentguard import ChatRequest, Guard, Limits, Principal

# Implement the ports over what you already have. Enforce authorization inside
# the query, and raise on failure — returning [] reads as "nothing matched" and
# silently widens what the model is told.
class OurDocuments:            # your pgvector / Elasticsearch / S3 index
    async def search(self, principal, query, limit, max_level, conversation_id, attachment_ids): ...
    async def quarantine(self, ctx, doc_id, signals): ...
    async def attachment_results(self, principal, conversation_id, attachment_ids): ...

class OurLedger:               # your Splunk / Datadog / Kafka pipeline
    async def event(self, ctx, event, **fields): ...

guard = Guard(
    provider=OurModelProvider(),   # your approved vendor SDK
    signer=OurSigner(),            # keyed pseudonymization for correlation values
    ledger=OurLedger(),
    quotas=OurQuotas(),            # durable and shared; a process-local counter is not a quota
    operations=OurOperations(),    # idempotency keyed on the client's operation_id
    documents=OurDocuments(),
    tool_executor=OurTools(),      # there is no default registry
    limits=Limits(model_name="your-model", allowed_models=frozenset({"your-model"})),
    system_policy=YOUR_VERSIONED_COMPANY_POLICY,
)

# Your OIDC middleware verifies signature, issuer, audience, expiry, and provider-specific
# claims, then constructs this immutable Principal. Do not construct it from JSON body data.
response = await guard.chat(principal, ChatRequest(
    message="What is my account status?", conversation_id=conversation_id,
    operation_id=operation_id, attachment_ids=[uploaded_document_id]
))
```

If you would rather the package own its storage, install the `sql` extra and use
the bundled adapter instead of writing any of the above:

```python
from agentguard import Audit, Guard
from agentguard.adapters.sql import SQLStore, sql_ports

audit = Audit(key)
store = SQLStore(settings, audit)      # agentguard migrate creates the tables
guard = Guard(provider=provider, signer=audit, limits=settings.limits(), **sql_ports(store))
```

`agentguard.contrib` supplies working implementations for common infrastructure, so
the ports above are usually a one-line import rather than something you write:

| Port | Module | Extra |
|---|---|---|
| `Documents` | `contrib.pgvector` — PostgreSQL + pgvector, ACL predicates inside the ranked query | `[pgvector]` |
| `ModelProvider` | `contrib.anthropic` — Claude via the official SDK, structured outputs | `[anthropic]` |
| `Ledger` | `contrib.ledger` — `StructuredLogLedger`, `TeeLedger`, `BufferedHTTPLedger` | none |

Read one before you use it. They are starting points with the security-relevant
decisions marked, not components to trust unexamined. The pgvector adapter in
particular exists to demonstrate the thing vector retrieval most often gets wrong:
it filters inside the ranked query rather than filtering the results, because
ordering over rows the caller cannot read leaks their content through rank
position even when those rows are dropped afterwards.

`agentguard.support` is a complete worked example of one business domain — accounts,
a fee-waiver policy, a tool registry, tables, and the consent/execution cycle. It is
there to be read and copied, not extended in place; nothing in the core imports it.

A custom document port must enforce tenant, owner, conversation, role, state, and
classification predicates in its own query. `secure_search` re-checks every row it
returns and fails the turn closed on an unauthorized document or a missing explicit
attachment — a tripwire for the adapter most likely to be swapped for a vector
database, not a substitute for filtering at the source.

Two controls are opt-in because their defaults trade usability for safety and that
choice belongs to the deployment. `Limits(citation_hosts={"help.example.com"})`
permits a model to name exactly those hosts, for products that must cite their own
help centre; an allowlisted host is also an allowlisted exfiltration channel, so
prefer mapping an authorized document ID to a server-generated link where you can.
`SupportPolicy(require_separate_approver=True)` requires the approving subject to
differ from the proposing one, which the default does not: the default guarantees
only that the *model* cannot approve, not that a stolen session cannot.

The RoadShield application is only a consumer of the package. Production applications import from `agentguard`; they do not depend on RoadShield, FastAPI, Claude, or a particular agent framework. A LangGraph, CrewAI, Semantic Kernel, custom MCP host, background agent, or ordinary SaaS request handler can place the same `Guard` call immediately before its model boundary. The provider receives minimized authorized context, and the host receives only inspected `ChatResponse` data and deterministic tool decisions.

For application-specific actions, inject a `ToolExecutor`. It receives the verified request context, original idempotent request, untrusted proposal, and risk flags. The adapter must validate a strict per-tool argument schema, reload authorization facts, apply policy and approval, execute with least-privilege credentials, and return the narrow `ToolExecutionResult` contract. There is no default gateway: a proposal with no registered executor is denied, so an unconfigured host cannot accidentally act. `COMPLETE` lets a trusted adapter finish a mutation with an authoritative inspected receipt; `OK` feeds a minimized read result back to the model.

## Customer uploads and explicit attachment binding

Shared enterprise knowledge and customer uploads use different privileges. `documents:publish` is required to create shared knowledge. A customer upload uses `documents:write` and must set `owner_subject` to the authenticated subject and `conversation_id` to a conversation owned by that subject. The store rejects attempts to assign another owner, cross a conversation, or replace an existing shared or foreign document ID.

Every stored document carries `tenant_id`, `owner_subject`, `conversation_id`, `classification`, `upload_state`, a SHA-256 `content_hash`, and `retention_policy`. Document text is selected only after every access predicate passes. Put an uploaded ID in `ChatRequest.attachment_ids` to bind it to the turn. Explicit attachments are selected before ranked knowledge, and the response reports `used`, `quarantined`, or `rejected`. A foreign ID receives the same generic result as a nonexistent ID.

The library accepts text at its ingestion boundary. File-format validation, antivirus or content-disarm processing, and text extraction belong in the host adapter. RoadShield demonstrates a PDF adapter that rejects active PDF features, minimizes PII, detects instruction-override signals, and quarantines suspicious text before a model call.

## Security ledger, OpenTelemetry, and SIEM

Every guard decision is stored as metadata-only JSON. Raw prompts, model responses, files, tokens, credentials, and PII are excluded. Each tenant has a monotonically increasing sequence, previous-record hash, record hash, HMAC signature, and signing `key_id`. This detects modification, removal, reordering, duplication, and truncation while the latest head or an externally archived checkpoint remains trusted.

The audit record and `guard_audit_outbox` entry commit together. `agentguard outbox-export` sends pending signed envelopes to an OTLP/HTTP Logs endpoint with at-least-once delivery. A collector or SIEM deduplicates with `security.event_id`. Records are acknowledged only after a successful collector response and only when the event ID and record hash still match.

For request traces and metrics, install `agentguard[telemetry]`, configure the OpenTelemetry SDK and exporters in the host, and pass `OpenTelemetryObservability()` as the `observability` argument to `Guard`. The hook creates `agentguard.chat` spans, safe decision events, a request counter, and a duration histogram. It does not install global providers or read exporter secrets. Telemetry failure cannot bypass or reverse a guard decision; the transactional signed ledger remains authoritative.

```powershell
$env:GUARD_OTEL_LOGS_ENDPOINT = "https://otel.example.com/v1/logs"
$env:GUARD_OTEL_AUTHORIZATION = "Bearer collector-credential"
agentguard outbox-export --tenant tenant-a --limit 250
```

Run the exporter continuously under a dedicated service identity or schedule bounded batches. Archive the signed NDJSON stream and checkpoints in retention-locked object storage. The operational database and SIEM support investigation, while the independent archive anchors ledger integrity. `audit checkpoint` adds a signed head checkpoint to the chain and outbox.

Signing-key rotation changes `GUARD_AUDIT_KEY` and `GUARD_AUDIT_KEY_ID`. Retain earlier keys through the secret `GUARD_AUDIT_PREVIOUS_KEYS` JSON mapping for the required verification window. Removing an old key makes its signatures unverifiable, while hash-chain continuity remains checkable.

Retaining the previous key is not optional bookkeeping. Pending approval arguments and operation idempotency digests are verified against every retained key version, so dropping an old key too early strands unredeemed approvals and turns in-flight retries into conflicts. Set `GUARD_AUDIT_PSEUDONYM_KEY` to a separate long-lived secret if analysts must correlate one subject's events across a rotation; without it, `subject_fingerprint` changes when the signing key does.

## Audit, quarantine, and retention CLI

The administrative CLI reads only security metadata:

```powershell
agentguard audit list --tenant tenant-a --severity high --limit 100
agentguard audit list --tenant tenant-a --event-type request_blocked --since 1787000000
agentguard audit show EVENT_ID --tenant tenant-a
agentguard audit verify --tenant tenant-a
agentguard audit stats --tenant tenant-a
agentguard audit checkpoint --tenant tenant-a --operator alice@example.com
agentguard audit export --tenant tenant-a --output tenant-a-audit.ndjson
agentguard quarantine list --tenant tenant-a
agentguard quarantine inspect DOCUMENT_ID --tenant tenant-a
agentguard retention-purge --tenant tenant-a --operator alice@example.com --policy customer-upload-30d --before-unix 1787000000 --yes
```

`audit export` creates a new file exclusively so prior evidence is not overwritten. Use separate privileged database credentials for administrative commands. Quarantine inspection returns metadata and hashes rather than document text.

`audit verify` exits `0` when the chain is intact and `2` when it is not, so a scheduled integrity check fails visibly instead of printing a problem nobody reads. Exit `1` still means the command could not run.

Commands that write to the ledger require `--operator`, which is recorded as the acting subject. The CLI authenticates through database credentials and shell access, so it cannot prove who is at the keyboard; the value makes a destructive action attributable rather than anonymous. Run these through a job runner that injects the operator from its own verified identity when that attribution has to be unforgeable.

Retention labels do not silently delete content. Schedule `retention-purge` from the organization’s approved policy, and pass `--yes` to confirm the deletion. It removes expired document content and ACLs while retaining the metadata-only event documenting the purge.

## Run the API

Development (SQLite and the pattern scanner are allowed for local testing):

```powershell
$env:GUARD_AUDIT_KEY = python -c "import secrets; print(secrets.token_urlsafe(48))"
$env:GUARD_MODEL_URL = "https://model.example.com/v1/complete"
$env:GUARD_ISSUER = "https://id.example.com/"
$env:GUARD_JWKS_URL = "https://id.example.com/.well-known/jwks.json"
.venv\Scripts\python.exe -m uvicorn "agentguard.main:create_app" --factory
```

The model endpoint contract is a bounded HTTPS `POST` accepting `model`, `system`, `user`, `max_output_tokens`, and `temperature`, and returning exactly `{ "text": "..." }`. Keep vendor credentials in the host secret manager. A host can pass a reviewed, versioned `system_policy` to `Guard` for company-specific behavior; the prompt guides the model while identity, retrieval ACLs, schemas, tools, DLP, and egress remain enforced outside it. The API disables redirects and ambient proxy variables, caps request bodies, rejects compressed bodies, requires JSON, disables interactive API documentation, and emits CSP/security headers.

## Production deployment

Set `GUARD_ENVIRONMENT=production`, use `postgresql+psycopg://...`, set an explicit `GUARD_ALLOWED_TENANTS` value, and configure `GUARD_MODEL_URL`, a reviewed `GUARD_AUDIT_KEY`, and a real DLP backend. `GUARD_DLP_BACKEND=presidio` uses the bundled Presidio integration; `GUARD_DLP_BACKEND=reviewed` requires you to pass your own evaluated `Scanner` to `create_app`, which is the right choice where Presidio's footprint or false-negative profile is unacceptable. `pattern` is refused in production. Run the migration as an administrator during deployment:

```powershell
agentguard migrate           # versioned Alembic revisions; never runs at app startup
agentguard enable-rls        # as the table-owning migration role
agentguard check-production  # as the application role, which must not own the tables
```

`init-db` creates tables directly from the models and is a development
convenience. Production uses `migrate`, which leaves a reviewable history. For a
database created before migrations existed, run `agentguard stamp` once to record
the baseline, then `migrate` from then on.

[`OPERATIONS.md`](OPERATIONS.md) covers role separation, backup and restore
drills, the audit key ceremony, capacity limits, monitoring signals, and incident
response.

Install the optional DLP dependencies in the production image (`uv sync --extra pii --locked`) and provision the language model assets required by your Presidio deployment. The API factory refuses pattern-only DLP in production either way.

The application role must not be a PostgreSQL superuser, `BYPASSRLS` role, or table owner. `check-production` verifies this, `FORCE ROW LEVEL SECURITY` on every table, and TLS for the current connection. Migrations and privilege grants are deployment responsibilities; the application never creates production tables at startup. Put PostgreSQL behind private networking, enforce TLS certificate verification, run the container as non-root with a read-only filesystem, pin and scan dependencies, and publish an SBOM.

RLS uses `SET LOCAL app.tenant_id` on every transaction. The value is derived from the verified token and cannot persist in a pooled connection. The app also includes tenant predicates in every query because RLS and application checks should independently fail closed.

## API lifecycle

`POST /conversations` creates a caller-owned conversation. `POST /chat` requires `chat:use`, verifies the conversation belongs to the caller, canonicalizes input, blocks high-confidence hidden payloads, minimizes input, retrieves only allowed documents, applies a reduced step-up tier to suspicious input, reserves shared model cost, and bounds model/tool/document counts per request. Read tools return purpose-specific projections. A fee waiver is pending until a caller with `actions:approve` confirms `POST /actions/{id}/approve`; the stored arguments, tenant, subject, conversation, expiry, and account version are checked again. A retry receives the durable receipt and cannot repeat the update.

`POST /documents` requires `documents:write`; ingestion always marks content untrusted. `DELETE /documents/{id}` and `DELETE /conversations/{id}` provide explicit erasure paths. Executed financial receipts belong in the organization's regulated ledger retention system; a real external billing adapter should use a transactional outbox and downstream idempotency key rather than placing a network call inside the database transaction.

## Security limits and effectiveness assessment

This system makes model compromise non-catastrophic for the boundaries it owns: a prompt injection may cause a bad answer or a denied proposal, but it cannot manufacture a scope, cross a tenant predicate, forge approval, or emit a browser request through an accepted response. Deterministic isolation and action checks are testable must-be-zero properties.

Natural-language injection, model hallucination, compromised dependencies, a malicious authenticated user acting within their legitimate permissions, incorrect upstream ACL data, and availability of the identity/model/database providers remain risks. Pattern DLP is only a local baseline; Presidio also has false negatives. It is intentionally required to choose and evaluate a DLP scanner in production. No output filter can prove that a semantic answer contains no sensitive inference, which is why the design minimizes context and avoids caching across authorization changes.

The package does not execute shell, SQL, HTML, email, webhooks, or dynamic MCP tools. Adding one requires a purpose-specific typed adapter, a deterministic policy, least-privilege service credentials, a transaction/outbox plan, an idempotency key, and adversarial tests. Do not pass model-generated URLs to a browser. If citations are needed, map stored document IDs to server-generated links.

## Tests and maintenance

```powershell
uv sync --locked --dev --all-extras
uv run pytest -q
uv run ruff check src tests
uv run ruff format --check src tests
```

PostgreSQL-only tests are skipped without a database. They cover the behavior
SQLite cannot exercise, so run them before trusting a release:

```powershell
$env:TEST_POSTGRES_URL = "postgresql+psycopg://postgres:postgres@localhost:5432/guard_test"
uv run agentguard migrate
uv run pytest -q -m postgres
```

Audit the exact dependency set the wheel ships:

```powershell
uv export --no-dev --no-emit-project --all-extras --format requirements-txt -o requirements.lock.txt
uv run pip-audit -r requirements.lock.txt --disable-pip
```

The suite is in four parts. `tests/test_security.py` asserts the design behaves
as designed. `tests/test_adversarial.py` tries to break it, organized by attacker
goal and asserting against stored state rather than a returned error code; its
final section holds *passing* tests that demonstrate the heuristics being evaded,
so nobody mistakes a tripwire for a boundary. `tests/test_money_concurrency.py`
and `tests/test_postgres.py` cover what SQLite cannot: row locks, row-level
security, and concurrent execution. `tests/test_contrib.py` attacks the shipped
adapters' ACL predicates.

That split exists because of a specific failure. A duplicate-execution defect
survived review and 85 adversarial tests because every one of them ran on SQLite,
where `with_for_update()` is a silent no-op and `ON CONFLICT DO NOTHING` reports
an accurate rowcount. On PostgreSQL it reports `-1`, the exclusivity check was
unreachable, and concurrent retries of one operation each executed the turn. Test
the backend you deploy on.

Add an adversarial and a benign case for every new tool, model, prompt, provider,
and retrieval adapter. Keep audit payloads metadata-only: the HMAC fingerprints
content for correlation but never records raw prompts, tokens, PII, or provider
responses.

## Install as a library

Once published to your organization’s package index, install the runtime package with:

```powershell
python -m pip install agentguard            # core: ports + engine, Pydantic only
python -m pip install "agentguard[sql]"     # bundled SQL implementation of the ports
python -m pip install "agentguard[all]"     # SQL, PostgreSQL, and the reference HTTP API
```

Install the optional Presidio integration when that is the DLP implementation approved by your security team:

```powershell
python -m pip install "agentguard[pii]"
```

For an internal registry, use its normal index configuration, for example `pip install --index-url https://packages.example.com/simple agentguard`. For a local wheel or an internal Git checkout, install `agentguard-0.4.0-py3-none-any.whl` with `pip install path/to/wheel.whl`, or use `pip install .` from this project. The package exposes `Guard`, `Limits`, `Principal`, `ChatRequest`, and the port protocols in `agentguard.ports` as its stable integration surface; the `agentguard` command provides the demo and database administration commands.
