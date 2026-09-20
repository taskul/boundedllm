# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Versioning and support policy

This package uses [Semantic Versioning](https://semver.org/). While the major
version is `0`, the minor version carries breaking changes.

**The public API** is what `boundedllm/__init__.py` exports, plus the protocols in
`boundedllm.ports`, `boundedllm.tool_gateway`, and `boundedllm.model_gateway`.
`boundedllm.adapters.*` and `boundedllm.support.*` are supported but may change more
freely; anything with a leading underscore is private.

**Security fixes** ship in a patch release for the current minor version and are
noted here under `Security`. A deprecation is announced in one minor release,
keeps working with a `DeprecationWarning` for at least one more, and is removed no
earlier than the release after that. A change that narrows what is permitted is
treated as a security fix, not a breaking change, and may ship in a patch.

**Database changes** ship as Alembic revisions under
`boundedllm/adapters/sql/migrations`. Run `boundedllm migrate` before rolling out a
new version. A release never modifies a database at application startup.

## [0.4.0] - 2026-09-19

### Added

- `boundedllm.contrib` — ready-made port implementations: `pgvector` (a
  `Documents` port that puts every ACL predicate inside the ranked query),
  `anthropic` (a `ModelProvider` on the official SDK), and `ledger`
  (`StructuredLogLedger`, `TeeLedger`, `BufferedHTTPLedger`). New extras:
  `[pgvector]` and `[anthropic]`.
- [`QUICKSTART.md`](QUICKSTART.md) — a ten-minute path separate from the
  reference documentation. Its example is executed in CI.
- `scripts/load_check.py` — asserts the shared ceilings bind under concurrency
  rather than measuring throughput.
- CI: SBOM (CycloneDX), CodeQL, gitleaks secret scanning over full history, a
  load job, and PostgreSQL coverage for the contrib adapters. All actions are now
  pinned to commit SHAs.

### Fixed

- **Concurrent retries of one operation id each executed the turn on PostgreSQL.**
  `INSERT ... ON CONFLICT DO NOTHING` reports `rowcount == -1` there, so the
  `OPERATION_IN_PROGRESS` branch was unreachable and twelve simultaneous retries
  produced twelve model calls and twelve executions. The claim now uses
  `RETURNING`. SQLite hid this because `BEGIN IMMEDIATE` serializes writers and
  its rowcount is accurate, so the entire SQLite suite stayed green while the
  production database duplicated work. Regression test in `tests/test_postgres.py`.
- The Docker image installed no extras after the dependency split, so the
  container had no web server and failed at startup; and `/app` being correctly
  read-only meant the default SQLite path was unwritable. The image now installs
  `[sql,postgres,api]`, and the Dockerfile documents the three environment
  variables required to start and the hardened `docker run` flags. Both are
  verified in CI.
- The CLI printed a traceback with absolute filesystem paths on a guard failure.
  It now prints the reason code and exits 3.
- The money paths (`_account`, `_action`, `propose_waiver`) had no concurrency
  coverage, because `with_for_update()` is a silent no-op on SQLite and every
  test ran there. `tests/test_money_concurrency.py` exercises them on PostgreSQL
  and asserts on the account balance and the ledger rather than on a status.
  Mutation testing recorded in that file shows the account-version pin and the
  approval-time policy re-check are independently sufficient, and that removing
  both overdraws the account.

### Security

- **Secret scanning would not have caught an Anthropic API key.** gitleaks
  v8.30.1 has no `sk-ant-` rule, and the `generic-api-key` heuristic did not fire
  on one even though it fired on an OpenAI key in the same file. For a repository
  whose example application is wired to Claude, that was the most likely
  credential to leak. `.gitleaks.toml` adds rules for Anthropic keys, explicit
  OpenAI keys, and `GUARD_AUDIT_KEY`, verified against both synthetic
  high-entropy credentials and a real key.

### Changed

- `testApp` is now published rather than excluded from source control, so the
  attack demonstration is reproducible and CI can run it. Its local state
  (`.env`, `.roadshield-dev-secret`, `testapp.db`, virtual environment) stays
  ignored.
- `testApp` uses the shipped `boundedllm.contrib.anthropic` adapter instead of a
  hand-rolled HTTP client, so the lab exercises what a customer installs. Its
  default model is `claude-opus-5`.
- The live attack runner reports whether each attack was stopped by the guard or
  by the model simply declining. Against a real model most are the latter, which
  is a good outcome and not evidence about this package.

## [0.3.0] - 2026-09-16

The theme of this release is that the package is now a library. Previously,
adopting it meant adopting its database schema; the core now depends on contracts
a host implements over its own storage.

### Changed - breaking

- `Guard.__init__` is keyword-only and takes ports instead of a store:
  `Guard(provider=..., signer=..., ledger=..., quotas=..., operations=...,
  documents=..., tool_executor=...)`. `Guard.from_settings` is removed.
- The core no longer depends on SQLAlchemy, psycopg, FastAPI, uvicorn, httpx,
  PyJWT, cryptography, or pydantic-settings. Core runtime dependencies went from
  nine packages to one. Install `boundedllm[sql]` for the bundled
  storage adapter, `[api]` for the reference HTTP service, or `[all]` for both.
- `boundedllm.store` moved to `boundedllm.adapters.sql.store`; `boundedllm.schema`
  to `boundedllm.adapters.sql.schema`.
- `HTTPModelProvider` moved to `boundedllm.adapters.http_model`. The OTLP sink and
  `export_pending` moved to `boundedllm.adapters.otlp`.
- Domain-specific code left the core for `boundedllm.support`: `Account`,
  `WaiveFeeArgs`, `GetAccountSummaryArgs`, `PendingAction`, `ToolDecision`,
  `AccountID`, `can_access_account`, `SupportPolicy`, `ToolGateway`,
  `account_summary`, and the `guard_accounts` and `guard_actions` tables.
- `Guard` has no default tool registry. A proposal with no registered executor is
  denied, so an unconfigured host cannot act by accident. Supply a
  `ToolExecutor`, or `boundedllm.support.ToolGateway` for the reference domain.
- The engine takes `Limits` rather than `Settings`, so embedding it no longer
  requires a database URL or a JWKS URL. `Settings.limits()` builds one.
- `SupportPolicy.waive_fee` accepts an optional `proposed_by` argument, supplied
  on the approval pass.

### Added

- `boundedllm.ports` — `Documents`, `Operations`, `Quotas`, `Ledger`, `Signer`.
- `boundedllm.adapters.sql.sql_ports(store)` to compose the bundled adapter in one
  call, and `SQLAdapter`, which owns the threading policy for synchronous SQL.
- Alembic migrations, `boundedllm migrate`, and `boundedllm stamp` for databases
  created before this release. Migrations ship inside the wheel.
- `SupportPolicy(require_separate_approver=True)` for deployments where a
  compromised session must not be able to approve its own proposal.
- `GUARD_AUDIT_PSEUDONYM_KEY` for a long-lived pseudonymization key that survives
  signing-key rotation, so subject correlation does not break at every rotation.
- `tests/test_adversarial.py`, an attack-oriented suite that asserts against
  stored state rather than returned error codes.
- `Audit.matches` and `Audit.from_settings`.

### Fixed

- **Signing-key rotation stranded pending approvals and idempotent retries.**
  Digests were verified only against the current key, so after a documented
  rotation every unredeemed approval failed with `ACTION_INTEGRITY` and every
  in-flight retry returned a 409 instead of its cached response. Digests are now
  checked against every retained key version.
- **`pip-audit --locked` never ran.** It reads a PEP 751 `pylock.toml`, not
  `uv.lock`, so the CI dependency audit had been failing to resolve anything.
- The Docker image installed from `pyproject.toml` rather than `uv.lock`, so the
  audited dependency set and the shipped one were different artifacts.
- `audit_stats` and `verify_audit_chain` loaded an entire tenant's ledger into
  memory; both now stream.
- A DLP scanner that broke JSON structure escaped as an unhandled error instead
  of failing the turn closed.
- Duplicate `Content-Type` or `Content-Encoding` headers are rejected rather than
  validated on one value and parsed as another.
- `delete_conversation` in the generic store no longer reaches into domain
  tables; a subclass hook purges them inside the same transaction.

### Security

- **Egress: scheme-less references were released.** `evil.invalid/collect?d=...`
  passed the filter, as did an authority and path split across prose. Bare
  hostnames are now rejected, along with the IDNA dot variants `U+FF0E`,
  `U+3002`, and `U+FF61`, which browsers resolve as `.`. Email addresses are
  carved out and left to the DLP layer, which redacts the whole address.
- The injection tripwire matched essentially one phrasing; it now covers the
  common blunt forms. It remains a signal, not a control — see `SECURITY.md`.
- `boundedllm audit verify` exits `2` when the chain is broken. It previously
  exited `0`, so a scheduled integrity check could never fail.
- Ledger-writing CLI commands require `--operator`, recorded as the acting
  subject. Destructive actions were previously attributed to a constant
  `boundedllm-cli` identity. `retention-purge` also requires `--yes`.

### Documentation

- `SECURITY.md` now separates controls from signals, states what the package does
  not do, and records that it has had no third-party audit.
- README claims are aligned with what the architecture guarantees.
