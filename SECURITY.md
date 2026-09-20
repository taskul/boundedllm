# Security model and reporting

## What this package does

It bounds what a compromised agent can reach and do. Identity, tenant isolation,
retrieval ACLs, tool authorization, human consent, idempotency, quotas, and a
tamper-evident ledger are deterministic application code here. They hold whether
or not the model has been manipulated, because none of them ask the model
anything.

That is the claim. It is narrower than "blocks LLM attacks" and it is the one the
architecture can actually support.

## What this package does not do

**It does not detect prompt injection.** `agentguard.risk` matches a handful of
blunt override phrasings. Paraphrase defeats it, and
`tests/test_adversarial.py` contains passing tests that demonstrate the evasion
on purpose. It is a tripwire that lowers a turn's clearance and raises an alert.
It is not a boundary, and adding patterns to it is not a security roadmap.

**It does not implement DLP.** The bundled `PatternScanner` matches dashed US
SSNs, email addresses, long digit runs, and a few secret formats. It does not
match undashed identifiers, names, addresses, dates of birth, account numbers, or
anything contextual. It exists so the test suite runs offline. Production must
supply a reviewed `Scanner`; composition fails closed when
`Limits.require_reviewed_scanner` is set.

**It does not stop a correctly authorized user from misusing a permitted action.**
Authorization is the boundary, so anything inside a principal's real permissions
is allowed by design.

**It cannot prove an answer contains no sensitive inference.** No output filter
can. The design minimizes what enters the context instead, and treats semantic
disclosure as residual risk.

## Controls and signals

These are different things and the distinction is load-bearing.

| | Mechanism | Status |
|---|---|---|
| Tenant isolation | Query predicates plus `secure_search` re-check | Control |
| Document ACLs | Owner, conversation, role, classification, state in the query | Control |
| Tool authorization | Strict schema, then policy against stored facts | Control |
| Human consent | Argument-bound, single-use, TTL, account-version pinned | Control |
| Idempotency | Operation id bound to request digest | Control |
| Shared quotas | Durable counters across workers | Control |
| Egress | Schemes, markup, and bare hostnames rejected | Control, deliberately over-broad |
| Audit integrity | Per-tenant hash chain, HMAC, outbox | Control |
| Injection detection | Regex tripwire | **Signal** |
| PII detection | Pattern baseline, or your reviewed scanner | **Signal** |
| Document poisoning | Same regex tripwire, fails the turn closed | **Signal** |

A signal reduces capability and raises an alert. It never grants access, and a
deployment that relies on one as a boundary is misconfigured.

## Must-be-zero properties

Cross-tenant retrieval, unauthorized side effects, forged or replayed approvals,
duplicate monetary execution, and model cost beyond a committed shared quota.
Each has adversarial coverage in `tests/test_adversarial.py` that asserts against
stored state rather than a returned error code.

Prompt-injection resistance and PII detection are **not** on this list. They are
measured as rates and reviewed, not promised.

## Approval and separation of duties

By default the subject who triggered a proposal may approve it. The property this
enforces is that **the model cannot approve its own proposal** — a human acts
out-of-band against exact stored arguments. It is not two-person control.

Where a compromised session must not be able to self-approve, set
`SupportPolicy(require_separate_approver=True)`, which requires the approving
subject to differ from the proposing subject. Enable it for any action whose
value justifies the extra round trip.

## What a deployment must still supply

A real OIDC provider, least-privilege database credentials, PostgreSQL RLS, a
reviewed model endpoint, a reviewed DLP scanner, TLS, edge rate limits, secret
management, dependency and SBOM scanning, monitoring, retention, and incident
response.

## Reporting

Report suspected vulnerabilities privately to the maintainers before publishing
proof-of-concept data. Include the package version, deployment mode, affected
adapter, and a minimal reproduction using synthetic identifiers only. Never
include bearer tokens, customer records, prompt bodies, provider credentials, or
production URLs.

## Assurance status

This package has **not** had a third-party security audit or penetration test,
and carries no compliance attestation. The included tests are a starting harness
written by the authors; they encode the authors' threat model and therefore miss
whatever it misses. Each deployment must add provider-specific token, ACL, DLP,
and business-policy tests, and should commission an independent review before
trusting this with regulated data.
