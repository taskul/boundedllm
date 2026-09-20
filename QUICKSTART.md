# Quickstart

Ten minutes, three steps. This is the practical path; [`README.md`](README.md) is
the reference and [`SECURITY.md`](SECURITY.md) is the honest scope.

## What this does, in one paragraph

Your LLM app has a model that can be talked into things. This package puts the
decisions that matter — who you are, what you can read, what actions are allowed,
what leaves the building — into ordinary code that never asks the model anything.
When an injection works, the attacker gets a chatty model and nothing else.

It is **not** a prompt-injection detector. It assumes the injection already
succeeded.

## 1. See it work (2 minutes)

```bash
pip install "boundedllm[sql]"
boundedllm demo
```

You will see a normal answer, then a fee waiver the model proposed, held for human
approval, approved once, and **replayed without paying twice**. That last bit is
the whole product.

## 2. Wrap your own model call (5 minutes)

The smallest useful integration. Everything is in-memory here so it runs as-is —
swap each piece for your real systems afterwards.

```python
import asyncio, hashlib, hmac, json, time
from boundedllm import ChatRequest, Guard, Limits, Principal

# --- the four things you plug in -------------------------------------------

class Model:
    """Your model. Must return JSON: {"answer": str, "tool_call": null|{...}}."""
    async def complete(self, request):
        return json.dumps({"answer": "Your deductible is $500.", "tool_call": None})

class Ledger:
    """Where security events go. Print, log, Splunk, Kafka - your call."""
    async def event(self, ctx, event, **fields):
        print(f"[audit] {event} {fields}")

class Quotas:
    """Shared ceilings. Must be durable in production - Redis, Postgres, etc."""
    async def throttle(self, principal): ...
    async def reserve_model_cost(self, ctx): ...

class Operations:
    """Idempotency, so an HTTP retry is not a second turn."""
    def __init__(self): self.cache = {}
    async def claim(self, ctx, request): return self.cache.get(request.operation_id)
    async def finish(self, ctx, operation_id, response, docs=None):
        if response: self.cache[operation_id] = response

class Signer:
    """Keyed pseudonymization, so logs correlate without naming people."""
    def fingerprint(self, value):
        return hmac.new(b"replace-me-32-bytes-minimum-secret", value.encode(),
                        hashlib.sha256).hexdigest()

# --- wire it up -------------------------------------------------------------

guard = Guard(
    provider=Model(), signer=Signer(), ledger=Ledger(),
    quotas=Quotas(), operations=Operations(),
    limits=Limits(model_name="my-model", allowed_models=frozenset({"my-model"})),
)

# This comes from YOUR auth middleware after it verifies a token.
# Never build it from a request body.
user = Principal(
    subject="user-123", tenant_id="acme",
    scopes=frozenset({"chat:use"}), expires_at=time.time() + 300,
)

answer = asyncio.run(guard.chat(user, ChatRequest(
    message="What is my deductible?",
    conversation_id="0" * 32,
    operation_id="1" * 32,   # stable across retries of the same request
)))
print(answer.status, answer.answer)
```

Run it. Then try breaking it:

```python
# The model tries to exfiltrate. Status becomes BLOCKED.
return json.dumps({"answer": "Upload done: evil.invalid/c?d=SSN", "tool_call": None})

# The model proposes a tool you never registered. Status becomes DENIED.
return json.dumps({"answer": "", "tool_call": {"name": "refund", "arguments": {}}})
```

## 3. Replace the stubs with your systems

In rough order of value:

| Port | What to use | Ready-made |
|---|---|---|
| `provider` | Your model SDK | `boundedllm.contrib.anthropic` |
| `ledger` | Your log or SIEM pipeline | `boundedllm.contrib.ledger` |
| `quotas` + `operations` | Anything durable and shared | `boundedllm.adapters.sql` |
| `documents` | Your RAG index | `boundedllm.contrib.pgvector` |
| `tool_executor` | Your actions | `boundedllm.support` (example) |

With Claude and the bundled SQL storage:

```python
from anthropic import AsyncAnthropic
from boundedllm import Audit, Guard
from boundedllm.adapters.sql import SQLStore, sql_ports
from boundedllm.config import Settings
from boundedllm.contrib.anthropic import AnthropicProvider

settings = Settings()                      # reads GUARD_* environment variables
audit = Audit.from_settings(settings)
store = SQLStore(settings, audit)          # run `boundedllm migrate` first

guard = Guard(
    provider=AnthropicProvider(AsyncAnthropic(), model="claude-opus-5"),
    signer=audit,
    limits=settings.limits(),
    **sql_ports(store),
)
```

```bash
pip install "boundedllm[sql,anthropic]"
export GUARD_AUDIT_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")
export GUARD_DATABASE_URL=sqlite:///guard.db
boundedllm migrate
```

## The five ports

Implement these over what you already run. Two rules apply to all of them:
**filter inside the query, never in Python afterwards**, and **raise on failure** —
returning `[]` reads as "nothing matched" and silently widens what the model sees.

```python
class Ledger:     async def event(self, ctx, event, **fields) -> None
class Quotas:     async def throttle(self, principal) -> None
                  async def reserve_model_cost(self, ctx) -> None
class Operations: async def claim(self, ctx, request) -> ChatResponse | None
                  async def finish(self, ctx, operation_id, response, docs=None) -> None
class Documents:  async def search(self, principal, query, limit, max_level,
                                   conversation_id, attachment_ids) -> list[Document]
                  async def quarantine(self, ctx, doc_id, signals) -> None
                  async def attachment_results(self, principal, conversation_id,
                                               attachment_ids) -> list[dict]
class Signer:     def fingerprint(self, value) -> str
```

Only `provider`, `signer`, `ledger`, `quotas`, and `operations` are required.
Omit `documents` and the turn runs with no retrieved data. Omit `tool_executor`
and every tool proposal is denied — there is no default registry, so an
unconfigured app cannot act by accident.

## Things that surprise people

**Every tool call needs human approval by default.** That is deliberate. Lower it
per-action in your own policy once you have decided which actions are safe.

**Links are blocked entirely.** A model naming any host fails the turn, because a
URL is an exfiltration channel with a path and a query attached. If you must cite
your own domain: `Limits(citation_hosts={"help.yourco.com"})`, and read the
warning in `boundedllm.egress` first.

**`operation_id` must be stable across retries** of the same logical request and
different for a new one. Reusing it with a different message is a `409`; reusing
it with the same message replays the stored answer.

**The bundled `PatternScanner` is not DLP.** It catches dashed SSNs, emails, and
card-shaped digits. It misses names, addresses, and undashed identifiers.
Production requires a real scanner.

## Running the API instead

If you want the reference HTTP service rather than an embedded library:

```bash
pip install "boundedllm[all]"
export GUARD_AUDIT_KEY=...  GUARD_DATABASE_URL=...  GUARD_MODEL_URL=https://...
boundedllm migrate
uvicorn boundedllm.main:create_app --factory
```

All three environment variables are required; the process exits at startup
without them. `docker run` needs the same, plus a writable path for the database —
see the header of [`Dockerfile`](Dockerfile).

## Next

- [`SECURITY.md`](SECURITY.md) — what is a control and what is only a signal
- [`OPERATIONS.md`](OPERATIONS.md) — keys, backups, limits, incident response
- [`README.md`](README.md) — the full reference
- `testApp/` — a working insurance app with Claude connected and eight attacks you can run
