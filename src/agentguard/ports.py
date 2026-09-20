"""The storage contracts the core depends on, so a host can keep its own systems.

An enterprise adopting this package already has an identity provider, a document
store, a vector index, an authorization service, and an audit pipeline. Requiring
it to move that data into tables this package owns is not a guard it can add; it
is a rewrite. Every port below is therefore narrow enough to implement over
whatever already exists, and ``agentguard.adapters.sql`` supplies a working
implementation of all of them for deployments that want one.

Two rules apply to every implementation:

* **Enforce authorization inside the query.** These protocols receive the
  authenticated ``Principal`` because filtering has to happen where the data is
  selected, not afterwards in Python. The core re-checks what a document port
  returns (see ``retrieval.secure_search``), but that check is a tripwire for a
  misconfigured adapter, not the boundary itself.
* **Fail by raising.** Returning an empty result on an internal error reads as
  "nothing matched" and silently widens what the model is told. Raise
  ``Unavailable`` instead; the core fails the turn closed.

The methods are asynchronous so an adapter owns its own concurrency policy. A
synchronous backend belongs in ``asyncio.to_thread`` inside the adapter, where
the thread budget can be tuned, rather than in the request path.
"""

from typing import Protocol, runtime_checkable

from agentguard.models import (
    ChatRequest,
    ChatResponse,
    Document,
    Principal,
    RequestContext,
)


@runtime_checkable
class Signer(Protocol):
    """Keyed pseudonymization for correlation values that must not be reversible.

    ``agentguard.audit.Audit`` implements this and carries no storage of its own.
    """

    def fingerprint(self, value: str) -> str: ...


@runtime_checkable
class Ledger(Protocol):
    """Append-only security events. Records metadata, never prompts or content.

    Implementations must treat the field allowlist in ``agentguard.audit`` as the
    upper bound of what may be persisted. An adapter that writes an event to a
    destination outside the transaction it describes should use an outbox so a
    committed side effect can never lack its evidence.
    """

    async def event(self, ctx: RequestContext, event: str, **fields) -> None: ...


@runtime_checkable
class Quotas(Protocol):
    """Shared ceilings that must hold across every worker, not per process.

    Both methods have to be backed by durable shared state. An in-memory counter
    silently multiplies the real limit by the number of running replicas.
    """

    async def throttle(self, principal: Principal) -> None: ...

    async def reserve_model_cost(self, ctx: RequestContext) -> None: ...


@runtime_checkable
class Operations(Protocol):
    """Idempotency for a client-chosen operation id, so an HTTP retry is not a second turn.

    ``claim`` returns the stored response when this exact operation already
    completed, and ``None`` when the caller now owns it. Re-authorize any cached
    result against current permissions before replaying it: an answer that was
    safe to release yesterday may not be after an ACL change.
    """

    async def claim(self, ctx: RequestContext, request: ChatRequest) -> ChatResponse | None: ...

    async def finish(
        self,
        ctx: RequestContext,
        operation_id: str,
        response: ChatResponse | None,
        docs: list[Document] | None = None,
    ) -> None: ...


@runtime_checkable
class Documents(Protocol):
    """Retrieval and per-turn attachment state for content the model may be shown.

    ``search`` must apply tenant, owner, conversation, classification, and role
    predicates in the query. ``max_level`` is a ceiling the core lowers when a
    turn is risky; it is never a floor, and it never raises what the principal's
    own clearance already allows.
    """

    async def search(
        self,
        principal: Principal,
        query: str,
        limit: int,
        max_level: int,
        conversation_id: str,
        attachment_ids: list[str],
    ) -> list[Document]: ...

    async def quarantine(self, ctx: RequestContext, doc_id: str, signals: list[str]) -> None: ...

    async def attachment_results(
        self, principal: Principal, conversation_id: str, attachment_ids: list[str]
    ) -> list[dict]: ...
