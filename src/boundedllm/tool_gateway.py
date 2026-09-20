"""The boundary a model proposal has to cross before anything happens.

The core ships no tool registry. A tool is a side effect on the host's systems,
so the host implements this protocol and decides what exists, what the arguments
mean, and who may invoke them. ``boundedllm.support.gateway`` is a worked example.

An implementation is responsible for four things, in order, on every call:

1. **Reject unknown names.** Treat the registry as an allowlist. A name the model
   invented is a denial, never a passthrough.
2. **Validate arguments against a strict schema** that forbids unknown fields.
   Extra keys are how a proposal smuggles ``admin_override`` past a handler that
   forwards whatever it was given.
3. **Authorize against stored facts**, not against anything in the proposal.
   The model may name a resource; it may never assert who owns it or what the
   caller is allowed to do with it.
4. **Return a typed result.** ``REQUIRE_APPROVAL`` carries a pending action id,
   ``COMPLETE`` carries the authoritative answer text for a state change, and
   ``DENIED`` ends the turn. Never let the model narrate the outcome of a
   mutation it proposed.
"""

from typing import Protocol

from boundedllm.models import ChatRequest, ProposedToolCall, RequestContext, TurnFlags


class ToolExecutor(Protocol):
    """Typed schemas, policy, approval, and execution, owned by the host."""

    async def execute(
        self, ctx: RequestContext, request: ChatRequest, proposal: ProposedToolCall, flags: TurnFlags
    ) -> dict: ...
