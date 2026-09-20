"""Reference ToolExecutor: a static two-tool registry over a support domain.

This is an example of the contract in ``boundedllm.tool_gateway``, not a framework
to extend. It deliberately excludes network fetch, shell, SQL, email, and dynamic
plugin loading, because a registry that can be widened at runtime is not a
registry. Copy the shape; supply your own tools.
"""

import json

from pydantic import ValidationError

from boundedllm.models import ChatRequest, ProposedToolCall, RequestContext, TurnFlags
from boundedllm.support.models import GetAccountSummaryArgs, WaiveFeeArgs
from boundedllm.support.policy import SupportPolicy
from boundedllm.support.projections import account_summary

TOOL_ARGS = {"get_account_summary": GetAccountSummaryArgs, "waive_fee": WaiveFeeArgs}


class ToolGateway:
    """Validate, authorize, then execute; each step can only narrow the last."""

    def __init__(self, store, policy: SupportPolicy):
        self.store, self.policy = store, policy

    async def execute(
        self, ctx: RequestContext, request: ChatRequest, proposal: ProposedToolCall, flags: TurnFlags
    ) -> dict:
        arg_type = TOOL_ARGS.get(proposal.name)
        try:
            if arg_type is None:
                return {"status": "DENIED"}
            args = arg_type.model_validate(proposal.arguments)
        except ValidationError:
            await self.store.event(ctx, "tool_schema_rejected", code="SCHEMA_INVALID")
            return {"status": "DENIED"}
        if isinstance(args, GetAccountSummaryArgs):
            account = await self.store.get_account(ctx.principal, args.account_id)
            await self.store.event(ctx, "tool_read", tool=proposal.name, status="OK")
            # A projection, not the record: ownership and tenant never reach the model.
            return {"status": "OK", "result": account_summary(account)}
        outcome = await self.store.propose_waiver(ctx, request, args, flags, self.policy)
        if outcome.get("status") == "REQUIRE_APPROVAL":
            return outcome
        # The executor states the result of its own mutation so the model cannot
        # reinterpret a receipt into a different claim about what happened.
        return {"status": "COMPLETE", "answer": json.dumps(outcome, sort_keys=True)}
