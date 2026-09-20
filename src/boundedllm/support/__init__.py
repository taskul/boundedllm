"""A complete worked example of wiring one business domain into the guard.

Customer support with fee waivers: business objects, an action policy, a tool
registry, SQL tables, and the consent/execution cycle. None of it is imported by
``boundedllm``; it exists to be read and copied, not extended in place.

    from boundedllm import Guard
    from boundedllm.adapters.sql import sql_ports
    from boundedllm.support import SupportPolicy, SupportSQLStore, ToolGateway

    store  = SupportSQLStore(settings, audit)
    policy = SupportPolicy()
    guard  = Guard(
        provider=provider,
        signer=audit,
        tool_executor=ToolGateway(SQLAdapter(store), policy),
        **sql_ports(store),
    )
"""

from boundedllm.support.gateway import TOOL_ARGS, ToolGateway
from boundedllm.support.models import (
    Account,
    GetAccountSummaryArgs,
    PendingAction,
    ToolDecision,
    WaiveFeeArgs,
)
from boundedllm.support.policy import SupportPolicy
from boundedllm.support.projections import account_summary
from boundedllm.support.store import SupportSQLStore

__all__ = [
    "TOOL_ARGS",
    "Account",
    "GetAccountSummaryArgs",
    "PendingAction",
    "SupportPolicy",
    "SupportSQLStore",
    "ToolDecision",
    "ToolGateway",
    "WaiveFeeArgs",
    "account_summary",
]
