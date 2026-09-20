"""Business objects for the reference customer-support domain.

These used to sit in the core, which made a general-purpose package carry one
application's idea of an account and a fee waiver. They live here now as a worked
example: copy this module's shape for your own domain rather than bending your
data into it. Nothing in ``boundedllm`` imports this package.
"""

from typing import Annotated, Literal

from pydantic import Field

from boundedllm.models import Identifier, OpaqueID, StrictModel

AccountID = Annotated[str, Field(pattern=r"^acct_[A-Za-z0-9]{10,32}$")]


class WaiveFeeArgs(StrictModel):
    account_id: AccountID
    amount_cents: int = Field(gt=0, le=50000)
    reason: str = Field(min_length=5, max_length=300)


class GetAccountSummaryArgs(StrictModel):
    account_id: AccountID


class Account(StrictModel):
    account_id: AccountID
    tenant_id: Identifier
    owner_subject: Identifier
    status: Literal["active", "closed", "frozen"]
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    fee_cents: int = Field(ge=0)


class ToolDecision(StrictModel):
    verdict: Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    reason_code: str


class PendingAction(StrictModel):
    """Trusted UI displays these exact stored arguments before human confirmation."""

    pending_action_id: OpaqueID
    tool: Literal["waive_fee"] = "waive_fee"
    arguments: WaiveFeeArgs
    state: Literal["pending", "executed", "expired"]
    expires_at: float
