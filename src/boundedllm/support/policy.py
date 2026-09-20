"""Reference action policy for the support domain.

Small enough to review in one sitting, which is the point: a policy nobody reads
is not a control. LLM text never supplies ownership or permissions here.
"""

from boundedllm.models import Principal, TurnFlags
from boundedllm.support.authz import can_access_account
from boundedllm.support.models import Account, ToolDecision, WaiveFeeArgs


class SupportPolicy:
    """Replace this class to add domain rules without weakening gateway checks."""

    def __init__(
        self,
        max_waiver_cents: int = 50000,
        auto_approve_below_cents: int = 0,
        require_separate_approver: bool = False,
    ):
        # Defaults require human consent for every monetary mutation. Raising
        # auto_approve_below_cents is an operator decision with a paper trail;
        # no classifier and no model output can move it.
        self.max_waiver_cents = max_waiver_cents
        self.auto_approve_below_cents = auto_approve_below_cents
        # Off by default because the property the design guarantees is that the
        # *model* cannot approve its own proposal, which holds either way. Turn it
        # on where a compromised session must also be unable to self-approve; the
        # cost is a second human on every waiver.
        self.require_separate_approver = require_separate_approver

    def waive_fee(
        self,
        principal: Principal,
        args: WaiveFeeArgs,
        account: Account,
        flags: TurnFlags,
        proposed_by: str | None = None,
    ) -> ToolDecision:
        """Decide once for a proposal and again at approval time.

        ``proposed_by`` is supplied only on the approval pass, where it carries the
        subject that created the pending action. A policy cannot compare approver
        to proposer without it, so leaving it unset keeps the previous behavior.
        """
        code = None
        if "fees:waive" not in principal.scopes:
            code = "MISSING_SCOPE"
        elif not can_access_account(principal, account):
            code = "RESOURCE_DENIED"
        elif account.status != "active":
            code = "ACCOUNT_NOT_ACTIVE"
        elif args.amount_cents > min(account.fee_cents, self.max_waiver_cents):
            code = "AMOUNT_INVALID"
        elif self.require_separate_approver and proposed_by is not None and proposed_by == principal.subject:
            code = "SEPARATION_OF_DUTIES"
        if code:
            return ToolDecision(verdict="DENY", reason_code=code)
        # The default requires consent for every monetary mutation. Lower-risk writes
        # can be explicitly enabled by operators; text classifiers cannot enable them.
        if (
            flags.untrusted_content_present
            or flags.risk_action != "continue"
            or args.amount_cents > self.auto_approve_below_cents
        ):
            return ToolDecision(verdict="REQUIRE_APPROVAL", reason_code="HUMAN_CONSENT_REQUIRED")
        return ToolDecision(verdict="ALLOW", reason_code="POLICY_OK")
