"""SQL persistence for the reference support domain.

Subclasses the bundled adapter store rather than living inside it, so the generic
repository carries no accounts and no fee waivers. The interesting property is in
``_execute``: consent consumption, the monetary state change, the durable
receipt, and the audit evidence all commit in one transaction, so a committed
side effect can never exist without the record that authorized it.
"""

import json
import time
from uuid import uuid4

from sqlalchemy import delete, insert, select, update

from agentguard.adapters.sql.schema import conversations
from agentguard.adapters.sql.store import SQLStore
from agentguard.authz import require_live, require_scope
from agentguard.errors import Conflict, Denied, Unavailable
from agentguard.models import ChatRequest, Principal, RequestContext, TurnFlags
from agentguard.support.authz import can_access_account
from agentguard.support.models import Account, PendingAction, WaiveFeeArgs
from agentguard.support.policy import SupportPolicy
from agentguard.support.schema import accounts, actions


class SupportSQLStore(SQLStore):
    """Adds account reads and the fee-waiver consent/execution cycle."""

    def __init__(
        self,
        settings,
        audit,
        *,
        max_waiver_cents: int = 50000,
        auto_approve_below_cents: int = 0,
        approval_ttl_seconds: int = 300,
        require_separate_approver: bool = False,
    ):
        super().__init__(settings, audit)
        # A baseline policy is rebuilt from these on every decision so a composed
        # custom policy can only narrow the outcome, never widen it.
        self.max_waiver_cents = max_waiver_cents
        self.auto_approve_below_cents = auto_approve_below_cents
        self.approval_ttl_seconds = approval_ttl_seconds
        self.require_separate_approver = require_separate_approver

    def _account(self, conn, principal: Principal, account_id: str):
        row = (
            conn.execute(
                select(accounts)
                .where(accounts.c.tenant_id == principal.tenant_id, accounts.c.account_id == account_id)
                .with_for_update()
            )
            .mappings()
            .first()
        )
        if row is None:
            raise Denied("RESOURCE_NOT_FOUND")
        account = Account.model_validate({key: row[key] for key in Account.model_fields})
        if not can_access_account(principal, account):
            raise Denied("RESOURCE_NOT_FOUND")
        return account, row["version"]

    def get_account(self, principal: Principal, account_id: str) -> Account:
        require_scope(principal, "accounts:read")
        with self.transaction(principal.tenant_id) as conn:
            return self._account(conn, principal, account_id)[0]

    def _execute(self, conn, ctx: RequestContext, action, args: WaiveFeeArgs, account: Account) -> dict:
        # Consent consumption, the actual local monetary state transition, durable
        # receipt, and audit evidence commit together. External billing integrations
        # need a transactional outbox and downstream idempotency, not a network call here.
        require_live(ctx.principal)
        receipt = {"status": "executed", "amount_cents": args.amount_cents, "currency": account.currency}
        conn.execute(
            update(accounts)
            .where(
                accounts.c.tenant_id == ctx.principal.tenant_id, accounts.c.account_id == account.account_id
            )
            .values(fee_cents=account.fee_cents - args.amount_cents, version=accounts.c.version + 1)
        )
        conn.execute(
            update(actions)
            .where(actions.c.tenant_id == ctx.principal.tenant_id, actions.c.id == action["id"])
            .values(state="executed", receipt=json.dumps(receipt))
        )
        self._audit(
            conn,
            ctx,
            "tool_executed",
            tool="waive_fee",
            action_id=action["id"],
            arguments_digest=action["arguments_digest"],
            status="OK",
        )
        return receipt

    def propose_waiver(
        self,
        ctx: RequestContext,
        request: ChatRequest,
        args: WaiveFeeArgs,
        flags: TurnFlags,
        policy: SupportPolicy,
    ) -> dict:
        require_scope(ctx.principal, "fees:waive")
        with self.transaction(ctx.principal.tenant_id) as conn:
            self._conversation(conn, ctx.principal, request.conversation_id)
            account, version = self._account(conn, ctx.principal, args.account_id)
            # Always apply the baseline even when custom policies are composed.
            baseline = SupportPolicy(
                self.max_waiver_cents, self.auto_approve_below_cents, self.require_separate_approver
            ).waive_fee(ctx.principal, args, account, flags)
            decision = policy.waive_fee(ctx.principal, args, account, flags)
            if baseline.verdict == "DENY" or decision.verdict == "DENY":
                raise Denied("ACTION_POLICY_DENIED")
            existing = (
                conn.execute(
                    select(actions)
                    .where(
                        actions.c.tenant_id == ctx.principal.tenant_id,
                        actions.c.subject == ctx.principal.subject,
                        actions.c.operation_id == request.operation_id,
                    )
                    .with_for_update()
                )
                .mappings()
                .first()
            )
            digest = self.audit.fingerprint(args.model_dump_json())
            if existing:
                if not self.audit.matches(args.model_dump_json(), existing["arguments_digest"]):
                    raise Conflict("MUTATION_ALREADY_PROPOSED")
                if existing["state"] == "executed":
                    return json.loads(existing["receipt"])
                return {"status": "REQUIRE_APPROVAL", "pending_action_id": existing["id"]}
            action = dict(
                tenant_id=ctx.principal.tenant_id,
                id=uuid4().hex,
                subject=ctx.principal.subject,
                operation_id=request.operation_id,
                conversation_id=request.conversation_id,
                arguments=args.model_dump_json(),
                arguments_digest=digest,
                account_version=version,
                state="pending",
                expires_at=time.time() + self.approval_ttl_seconds,
                created_at=time.time(),
            )
            conn.execute(insert(actions).values(**action))
            self._audit(
                conn,
                ctx,
                "tool_proposed",
                tool="waive_fee",
                action_id=action["id"],
                arguments_digest=digest,
                status="REQUIRE_APPROVAL",
            )
            if baseline.verdict == decision.verdict == "ALLOW":
                return self._execute(conn, ctx, action, args, account)
            return {"status": "REQUIRE_APPROVAL", "pending_action_id": action["id"]}

    def _action(self, conn, principal: Principal, action_id: str):
        row = (
            conn.execute(
                select(actions)
                .where(
                    actions.c.tenant_id == principal.tenant_id,
                    actions.c.id == action_id,
                )
                .with_for_update()
            )
            .mappings()
            .first()
        )
        if row is None:
            raise Denied("RESOURCE_NOT_FOUND")
        # A support administrator may approve an action proposed by another
        # subject. The action's tenant and account policy remain authoritative.
        if row["subject"] != principal.subject and "support_admin" not in principal.roles:
            raise Denied("RESOURCE_NOT_FOUND")
        if not conn.execute(
            select(conversations.c.id).where(
                conversations.c.tenant_id == principal.tenant_id,
                conversations.c.id == row["conversation_id"],
            )
        ).first():
            raise Denied("RESOURCE_NOT_FOUND")
        return row

    def pending_action(self, principal: Principal, action_id: str) -> PendingAction:
        require_scope(principal, "fees:waive")
        with self.transaction(principal.tenant_id) as conn:
            row = self._action(conn, principal, action_id)
            state = row["state"]
            if state == "pending" and row["expires_at"] <= time.time():
                state = "expired"
            return PendingAction(
                pending_action_id=row["id"],
                arguments=WaiveFeeArgs.model_validate_json(row["arguments"]),
                state=state,
                expires_at=row["expires_at"],
            )

    def approve(self, ctx: RequestContext, action_id: str, policy: SupportPolicy) -> dict:
        require_scope(ctx.principal, "fees:waive")
        require_scope(ctx.principal, "actions:approve")
        with self.transaction(ctx.principal.tenant_id) as conn:
            row = self._action(conn, ctx.principal, action_id)
            if row["state"] == "executed":
                return json.loads(row["receipt"])  # Retry returns receipt; consent is never reused.
            if row["expires_at"] <= time.time() or row["state"] != "pending":
                raise Denied("APPROVAL_EXPIRED")
            args = WaiveFeeArgs.model_validate_json(row["arguments"])
            # Consent was recorded under whichever signing key was current at
            # proposal time; a later rotation must not void a pending approval.
            if not self.audit.matches(args.model_dump_json(), row["arguments_digest"]):
                raise Unavailable("ACTION_INTEGRITY")
            account, version = self._account(conn, ctx.principal, args.account_id)
            if version != row["account_version"]:
                raise Conflict("RESOURCE_CHANGED_REPROPOSE_REQUIRED")
            flags = TurnFlags(risk_action="step_up", untrusted_content_present=True)
            # The stored proposer, never a value from the approval request, so an
            # attacker cannot claim to be someone else to satisfy a separation rule.
            proposed_by = row["subject"]
            baseline = SupportPolicy(
                self.max_waiver_cents, self.auto_approve_below_cents, self.require_separate_approver
            ).waive_fee(ctx.principal, args, account, flags, proposed_by)
            decision = policy.waive_fee(ctx.principal, args, account, flags, proposed_by)
            if baseline.verdict == "DENY" or decision.verdict == "DENY":
                raise Denied("ACTION_POLICY_DENIED")
            self._audit(
                conn,
                ctx,
                "human_approved",
                action_id=action_id,
                arguments_digest=row["arguments_digest"],
                actor_fingerprint=self.audit.fingerprint(ctx.principal.subject),
            )
            return self._execute(conn, ctx, row, args, account)

    def _purge_domain_rows(self, conn, ctx: RequestContext, conversation_id: str) -> None:
        """Drop unconsumed consent for a deleted conversation.

        Only pending rows. An executed waiver is a financial receipt and stays
        under the organization's ledger retention policy; deleting a conversation
        must not erase evidence that money moved.
        """
        conn.execute(
            delete(actions).where(
                actions.c.tenant_id == ctx.principal.tenant_id,
                actions.c.conversation_id == conversation_id,
                actions.c.state == "pending",
            )
        )
