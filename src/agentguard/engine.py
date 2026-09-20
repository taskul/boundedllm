"""Orchestrate the security planes as an embeddable, storage-neutral wrapper.

``Guard`` owns the order of operations for a turn and nothing else. Identity
comes from the host, storage comes from the ports in ``agentguard.ports``, and the
model comes from a provider adapter. Nothing here imports a database driver, so
embedding the engine costs a host no schema and no migration.
"""

import asyncio
import json
import time
from contextlib import suppress
from uuid import uuid4

from pydantic import ValidationError

from agentguard.authz import clearance, require_live, require_scope
from agentguard.budget import Budget
from agentguard.context import render_doc_for_model, render_tool_result
from agentguard.egress import citation_allowlist
from agentguard.errors import Denied, GuardError, LimitExceeded, OutputBlocked, Unavailable
from agentguard.limits import Limits
from agentguard.model_gateway import ModelGateway, ModelProvider
from agentguard.models import (
    AttachmentResult,
    ChatRequest,
    ChatResponse,
    Principal,
    RequestContext,
    ToolExecutionResult,
    TurnFlags,
)
from agentguard.normalize import normalize
from agentguard.output_firewall import OutputFirewall, PatternScanner, Scanner
from agentguard.parsing import parse_assistant_output, unique_object
from agentguard.ports import Documents, Ledger, Operations, Quotas, Signer
from agentguard.prompts import POLICY_VERSION, SYSTEM_POLICY
from agentguard.retrieval import secure_search
from agentguard.risk import assess
from agentguard.telemetry import NoopObservability, Observability
from agentguard.tool_gateway import ToolExecutor


class Guard:
    """Compose trusted adapters around an untrusted model.

    ``principal`` must come from a verified host identity layer; there is no
    internal fallback authenticator. Every adapter passed here runs as trusted
    application code, so this is a boundary around a model, not a sandbox for
    arbitrary Python.
    """

    def __init__(
        self,
        *,
        provider: ModelProvider,
        ledger: Ledger,
        quotas: Quotas,
        operations: Operations,
        signer: Signer,
        documents: Documents | None = None,
        tool_executor: ToolExecutor | None = None,
        limits: Limits | None = None,
        scanner: Scanner | None = None,
        observability: Observability | None = None,
        system_policy: str = SYSTEM_POLICY,
    ):
        if not system_policy.strip() or len(system_policy) > 20000:
            raise ValueError("system_policy must contain 1-20000 characters")
        self.limits = limits or Limits()
        self.system_policy = system_policy
        self.signer = signer
        self.ledger = ledger
        self.quotas = quotas
        self.operations = operations
        # A host with no retrieval passes nothing; the turn then runs with no
        # authorized data rather than falling back to an unfiltered store.
        self.documents = documents
        self.model = ModelGateway(self.limits, provider)
        if self.limits.require_reviewed_scanner and scanner is None:
            raise ValueError(
                "this deployment requires an explicit reviewed DLP scanner; "
                "the built-in PatternScanner is a test baseline, not a control"
            )
        self.firewall = OutputFirewall(
            scanner or PatternScanner(),
            self.limits.max_output_chars,
            citation_allowlist(self.limits.citation_hosts),
        )
        # No default tool registry. A tool is a side effect on the host's systems,
        # so the host has to supply and authorize it deliberately.
        self.tools = tool_executor
        self.observability = observability or NoopObservability()
        # Fast fail at capacity, instead of keeping an unbounded waiter queue.
        # This is per process; shared ceilings live behind the Quotas port.
        self._inflight = 0

    def context(self, principal: Principal) -> RequestContext:
        require_live(principal)
        if self.limits.allowed_tenants and principal.tenant_id not in self.limits.allowed_tenants:
            raise Denied("TENANT_NOT_ALLOWED")
        return RequestContext(request_id=uuid4().hex, principal=principal)

    async def _event(self, ctx: RequestContext, event: str, **fields):
        await self.ledger.event(ctx, event, **fields)
        with suppress(Exception):
            self.observability.event(event, fields)

    async def chat(self, principal: Principal, request: ChatRequest) -> ChatResponse:
        """Validate, authorize, minimize, propose, execute, inspect, then release once."""
        require_scope(principal, "chat:use")
        ctx = self.context(principal)
        if self._inflight >= self.limits.max_concurrent_requests:
            raise LimitExceeded("CONCURRENCY")
        self._inflight += 1
        claimed = False
        used_docs = []
        started = time.monotonic()
        telemetry_status = "FAILED"
        telemetry_handle = None
        try:
            # Telemetry is an operational copy; the committed signed ledger is authoritative.
            with suppress(Exception):
                telemetry_handle = self.observability.start_request(
                    principal.tenant_id, request.operation_id, ctx.request_id
                )
            # Rate limits apply to cached retries too. Cost reservation occurs only
            # for actual model calls and is shared between all workers.
            await self.quotas.throttle(principal)
            cached = await self.operations.claim(ctx, request)
            if cached is not None:
                telemetry_status = cached.status
                return cached
            claimed = True
            async with asyncio.timeout(self.limits.request_timeout_seconds):
                response, used_docs = await self._turn(ctx, request)
            require_live(principal)
            await self.operations.finish(ctx, request.operation_id, response, used_docs)
            claimed = False
            telemetry_status = response.status
            return response
        except (Denied, OutputBlocked) as exc:
            await self._event(ctx, "request_blocked", code=exc.code, operation_id=request.operation_id)
            response = ChatResponse(
                answer="I couldn't safely complete that request.",
                request_id=ctx.request_id,
                status="DENIED" if isinstance(exc, Denied) else "BLOCKED",
                attachment_results=[
                    AttachmentResult.model_validate(item)
                    for item in await self._attachment_results(principal, request)
                ],
            )
            if claimed:
                await self.operations.finish(ctx, request.operation_id, response, [])
                claimed = False
            telemetry_status = response.status
            return response
        except TimeoutError as exc:
            await self._event(ctx, "request_failed", code="REQUEST_TIMEOUT")
            raise Unavailable("REQUEST_TIMEOUT") from exc
        except GuardError as exc:
            await self._event(ctx, "request_failed", code=exc.code)
            raise
        finally:
            try:
                if claimed:
                    # A failed/ambiguous operation is never silently restarted.
                    # Operators reconcile it; a new operation is a new intent.
                    await asyncio.shield(self.operations.finish(ctx, request.operation_id, None, []))
            finally:
                self._inflight -= 1
                if telemetry_handle is not None:
                    with suppress(Exception):
                        self.observability.finish_request(
                            telemetry_handle,
                            telemetry_status,
                            int((time.monotonic() - started) * 1000),
                        )

    async def _attachment_results(self, principal: Principal, request: ChatRequest) -> list[dict]:
        if self.documents is None or not request.attachment_ids:
            return []
        return await self.documents.attachment_results(
            principal, request.conversation_id, request.attachment_ids
        )

    async def _retrieve(self, ctx: RequestContext, request: ChatRequest, user_text, limit, level):
        if self.documents is None or "documents:read" not in ctx.principal.scopes:
            return []
        return await secure_search(
            self.documents,
            ctx.principal,
            user_text,
            limit,
            level,
            request.conversation_id,
            request.attachment_ids,
        )

    async def _turn(self, ctx: RequestContext, request: ChatRequest):
        norm = normalize(request.message)
        if not norm.text.strip() or len(norm.text) > self.limits.max_input_chars:
            raise OutputBlocked("INPUT_REJECTED")
        risk = assess(norm)
        await self._event(
            ctx,
            "input_risk",
            signals=list(risk.signals),
            status=risk.action,
            hidden_length=norm.hidden_length,
            policy_version=POLICY_VERSION,
        )
        if risk.action == "block":
            raise OutputBlocked("INPUT_RISK")
        budget = Budget(self.limits.max_model_calls, self.limits.max_tool_calls, self.limits.max_docs)
        level = min(clearance(ctx.principal), 1) if risk.action == "step_up" else clearance(ctx.principal)
        limit = min(self.limits.max_docs, 2) if risk.action == "step_up" else self.limits.max_docs
        # Input redaction happens before embedding/search or any provider call.
        user_text = await self.firewall.minimize(norm.text)
        docs = await self._retrieve(ctx, request, user_text, limit, level)
        budget.spend("documents", len(docs))
        for doc in docs:
            # Retrieved text is attacker-controlled even when its ACL and source
            # are valid. Quarantine explicit instruction-override signals before
            # they reach the model; the system prompt remains a second layer.
            document_risk = assess(normalize(doc.body))
            if document_risk.action != "continue":
                if doc.doc_id in request.attachment_ids and doc.owner_subject == ctx.principal.subject:
                    await self.documents.quarantine(ctx, doc.doc_id, list(document_risk.signals))
                else:
                    await self._event(
                        ctx,
                        "document_quarantined",
                        document_ids=[doc.doc_id],
                        signals=list(document_risk.signals),
                        status=document_risk.action,
                        severity="high",
                    )
                raise OutputBlocked("POISONED_DOCUMENT")
        flags = TurnFlags(risk_action=risk.action, untrusted_content_present=bool(docs))
        blocks = []
        for doc in docs:
            minimal = await self.firewall.minimize(doc.body[: self.limits.max_document_chars])
            projected = doc.model_copy(update={"body": minimal})
            blocks.append(render_doc_for_model(projected, self.limits.max_document_chars))
        user = f"USER REQUEST (UNTRUSTED):\n{user_text}\n\nAUTHORIZED DATA:\n" + "\n\n".join(blocks)
        attachment_results = [
            AttachmentResult(document_id=doc_id, status="used") for doc_id in request.attachment_ids
        ]
        await self._event(
            ctx,
            "model_input",
            document_ids=[doc.doc_id for doc in docs],
            input_fingerprint=self.signer.fingerprint(user),
            count=len(docs),
        )
        while True:
            require_live(ctx.principal)
            budget.spend("model_calls")
            await self.quotas.reserve_model_cost(ctx)
            started = time.monotonic()
            raw = await self.model.complete(self.system_policy, user)
            await self._event(
                ctx,
                "model_completed",
                model=self.limits.model_name,
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            parsed = parse_assistant_output(raw)
            if parsed.tool_call is None:
                answer = await self.firewall.inspect(parsed.answer)
                await self._event(
                    ctx, "response_released", output_fingerprint=self.signer.fingerprint(answer)
                )
                return ChatResponse(
                    answer=answer,
                    request_id=ctx.request_id,
                    attachment_results=attachment_results,
                ), docs
            if self.tools is None:
                # A proposal with no registered executor is a denial, never an
                # implicit success the model can narrate as one.
                await self._event(ctx, "tool_schema_rejected", code="NO_TOOL_EXECUTOR")
                raise Denied("TOOL_SCHEMA_DENIED")
            budget.spend("tool_calls")
            raw_result = await self.tools.execute(ctx, request, parsed.tool_call, flags)
            try:
                result = ToolExecutionResult.model_validate(raw_result)
            except ValidationError as exc:
                raise OutputBlocked("TOOL_RESULT_SCHEMA_INVALID") from exc
            if result.status == "REQUIRE_APPROVAL":
                if result.pending_action_id is None:
                    raise OutputBlocked("TOOL_RESULT_SCHEMA_INVALID")
                return ChatResponse(
                    answer="Review the stored action details before approving.",
                    request_id=ctx.request_id,
                    status="REQUIRE_APPROVAL",
                    pending_action_id=result.pending_action_id,
                    attachment_results=attachment_results,
                ), docs
            if result.status == "DENIED":
                raise Denied("TOOL_SCHEMA_DENIED")
            if result.status == "COMPLETE":
                if result.answer is None:
                    raise OutputBlocked("TOOL_RESULT_SCHEMA_INVALID")
                # The trusted executor can end a state-changing turn so the model
                # cannot reinterpret an authoritative execution receipt.
                answer = await self.firewall.inspect(result.answer)
                return ChatResponse(
                    answer=answer,
                    request_id=ctx.request_id,
                    attachment_results=attachment_results,
                ), docs
            try:
                encoded_result = json.dumps(result.result, sort_keys=True)
            except (TypeError, ValueError) as exc:
                raise OutputBlocked("TOOL_RESULT_SCHEMA_INVALID") from exc
            minimal_result = await self.firewall.minimize(encoded_result)
            try:
                # A composed DLP scanner is trusted to redact, not to preserve JSON
                # structure. A replacement that lands across a delimiter must fail
                # this turn closed rather than escape as an unhandled error.
                redacted_result = json.loads(minimal_result, object_pairs_hook=unique_object)
            except (ValueError, RecursionError) as exc:
                raise OutputBlocked("TOOL_RESULT_SCHEMA_INVALID") from exc
            flags = TurnFlags(risk_action=risk.action, untrusted_content_present=True)
            user += "\n\n" + render_tool_result(redacted_result)
