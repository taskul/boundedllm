"""Immutable security facts and strict request contracts shared by all adapters.

Everything here is domain-neutral. Business objects an application happens to act
on — accounts, fee waivers, approval payloads — belong to that application, and
the reference implementation of one lives in ``boundedllm.support``.
"""

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:@/-]+$")]
OpaqueID = Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
Classification = Literal["public", "internal", "confidential", "restricted"]
CLASS_LEVEL = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


class StrictModel(BaseModel):
    """Reject coercion and unknown fields, including injected privilege attributes."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Principal(StrictModel):
    """Construct only after trusted authentication; never deserialize from a request body."""

    subject: Identifier
    tenant_id: Identifier
    roles: frozenset[str] = frozenset()
    scopes: frozenset[str] = frozenset()
    expires_at: float


class RequestContext(StrictModel):
    request_id: OpaqueID
    principal: Principal


class ChatRequest(StrictModel):
    message: str = Field(min_length=1, max_length=20000)
    conversation_id: OpaqueID
    # Stable across HTTP retries, chosen by the client and bound to the request body.
    operation_id: OpaqueID
    # Attachments are explicit capabilities for this turn. The repository still
    # verifies their tenant, owner, conversation, classification, and role ACLs.
    attachment_ids: list[Identifier] = Field(default_factory=list, max_length=8)


class ProposedToolCall(StrictModel):
    """What the model asked for. A proposal is not a decision and not an execution.

    Arguments stay untyped here on purpose: the registry that owns a tool is the
    only thing that knows its schema, and it must validate against that schema
    before authorizing anything.
    """

    name: Identifier
    arguments: dict[str, Any]


class AssistantOutput(StrictModel):
    answer: str = Field(default="", max_length=12000)
    tool_call: ProposedToolCall | None = None


class ToolExecutionResult(StrictModel):
    """Narrow contract returned by trusted, deterministic tool executors."""

    status: Literal["OK", "DENIED", "REQUIRE_APPROVAL", "COMPLETE"]
    result: Any = None
    answer: str | None = Field(default=None, max_length=12000)
    pending_action_id: OpaqueID | None = None


class AttachmentResult(StrictModel):
    """Safe per-turn status; filenames and extracted content never enter audit logs."""

    document_id: Identifier
    status: Literal["used", "quarantined", "rejected"]
    code: Identifier | None = None


class ChatResponse(StrictModel):
    answer: str
    request_id: OpaqueID
    status: Literal["OK", "BLOCKED", "REQUIRE_APPROVAL", "DENIED"] = "OK"
    pending_action_id: OpaqueID | None = None
    attachment_results: list[AttachmentResult] = Field(default_factory=list)


class Document(StrictModel):
    doc_id: Identifier
    tenant_id: Identifier
    classification: Classification
    allowed_roles: frozenset[str]
    source: Identifier
    body: str = Field(min_length=1, max_length=10000)
    owner_subject: Identifier | None = None
    conversation_id: OpaqueID | None = None
    upload_state: Literal["ready", "quarantined"] = "ready"
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    retention_policy: Identifier = "standard"
    # Publisher-controlled provenance does not turn document text into instructions.
    provenance_verified: bool = False


class IngestRequest(StrictModel):
    doc_id: Identifier
    classification: Classification
    allowed_roles: list[Identifier] = Field(max_length=32)
    source: Identifier
    body: str = Field(min_length=1, max_length=10000)
    # A value of None creates shared enterprise knowledge. A value must match
    # the authenticated subject; callers cannot assign a document to another user.
    owner_subject: Identifier | None = None
    conversation_id: OpaqueID | None = None
    retention_policy: Identifier = "standard"


class TurnFlags(StrictModel):
    risk_action: Literal["continue", "step_up", "block"]
    untrusted_content_present: bool = True
