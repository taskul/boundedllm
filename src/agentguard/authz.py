"""Deterministic authorization depends exclusively on authenticated and stored facts."""

import time

from agentguard.errors import Denied
from agentguard.models import CLASS_LEVEL, Document, Principal


def require_live(principal: Principal) -> None:
    if time.time() >= principal.expires_at:
        raise Denied("SESSION_EXPIRED")


def require_scope(principal: Principal, scope: str) -> None:
    require_live(principal)
    if scope not in principal.scopes:
        raise Denied("MISSING_SCOPE")


def clearance(principal: Principal) -> int:
    if "data:restricted" in principal.scopes:
        return 3
    if "data:confidential" in principal.scopes:
        return 2
    return 1


def can_read(
    principal: Principal,
    doc: Document,
    max_level: int | None = None,
    conversation_id: str | None = None,
) -> bool:
    level = clearance(principal) if max_level is None else min(clearance(principal), max_level)
    return (
        doc.tenant_id == principal.tenant_id
        and CLASS_LEVEL[doc.classification] <= level
        and (doc.classification == "public" or bool(doc.allowed_roles & principal.roles))
        and (doc.owner_subject is None or doc.owner_subject == principal.subject)
        and (doc.conversation_id is None or doc.conversation_id == conversation_id)
        and doc.upload_state == "ready"
    )
