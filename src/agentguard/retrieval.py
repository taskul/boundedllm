"""A tripwire for a document port that does not enforce what it promised.

``Documents.search`` is required to apply tenant, owner, conversation,
classification, and role predicates in its own query. This module re-checks the
result anyway. That is not redundancy for its own sake: retrieval adapters are
the component most often swapped for a vector database, and a filter silently
dropped during that swap is invisible until it leaks. A violation here means the
adapter is wrong, so the turn fails closed rather than trusting the rows.
"""

from agentguard.authz import can_read
from agentguard.errors import Unavailable
from agentguard.models import Document, Principal
from agentguard.ports import Documents


async def secure_search(
    documents: Documents,
    principal: Principal,
    query: str,
    limit: int,
    max_level: int,
    conversation_id: str,
    attachment_ids: list[str],
) -> list[Document]:
    docs = await documents.search(principal, query, limit, max_level, conversation_id, attachment_ids)
    if (
        not isinstance(docs, list)
        or len(docs) > limit
        or any(
            not isinstance(doc, Document) or not can_read(principal, doc, max_level, conversation_id)
            for doc in docs
        )
        # An attachment the caller named must come back through the same ACL
        # path as everything else, so a port cannot honor it by bypassing them.
        or not set(attachment_ids) <= {doc.doc_id for doc in docs}
    ):
        raise Unavailable("ACL_INVARIANT_VIOLATION")
    return docs
