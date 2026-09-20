"""Portable SQL schema for the bundled adapter: tenancy, retries, quotas, audit.

Domain tables are not here. An application's own business objects belong to that
application; the reference support domain defines its tables in
``agentguard.support.schema`` against this same MetaData, so ``create_all`` and the
row-level-security helper cover both when a deployment uses them together.
"""

from sqlalchemy import Column, Float, Index, Integer, MetaData, String, Table, Text

metadata = MetaData()

# Composite primary keys prevent identifier collisions from weakening tenant isolation.
conversations = Table(
    "guard_conversations",
    metadata,
    Column("tenant_id", String(128), primary_key=True),
    Column("id", String(32), primary_key=True),
    Column("subject", String(128), nullable=False),
    Column("created_at", Float, nullable=False),
)
documents = Table(
    "guard_documents",
    metadata,
    Column("tenant_id", String(128), primary_key=True),
    Column("doc_id", String(128), primary_key=True),
    Column("classification", String(16), nullable=False),
    Column("level", Integer, nullable=False),
    Column("source", String(128), nullable=False),
    Column("body", Text, nullable=False),
    # Shared policy documents leave owner/conversation null. Customer uploads
    # bind both fields so users in the same tenant and role remain isolated.
    Column("owner_subject", String(128)),
    Column("conversation_id", String(32)),
    Column("upload_state", String(16), nullable=False, default="ready"),
    Column("content_hash", String(64), nullable=False),
    Column("retention_policy", String(128), nullable=False, default="standard"),
    Column("provenance_verified", Integer, nullable=False),
    Column("created_at", Float, nullable=False),
)
document_roles = Table(
    "guard_document_roles",
    metadata,
    Column("tenant_id", String(128), primary_key=True),
    Column("doc_id", String(128), primary_key=True),
    Column("role", String(128), primary_key=True),
)
operations = Table(
    "guard_operations",
    metadata,
    Column("tenant_id", String(128), primary_key=True),
    Column("subject", String(128), primary_key=True),
    Column("operation_id", String(32), primary_key=True),
    Column("conversation_id", String(32), nullable=False),
    Column("input_digest", String(64), nullable=False),
    Column("state", String(16), nullable=False),
    Column("response", Text),
    Column("output_doc_ids", Text),
    Column("created_at", Float, nullable=False),
)
quotas = Table(
    "guard_quotas",
    metadata,
    Column("tenant_id", String(128), primary_key=True),
    Column("subject", String(128), primary_key=True),
    Column("dimension", String(32), primary_key=True),
    Column("bucket", Integer, primary_key=True),
    Column("used", Integer, nullable=False),
)
audit_events = Table(
    "guard_audit",
    metadata,
    Column("tenant_id", String(128), primary_key=True),
    Column("event_id", String(32), primary_key=True),
    Column("created_at", Float, nullable=False),
    Column("sequence", Integer, nullable=False),
    Column("previous_hash", String(64), nullable=False),
    Column("record_hash", String(64), nullable=False),
    Column("key_id", String(128), nullable=False),
    Column("payload", Text, nullable=False),
    Column("signature", String(64), nullable=False),
)
Index("guard_audit_created", audit_events.c.tenant_id, audit_events.c.created_at)
Index("guard_audit_sequence", audit_events.c.tenant_id, audit_events.c.sequence, unique=True)

# One locked row per tenant serializes chain assignment across application workers.
audit_heads = Table(
    "guard_audit_heads",
    metadata,
    Column("tenant_id", String(128), primary_key=True),
    Column("last_sequence", Integer, nullable=False),
    Column("last_hash", String(64), nullable=False),
)

# The outbox commits with the audit record. A separate worker can deliver these
# signed envelopes to OpenTelemetry/SIEM without making request success depend on it.
audit_outbox = Table(
    "guard_audit_outbox",
    metadata,
    Column("tenant_id", String(128), primary_key=True),
    Column("event_id", String(32), primary_key=True),
    Column("sequence", Integer, nullable=False),
    Column("record_hash", String(64), nullable=False),
    Column("envelope", Text, nullable=False),
    Column("state", String(16), nullable=False),
    Column("attempts", Integer, nullable=False),
    Column("created_at", Float, nullable=False),
    Column("exported_at", Float),
)
Index("guard_outbox_pending", audit_outbox.c.state, audit_outbox.c.created_at)

# Analyst workflow stores no prompt text or free-form notes. External SIEM case
# systems can use case_id while this table retains the local acknowledgement.
security_cases = Table(
    "guard_security_cases",
    metadata,
    Column("tenant_id", String(128), primary_key=True),
    Column("event_id", String(32), primary_key=True),
    Column("state", String(16), nullable=False),
    Column("case_id", String(128)),
    Column("actor_fingerprint", String(64), nullable=False),
    Column("updated_at", Float, nullable=False),
)
