"""SQL tables for the reference support domain, registered on the shared MetaData.

Separated from the adapter schema so the core package ships no opinion about
accounts or fee waivers, while a deployment that uses both still gets one
``create_all`` and one row-level-security pass.
"""

from sqlalchemy import Column, Float, Index, Integer, String, Table, Text

from boundedllm.adapters.sql.schema import metadata

accounts = Table(
    "guard_accounts",
    metadata,
    Column("tenant_id", String(128), primary_key=True),
    Column("account_id", String(40), primary_key=True),
    Column("owner_subject", String(128), nullable=False),
    Column("status", String(16), nullable=False),
    Column("currency", String(3), nullable=False),
    Column("fee_cents", Integer, nullable=False),
    Column("version", Integer, nullable=False, default=1),
)
actions = Table(
    "guard_actions",
    metadata,
    Column("tenant_id", String(128), primary_key=True),
    Column("id", String(32), primary_key=True),
    Column("subject", String(128), nullable=False),
    Column("operation_id", String(32), nullable=False),
    Column("conversation_id", String(32), nullable=False),
    Column("arguments", Text, nullable=False),
    Column("arguments_digest", String(64), nullable=False),
    Column("account_version", Integer, nullable=False),
    Column("state", String(16), nullable=False),
    Column("expires_at", Float, nullable=False),
    Column("receipt", Text),
    Column("created_at", Float, nullable=False),
)
Index(
    "guard_one_mutation_per_operation",
    actions.c.tenant_id,
    actions.c.subject,
    actions.c.operation_id,
    unique=True,
)
