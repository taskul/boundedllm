"""Insurance and authentication tables are separate from the guard library's tables."""

from sqlalchemy import Column, Float, Integer, MetaData, String, Table, Text, UniqueConstraint

metadata = MetaData()

users = Table(
    "demo_users",
    metadata,
    Column("id", String(32), primary_key=True),
    Column("tenant_id", String(64), nullable=False),
    Column("email", String(254), nullable=False),
    Column("password_hash", Text, nullable=False),
    Column("display_name", String(100), nullable=False),
    Column("phone", String(32), nullable=False),
    Column("address", String(200), nullable=False),
    Column("role", String(32), nullable=False),
    Column("scopes", Text, nullable=False),
    Column("conversation_id", String(32), nullable=False),
    # Synthetic lab secret; production stores MFA material encrypted through KMS/HSM.
    Column("mfa_secret", String(64)),
    UniqueConstraint("tenant_id", "email", name="demo_user_email_tenant"),
)

policies = Table(
    "insurance_policies",
    metadata,
    Column("id", String(32), primary_key=True),
    Column("tenant_id", String(64), nullable=False),
    Column("user_id", String(32), nullable=False),
    Column("policy_number", String(32), nullable=False, unique=True),
    Column("vehicle", String(120), nullable=False),
    Column("coverage", String(64), nullable=False),
    Column("premium_cents", Integer, nullable=False),
    Column("deductible_cents", Integer, nullable=False),
    Column("status", String(20), nullable=False),
    Column("renewal_date", String(10), nullable=False),
    Column("account_id", String(40), nullable=False),
)

claims = Table(
    "insurance_claims",
    metadata,
    Column("id", String(32), primary_key=True),
    Column("tenant_id", String(64), nullable=False),
    Column("user_id", String(32), nullable=False),
    Column("claim_number", String(32), nullable=False, unique=True),
    Column("incident_date", String(10), nullable=False),
    Column("status", String(20), nullable=False),
    Column("summary", Text, nullable=False),
    Column("amount_cents", Integer, nullable=False),
)

sessions = Table(
    "auth_sessions",
    metadata,
    Column("token_hash", String(64), primary_key=True),
    Column("user_id", String(32), nullable=False),
    Column("tenant_id", String(64), nullable=False),
    Column("csrf_hash", String(64), nullable=False),
    Column("expires_at", Float, nullable=False),
    Column("created_at", Float, nullable=False),
)

login_limits = Table(
    "login_limits",
    metadata,
    Column("key_hash", String(64), primary_key=True),
    Column("bucket", Integer, primary_key=True),
    Column("attempts", Integer, nullable=False),
)

attack_runs = Table(
    "attack_runs",
    metadata,
    Column("id", String(32), primary_key=True),
    Column("tenant_id", String(64), nullable=False),
    Column("user_id", String(32), nullable=False),
    Column("scenario", String(64), nullable=False),
    Column("result_status", String(32), nullable=False),
    Column("protected", Integer, nullable=False),
    Column("created_at", Float, nullable=False),
)
