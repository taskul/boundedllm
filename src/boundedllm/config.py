"""Validated operator configuration, separate from user input and model output."""

import json
import secrets
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from boundedllm.limits import Limits


def require_https(url: str) -> str:
    """Reject credential-bearing, redirected, or ambiguous endpoint definitions."""
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.fragment
        or parts.port not in (None, 443)
    ):
        raise ValueError("endpoint must be an HTTPS URL without credentials or fragments")
    return url


class Settings(BaseSettings):
    """GUARD_* environment variables customize ceilings; no automatic .env loading."""

    model_config = SettingsConfigDict(env_prefix="GUARD_", extra="forbid", frozen=True)
    environment: str = Field(default="development", pattern="^(development|production)$")
    database_url: SecretStr = SecretStr("sqlite:///guard.db")
    # A random development key makes the demo runnable. Production validation below
    # requires GUARD_AUDIT_KEY so restarts cannot silently rotate audit identity.
    audit_key: SecretStr = SecretStr(secrets.token_urlsafe(48))
    audit_key_id: str = Field(default="development-v1", pattern=r"^[A-Za-z0-9_.:@/-]{1,128}$")
    # JSON object of retained key-id to key mappings, normally injected by a
    # secret manager during a verification window after signing-key rotation.
    audit_previous_keys: SecretStr | None = None
    # Optional long-lived key for subject/content pseudonymization only. Signing
    # keys rotate; pseudonyms must not, or subject correlation breaks at every
    # rotation boundary. Defaults to the signing key when unset.
    audit_pseudonym_key: SecretStr | None = None
    otel_logs_endpoint: str | None = None
    otel_authorization: SecretStr | None = None
    issuer: str = "https://id.example.com/"
    audience: str = "secure-ai-api"
    jwks_url: str = "https://id.example.com/.well-known/jwks.json"
    allowed_tenants: frozenset[str] = frozenset()
    algorithms: frozenset[str] = frozenset({"RS256", "ES256"})
    tenant_claim: str = "tenant_id"
    roles_claim: str = "roles"
    scopes_claim: str = "scope"
    access_token_type: str | None = None
    max_token_lifetime_seconds: int = Field(default=3600, ge=60, le=86400)
    jwks_ttl_seconds: int = Field(default=300, ge=30, le=3600)
    jwks_refresh_cooldown_seconds: int = Field(default=30, ge=1, le=300)
    model_name: str = "enterprise-chat-model"
    allowed_models: frozenset[str] = frozenset({"enterprise-chat-model"})
    model_url: str | None = None
    model_api_key: SecretStr | None = None
    max_body_bytes: int = Field(default=32768, ge=1024, le=1048576)
    max_input_chars: int = Field(default=20000, ge=1, le=20000)
    max_output_chars: int = Field(default=12000, ge=1, le=12000)
    max_context_chars: int = Field(default=50000, ge=1024, le=200000)
    max_document_chars: int = Field(default=6000, ge=128, le=10000)
    max_docs: int = Field(default=6, ge=0, le=20)
    max_model_calls: int = Field(default=3, ge=1, le=8)
    max_tool_calls: int = Field(default=2, ge=0, le=8)
    output_tokens_per_call: int = Field(default=800, ge=32, le=4096)
    request_timeout_seconds: float = Field(default=60, gt=0, le=120)
    model_timeout_seconds: float = Field(default=20, gt=0, le=60)
    max_concurrent_requests: int = Field(default=16, ge=1, le=256)
    user_requests_per_minute: int = Field(default=20, ge=1, le=10000)
    tenant_requests_per_minute: int = Field(default=200, ge=1, le=100000)
    tenant_daily_cost_units: int = Field(default=100000, ge=1)
    model_call_cost_units: int = Field(default=100, ge=1)
    auto_approve_below_cents: int = Field(default=0, ge=0, le=10000)
    approval_ttl_seconds: int = Field(default=300, ge=30, le=900)
    max_waiver_cents: int = Field(default=50000, ge=1, le=50000)
    # "reviewed" means the host composes its own Scanner and takes responsibility
    # for evaluating it. Presidio is one option, not a requirement: it is a heavy
    # dependency with its own false-negative profile, and mandating one vendor
    # pushes deployments that cannot take it into disabling DLP entirely.
    dlp_backend: str = Field(default="pattern", pattern="^(pattern|presidio|reviewed)$")
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "testserver")

    @model_validator(mode="before")
    @classmethod
    def require_production_secret(cls, values):
        # This runs before defaults are applied, so production cannot accidentally
        # use the development class-level key after an environment misconfiguration.
        if (
            isinstance(values, dict)
            and values.get("environment") == "production"
            and not values.get("audit_key")
        ):
            raise ValueError("production requires GUARD_AUDIT_KEY")
        return values

    @model_validator(mode="after")
    def validate_boundaries(self):
        if len(self.audit_key.get_secret_value().encode()) < 32:
            raise ValueError("audit_key requires at least 32 bytes")
        if self.audit_pseudonym_key is not None and (
            len(self.audit_pseudonym_key.get_secret_value().encode()) < 32
        ):
            raise ValueError("audit_pseudonym_key requires at least 32 bytes")
        require_https(self.issuer)
        require_https(self.jwks_url)
        if self.model_url:
            require_https(self.model_url)
        if self.otel_logs_endpoint:
            require_https(self.otel_logs_endpoint)
        if not self.algorithms or not self.algorithms <= {"RS256", "ES256"}:
            raise ValueError("only explicitly pinned RS256/ES256 algorithms are supported")
        if self.model_name not in self.allowed_models:
            raise ValueError("configured model must be allowlisted")
        if not self.allowed_hosts or "*" in self.allowed_hosts:
            raise ValueError("explicit HTTP Host allowlist required")
        if self.environment == "production":
            if not self.database_url.get_secret_value().startswith("postgresql+psycopg://"):
                raise ValueError("production requires PostgreSQL with psycopg")
            if not self.allowed_tenants or not self.model_url:
                raise ValueError("production requires an explicit tenant allowlist and model endpoint")
            if self.dlp_backend == "pattern":
                raise ValueError(
                    "production requires a real DLP scanner: set GUARD_DLP_BACKEND=presidio, "
                    "or 'reviewed' and pass your own evaluated Scanner to create_app"
                )
        return self

    def limits(self) -> Limits:
        """Project deployment configuration onto the bounds the engine reads.

        Keeps the engine independent of how a deployment is configured: a host
        embedding ``Guard`` can build ``Limits`` directly and never touch this
        class, its environment prefix, or its database and identity fields.
        """
        return Limits(
            model_name=self.model_name,
            allowed_models=self.allowed_models,
            allowed_tenants=self.allowed_tenants,
            max_input_chars=self.max_input_chars,
            max_output_chars=self.max_output_chars,
            max_context_chars=self.max_context_chars,
            max_document_chars=self.max_document_chars,
            max_docs=self.max_docs,
            max_model_calls=self.max_model_calls,
            max_tool_calls=self.max_tool_calls,
            output_tokens_per_call=self.output_tokens_per_call,
            request_timeout_seconds=self.request_timeout_seconds,
            model_timeout_seconds=self.model_timeout_seconds,
            max_concurrent_requests=self.max_concurrent_requests,
            require_reviewed_scanner=self.environment == "production",
        )

    def previous_audit_keys(self) -> dict[str, str]:
        if self.audit_previous_keys is None:
            return {}
        try:
            value = json.loads(self.audit_previous_keys.get_secret_value())
        except json.JSONDecodeError as exc:
            raise ValueError("GUARD_AUDIT_PREVIOUS_KEYS must be a JSON object") from exc
        if not isinstance(value, dict) or any(
            not isinstance(name, str) or not isinstance(key, str) or len(key.encode()) < 32
            for name, key in value.items()
        ):
            raise ValueError("every previous audit key requires a string id and 32-byte key")
        return value
