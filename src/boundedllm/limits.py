"""The ceilings the turn engine enforces, separated from deployment configuration.

``Settings`` also describes a database, an identity provider, and an HTTP
listener. A host that embeds ``Guard`` inside its own service has none of those
concerns and should not have to satisfy them: requiring a valid JWKS URL before a
chat turn can run is the kind of coupling that makes a library unadoptable. This
object carries only what the engine and the model gateway actually read, and
``Settings.limits()`` builds one for deployments that do use the bundled API.
"""

from dataclasses import dataclass, field, replace


@dataclass(frozen=True)
class Limits:
    """Every bound is explicit. Defaults are conservative, not permissive."""

    model_name: str = "enterprise-chat-model"
    allowed_models: frozenset[str] = frozenset({"enterprise-chat-model"})
    # Empty means the host performs its own tenant admission. A populated set is
    # a second, independent check against a token from an unexpected tenant.
    allowed_tenants: frozenset[str] = frozenset()

    max_input_chars: int = 20000
    max_output_chars: int = 12000
    max_context_chars: int = 50000
    max_document_chars: int = 6000

    max_docs: int = 6
    max_model_calls: int = 3
    max_tool_calls: int = 2
    output_tokens_per_call: int = 800

    request_timeout_seconds: float = 60.0
    model_timeout_seconds: float = 20.0
    # Per process. Shared ceilings belong in the Quotas port, which is backed by
    # durable state; this one only protects a single worker's own memory.
    max_concurrent_requests: int = 16

    # Set this wherever the pattern-matching default DLP baseline is not an
    # acceptable control. Composition then fails closed unless a reviewed scanner
    # is supplied, instead of quietly running regexes against regulated data.
    require_reviewed_scanner: bool = False

    # Hosts a model may name in an answer. Empty means none, which is the default
    # and the safer setting; see boundedllm.egress.citation_allowlist for why an
    # entry here is also an exfiltration channel to that host.
    citation_hosts: frozenset[str] = frozenset()

    _validated: bool = field(default=False, repr=False, compare=False)

    def __post_init__(self):
        if self._validated:
            return
        positive = {
            "max_input_chars": self.max_input_chars,
            "max_output_chars": self.max_output_chars,
            "max_context_chars": self.max_context_chars,
            "max_document_chars": self.max_document_chars,
            "max_model_calls": self.max_model_calls,
            "output_tokens_per_call": self.output_tokens_per_call,
            "max_concurrent_requests": self.max_concurrent_requests,
        }
        for name, value in positive.items():
            if value < 1:
                raise ValueError(f"{name} must be at least 1")
        if self.max_docs < 0 or self.max_tool_calls < 0:
            raise ValueError("max_docs and max_tool_calls cannot be negative")
        if self.request_timeout_seconds <= 0 or self.model_timeout_seconds <= 0:
            raise ValueError("timeouts must be positive")
        if self.model_timeout_seconds > self.request_timeout_seconds:
            # Otherwise the request deadline fires first and the model timeout,
            # which produces the more specific failure, can never be reached.
            raise ValueError("model_timeout_seconds must not exceed request_timeout_seconds")
        if self.model_name not in self.allowed_models:
            raise ValueError("model_name must appear in allowed_models")
        if self.max_document_chars * max(self.max_docs, 1) > self.max_context_chars * 8:
            raise ValueError("max_docs by max_document_chars greatly exceeds the context ceiling")
        object.__setattr__(self, "_validated", True)

    def evolve(self, **changes) -> "Limits":
        """Return a revalidated copy; used by hosts that tune one bound per tenant."""
        return replace(self, _validated=False, **changes)
