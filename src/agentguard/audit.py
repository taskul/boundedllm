"""Allowlisted metadata-only audit records with keyed content fingerprints."""

import hashlib
import hmac
import json
import time
from uuid import uuid4

from agentguard.models import RequestContext

# Reject arbitrary fields so accidental prompt/credential logging is a hard error.
ALLOWED_FIELDS = frozenset(
    {
        "code",
        "status",
        "tool",
        "action_id",
        "operation_id",
        "document_ids",
        "count",
        "signals",
        "hidden_length",
        "input_fingerprint",
        "output_fingerprint",
        "policy_version",
        "cost_units",
        "model",
        "latency_ms",
        "arguments_digest",
        "state",
        "actor_fingerprint",
        "severity",
        "classification",
        "upload_state",
        "content_hash",
        "retention_policy",
        "conversation_fingerprint",
        "export_destination",
        "checkpoint_sequence",
        "checkpoint_hash",
        "related_event_id",
        "case_id",
    }
)


class Audit:
    """Store records through the repository; mutations write events in their transaction."""

    def __init__(
        self,
        key: str,
        key_id: str = "development-v1",
        verification_keys: dict[str, str] | None = None,
        pseudonym_key: str | None = None,
    ):
        self.key = key.encode()
        self.key_id = key_id
        self.verification_keys = {
            **{name: value.encode() for name, value in (verification_keys or {}).items()},
            key_id: self.key,
        }
        # Pseudonymization and signing are separate purposes with different
        # lifetimes. Signing keys rotate on a schedule; a pseudonym key must stay
        # stable or an analyst can no longer follow one subject across a rotation.
        # Defaulting to the signing key preserves existing fingerprints when no
        # dedicated key is provisioned.
        self.pseudonym_key = (pseudonym_key or key).encode()

    @classmethod
    def from_settings(cls, settings) -> "Audit":
        """Single construction path so no adapter silently drops a retained key."""
        return cls(
            settings.audit_key.get_secret_value(),
            settings.audit_key_id,
            settings.previous_audit_keys(),
            settings.audit_pseudonym_key.get_secret_value()
            if settings.audit_pseudonym_key is not None
            else None,
        )

    def fingerprint(self, value: str) -> str:
        return hmac.new(self.pseudonym_key, value.encode(), hashlib.sha256).hexdigest()

    def matches(self, value: str, digest: str) -> bool:
        """Verify a stored digest against every key version this deployment retains.

        Stored integrity digests (action arguments, operation inputs) outlive a
        single signing key. Comparing only against the current key would reject
        every approval and idempotent retry created before a rotation, so the
        retained verification keys and the pseudonym key are all candidates.
        """
        if not isinstance(digest, str):
            return False
        candidates = [self.pseudonym_key, self.key, *self.verification_keys.values()]
        return any(
            hmac.compare_digest(hmac.new(key, value.encode(), hashlib.sha256).hexdigest(), digest)
            for key in candidates
        )

    def record(
        self,
        ctx: RequestContext,
        event_type: str,
        *,
        sequence: int,
        previous_hash: str,
        **fields,
    ) -> dict:
        if not fields.keys() <= ALLOWED_FIELDS:
            raise ValueError("audit fields are not allowlisted")
        if "severity" not in fields:
            if event_type in {"request_blocked", "document_quarantined"}:
                fields["severity"] = "high"
            elif event_type in {"request_failed", "document_upload_rejected"}:
                fields["severity"] = "medium"
            else:
                fields["severity"] = "info"
        payload = {
            "event_id": uuid4().hex,
            "timestamp": time.time(),
            "request_id": ctx.request_id,
            "subject_fingerprint": self.fingerprint(ctx.principal.subject),
            "tenant_id": ctx.principal.tenant_id,
            "event_type": event_type,
            "sequence": sequence,
            "previous_hash": previous_hash,
            "key_id": self.key_id,
            **fields,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        signature = self.fingerprint(encoded)
        record_hash = hashlib.sha256(f"{previous_hash}.{encoded}.{signature}".encode()).hexdigest()
        return {
            "event_id": payload["event_id"],
            "tenant_id": ctx.principal.tenant_id,
            "created_at": payload["timestamp"],
            "sequence": sequence,
            "previous_hash": previous_hash,
            "record_hash": record_hash,
            "key_id": self.key_id,
            "payload": encoded,
            "signature": signature,
        }

    def verify(self, row: dict) -> bool:
        """Verify this key version's signature and chained record digest."""
        key = self.verification_keys.get(row.get("key_id"))
        if key is None:
            return False
        encoded = row["payload"]
        signature = hmac.new(key, encoded.encode(), hashlib.sha256).hexdigest()
        expected_hash = hashlib.sha256(f"{row['previous_hash']}.{encoded}.{signature}".encode()).hexdigest()
        return hmac.compare_digest(signature, row["signature"]) and hmac.compare_digest(
            expected_hash, row["record_hash"]
        )
