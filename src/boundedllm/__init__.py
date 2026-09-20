"""Deterministic security boundaries for enterprise LLM applications.

Importing this package starts no servers, reads no credentials, and pulls in no
database driver. The core depends on the storage contracts in
``boundedllm.ports``; a host implements them over whatever it already runs, or
imports ``boundedllm.adapters.sql`` for a working implementation.

    from boundedllm import Audit, Guard, Limits
    from boundedllm.adapters.sql import SQLStore, sql_ports

    audit = Audit(key)
    store = SQLStore(settings, audit)
    guard = Guard(provider=provider, signer=audit, **sql_ports(store))

What this package is for: bounding what a compromised agent can reach and do.
Identity, tenant isolation, retrieval ACLs, tool authorization, human consent,
idempotency, quotas, and a tamper-evident ledger are deterministic application
code here, and they hold whether or not the model has been manipulated.

What it is not: a prompt-injection detector. ``boundedllm.risk`` is a tripwire for
blunt override attempts, and the bundled ``PatternScanner`` is a test baseline,
not a DLP product. Both are signals. The boundaries above are the controls.
"""

__version__ = "0.4.0"

from boundedllm.audit import Audit
from boundedllm.engine import Guard
from boundedllm.errors import (
    Conflict,
    Denied,
    GuardError,
    InvalidToken,
    LimitExceeded,
    OutputBlocked,
    Unavailable,
)
from boundedllm.limits import Limits
from boundedllm.model_gateway import ModelProvider, ModelRequest
from boundedllm.models import (
    ChatRequest,
    ChatResponse,
    Document,
    IngestRequest,
    Principal,
    ProposedToolCall,
    ToolExecutionResult,
    TurnFlags,
)
from boundedllm.output_firewall import Scanner
from boundedllm.ports import Documents, Ledger, Operations, Quotas, Signer
from boundedllm.telemetry import Observability, OpenTelemetryObservability
from boundedllm.tool_gateway import ToolExecutor

__all__ = [
    "Audit",
    "ChatRequest",
    "ChatResponse",
    "Conflict",
    "Denied",
    "Document",
    "Documents",
    "Guard",
    "GuardError",
    "IngestRequest",
    "InvalidToken",
    "Ledger",
    "LimitExceeded",
    "Limits",
    "ModelProvider",
    "ModelRequest",
    "Observability",
    "OpenTelemetryObservability",
    "Operations",
    "OutputBlocked",
    "Principal",
    "ProposedToolCall",
    "Quotas",
    "Scanner",
    "Signer",
    "ToolExecutionResult",
    "ToolExecutor",
    "TurnFlags",
    "Unavailable",
    "__version__",
]
