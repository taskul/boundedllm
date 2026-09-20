"""Deterministic security boundaries for enterprise LLM applications.

Importing this package starts no servers, reads no credentials, and pulls in no
database driver. The core depends on the storage contracts in
``agentguard.ports``; a host implements them over whatever it already runs, or
imports ``agentguard.adapters.sql`` for a working implementation.

    from agentguard import Audit, Guard, Limits
    from agentguard.adapters.sql import SQLStore, sql_ports

    audit = Audit(key)
    store = SQLStore(settings, audit)
    guard = Guard(provider=provider, signer=audit, **sql_ports(store))

What this package is for: bounding what a compromised agent can reach and do.
Identity, tenant isolation, retrieval ACLs, tool authorization, human consent,
idempotency, quotas, and a tamper-evident ledger are deterministic application
code here, and they hold whether or not the model has been manipulated.

What it is not: a prompt-injection detector. ``agentguard.risk`` is a tripwire for
blunt override attempts, and the bundled ``PatternScanner`` is a test baseline,
not a DLP product. Both are signals. The boundaries above are the controls.
"""

__version__ = "0.4.0"

from agentguard.audit import Audit
from agentguard.engine import Guard
from agentguard.errors import (
    Conflict,
    Denied,
    GuardError,
    InvalidToken,
    LimitExceeded,
    OutputBlocked,
    Unavailable,
)
from agentguard.limits import Limits
from agentguard.model_gateway import ModelProvider, ModelRequest
from agentguard.models import (
    ChatRequest,
    ChatResponse,
    Document,
    IngestRequest,
    Principal,
    ProposedToolCall,
    ToolExecutionResult,
    TurnFlags,
)
from agentguard.output_firewall import Scanner
from agentguard.ports import Documents, Ledger, Operations, Quotas, Signer
from agentguard.telemetry import Observability, OpenTelemetryObservability
from agentguard.tool_gateway import ToolExecutor

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
