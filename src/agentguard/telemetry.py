"""Optional metrics and traces. The signed ledger stays authoritative.

Telemetry is an operational convenience and is allowed to fail: every call from
the engine is wrapped in a suppressor, because losing a span must never fail a
request that already committed. Delivery of the ledger itself is a different
concern and lives in ``agentguard.adapters.otlp``.
"""

from typing import Any, Protocol


class Observability(Protocol):
    """Optional metrics and trace hook; the signed database ledger stays authoritative."""

    def start_request(self, tenant_id: str, operation_id: str, request_id: str) -> Any: ...

    def event(self, name: str, fields: dict) -> None: ...

    def finish_request(self, handle: Any, status: str, duration_ms: int) -> None: ...


class NoopObservability:
    """Zero-dependency default used when the host has no OpenTelemetry SDK."""

    def start_request(self, tenant_id: str, operation_id: str, request_id: str) -> None:
        return None

    def event(self, name: str, fields: dict) -> None:
        return None

    def finish_request(self, handle: Any, status: str, duration_ms: int) -> None:
        return None


class OpenTelemetryObservability:
    """Use the host-configured OpenTelemetry providers for safe metrics and traces.

    Install ``agentguard[telemetry]`` and configure the SDK/exporter in
    the host process. This class never installs a global provider or reads secrets.
    """

    def __init__(self):
        try:
            from opentelemetry import metrics, trace
        except ImportError as exc:
            raise RuntimeError("install agentguard[telemetry]") from exc
        self.trace = trace
        # Derived, not literal: a hardcoded version here silently mislabels every
        # span and metric after the next release, and nothing fails to catch it.
        from agentguard import __version__

        self.tracer = trace.get_tracer("agentguard", __version__)
        meter = metrics.get_meter("agentguard", __version__)
        self.requests = meter.create_counter("agentguard.requests")
        self.duration = meter.create_histogram("agentguard.request.duration", unit="ms")

    def start_request(self, tenant_id: str, operation_id: str, request_id: str):
        manager = self.tracer.start_as_current_span(
            "agentguard.chat",
            attributes={
                "agentguard.tenant_id": tenant_id,
                "agentguard.operation_id": operation_id,
                "agentguard.request_id": request_id,
            },
        )
        manager.__enter__()
        self.requests.add(1, {"agentguard.tenant_id": tenant_id})
        return manager

    def event(self, name: str, fields: dict) -> None:
        attributes = {
            f"agentguard.{key}": value
            for key, value in fields.items()
            if isinstance(value, (str, bool, int, float))
        }
        self.trace.get_current_span().add_event(f"agentguard.{name}", attributes=attributes)

    def finish_request(self, handle, status: str, duration_ms: int) -> None:
        span = self.trace.get_current_span()
        span.set_attribute("agentguard.status", status)
        self.duration.record(duration_ms, {"agentguard.status": status})
        handle.__exit__(None, None, None)
