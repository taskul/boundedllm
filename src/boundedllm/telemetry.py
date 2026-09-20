"""Optional metrics and traces. The signed ledger stays authoritative.

Telemetry is an operational convenience and is allowed to fail: every call from
the engine is wrapped in a suppressor, because losing a span must never fail a
request that already committed. Delivery of the ledger itself is a different
concern and lives in ``boundedllm.adapters.otlp``.
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

    Install ``boundedllm[telemetry]`` and configure the SDK/exporter in
    the host process. This class never installs a global provider or reads secrets.
    """

    def __init__(self):
        try:
            from opentelemetry import metrics, trace
        except ImportError as exc:
            raise RuntimeError("install boundedllm[telemetry]") from exc
        self.trace = trace
        # Derived, not literal: a hardcoded version here silently mislabels every
        # span and metric after the next release, and nothing fails to catch it.
        from boundedllm import __version__

        self.tracer = trace.get_tracer("boundedllm", __version__)
        meter = metrics.get_meter("boundedllm", __version__)
        self.requests = meter.create_counter("boundedllm.requests")
        self.duration = meter.create_histogram("boundedllm.request.duration", unit="ms")

    def start_request(self, tenant_id: str, operation_id: str, request_id: str):
        manager = self.tracer.start_as_current_span(
            "boundedllm.chat",
            attributes={
                "boundedllm.tenant_id": tenant_id,
                "boundedllm.operation_id": operation_id,
                "boundedllm.request_id": request_id,
            },
        )
        manager.__enter__()
        self.requests.add(1, {"boundedllm.tenant_id": tenant_id})
        return manager

    def event(self, name: str, fields: dict) -> None:
        attributes = {
            f"boundedllm.{key}": value
            for key, value in fields.items()
            if isinstance(value, (str, bool, int, float))
        }
        self.trace.get_current_span().add_event(f"boundedllm.{name}", attributes=attributes)

    def finish_request(self, handle, status: str, duration_ms: int) -> None:
        span = self.trace.get_current_span()
        span.set_attribute("boundedllm.status", status)
        self.duration.record(duration_ms, {"boundedllm.status": status})
        handle.__exit__(None, None, None)
