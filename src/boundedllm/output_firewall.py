"""Inspect complete text before release; semantic disclosure remains a residual risk."""

import asyncio
import re
from typing import Protocol

from boundedllm.egress import inspect_egress
from boundedllm.errors import OutputBlocked, Unavailable
from boundedllm.normalize import normalize

SECRET = re.compile(
    r"(?i)(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bbearer\s+\S{16,}"
    r"|\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*\S{8,}"
    r"|\bsk-[a-z0-9_-]{20,}|\bAKIA[0-9A-Z]{16}|\bgh[pousr]_[a-z0-9]{30,}"
    r"|\beyJ[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,})"
)
PII = re.compile(
    r"(?i)(\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|\b\d{3}-\d{2}-\d{4}\b"
    r"|(?<!\d)(?:\d[ -]?){13,19}(?!\d)|\+\d[\d ()-]{8,}\d)"
)


class Scanner(Protocol):
    """Custom DLP must fail by raising; a timeout is never a permission to release."""

    async def redact(self, text: str) -> str: ...


class PatternScanner:
    """Offline baseline for tests/demo; cannot identify names or contextual regulated data."""

    async def redact(self, text: str) -> str:
        return PII.sub("[REDACTED]", text)


class PresidioScanner:
    """Load once at composition time; the host provisions and evaluates the NLP model."""

    def __init__(self):
        from presidio_analyzer import AnalyzerEngine
        from presidio_anonymizer import AnonymizerEngine

        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()

    async def redact(self, text: str) -> str:
        def run():
            results = self.analyzer.analyze(text=text, language="en")
            return self.anonymizer.anonymize(text=text, analyzer_results=results).text

        try:
            return await asyncio.to_thread(run)
        except Exception as exc:
            raise Unavailable("DLP_FAILURE") from exc


class OutputFirewall:
    """Also usable on input context to minimize provider-side disclosure."""

    def __init__(self, scanner: Scanner, max_chars: int, allowed_citations=None):
        self.scanner = scanner
        self.max_chars = max_chars
        # None means the default: no model-generated network reference is released.
        self.allowed_citations = allowed_citations

    async def minimize(self, text: str) -> str:
        cleaned = normalize(text).text
        if SECRET.search(cleaned):
            raise OutputBlocked("SECRET_MATERIAL")
        try:
            result = await self.scanner.redact(cleaned)
        except Exception as exc:
            raise Unavailable("DLP_FAILURE") from exc
        if not isinstance(result, str) or len(result) > max(len(cleaned) * 4, 1024):
            raise Unavailable("DLP_SCHEMA")
        return result

    async def inspect(self, text: str) -> str:
        if len(text) > self.max_chars:
            raise OutputBlocked("OUTPUT_TOO_LARGE")
        # Inspect both pre- and post-redaction forms; scanners cannot introduce links.
        inspect_egress(normalize(text).text, self.allowed_citations)
        result = await self.minimize(text)
        inspect_egress(result, self.allowed_citations)
        if len(result) > self.max_chars:
            raise OutputBlocked("OUTPUT_TOO_LARGE")
        return result
