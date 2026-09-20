"""Safely extract inert text from customer PDFs before tenant-scoped RAG ingestion."""

import io
import re
from dataclasses import dataclass
from pathlib import Path

from pypdf import PdfReader

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_PAGES = 20
MAX_EXTRACTED_CHARS = 10000
# Bound the object-graph walk so a deeply nested or wide document cannot turn
# validation itself into the denial of service.
MAX_OBJECT_DEPTH = 24
MAX_OBJECT_FANOUT = 512

# RoadShield's demo accepts text-only PDFs. Active actions, forms, attachments,
# and remote references are unnecessary for RAG and expand the attack surface.
#
# These names are checked against the parsed object graph, not the raw bytes. A
# raw-byte scan looks sufficient but misses everything inside a compressed object
# stream, which is where PDF 1.5 and later put most objects by default, so a
# crafted file could carry /OpenAction and /JavaScript straight past it.
FORBIDDEN_PDF_TOKENS = (
    b"/JavaScript",
    b"/JS",
    b"/OpenAction",
    b"/AA",
    b"/Launch",
    b"/EmbeddedFile",
    b"/Filespec",
    b"/RichMedia",
    b"/XFA",
    b"/AcroForm",
    b"/SubmitForm",
    b"/GoToR",
)
# The raw-byte prefilter compares bytes; the object-graph walk compares parsed
# PDF names, which are str. Deriving one from the other keeps the two checks from
# drifting apart, and a str/bytes mismatch here would silently pass everything.
FORBIDDEN_PDF_NAMES = frozenset(token.decode("ascii") for token in FORBIDDEN_PDF_TOKENS)


class DocumentRejected(ValueError):
    """A public, non-sensitive reason that an uploaded document was rejected."""


@dataclass(frozen=True)
class ParsedPDF:
    filename: str
    text: str
    pages: int


def _reject_active_objects(node, depth: int = 0, seen: set[int] | None = None) -> None:
    """Walk the resolved object graph and refuse any active-content key.

    Object streams are decompressed by the parser before this runs, so a name
    hidden inside a Flate-compressed stream is visible here even though it never
    appears in the raw upload bytes.
    """
    seen = seen if seen is not None else set()
    if depth > MAX_OBJECT_DEPTH or id(node) in seen:
        return
    seen.add(id(node))
    try:
        node = node.get_object()
    except Exception:  # A reference that will not resolve carries no active content.
        return
    if isinstance(node, dict):
        for key, value in node.items():
            if str(key) in FORBIDDEN_PDF_NAMES:
                raise DocumentRejected("active PDF content is not allowed")
            _reject_active_objects(value, depth + 1, seen)
    elif isinstance(node, list):
        for value in node[:MAX_OBJECT_FANOUT]:
            _reject_active_objects(value, depth + 1, seen)
    elif isinstance(node, str) and str(node) in FORBIDDEN_PDF_NAMES:
        raise DocumentRejected("active PDF content is not allowed")


def parse_pdf(filename: str | None, content_type: str | None, payload: bytes) -> ParsedPDF:
    """Validate PDF structure and return bounded plain text without writing the file."""
    safe_name = Path(filename or "upload.pdf").name
    if content_type != "application/pdf" or not safe_name.lower().endswith(".pdf"):
        raise DocumentRejected("only PDF files are accepted")
    if not payload.startswith(b"%PDF-"):
        raise DocumentRejected("file signature is not PDF")
    if not payload or len(payload) > MAX_UPLOAD_BYTES:
        raise DocumentRejected("PDF exceeds the 2 MB limit")
    # Cheap pre-filter on the uncompressed portion. It is not sufficient on its
    # own; the object-graph walk below is the control that actually holds.
    if any(token in payload for token in FORBIDDEN_PDF_TOKENS):
        raise DocumentRejected("active PDF content is not allowed")
    try:
        reader = PdfReader(io.BytesIO(payload), strict=True)
        if reader.is_encrypted:
            raise DocumentRejected("encrypted PDFs are not accepted")
        if not 1 <= len(reader.pages) <= MAX_PAGES:
            raise DocumentRejected("PDF must contain 1-20 pages")
        _reject_active_objects(reader.trailer)
        parts = []
        for page in reader.pages:
            if page.get("/Annots"):
                raise DocumentRejected("PDF annotations are not allowed")
            _reject_active_objects(page)
            parts.append(page.extract_text() or "")
    except DocumentRejected:
        raise
    except Exception as exc:
        raise DocumentRejected("PDF could not be safely parsed") from exc
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", "\n".join(parts)).strip()
    if len(text) < 20:
        raise DocumentRejected("PDF contains no usable text")
    if len(text) > MAX_EXTRACTED_CHARS:
        raise DocumentRejected("extracted PDF text exceeds 10000 characters")
    return ParsedPDF(safe_name[:120], text, len(reader.pages))
