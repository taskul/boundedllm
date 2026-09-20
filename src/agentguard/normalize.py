"""Canonicalize a control copy; quarantine invisible payloads away from the model."""

import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class Normalized:
    text: str
    findings: tuple[str, ...]
    hidden_length: int  # Record evidence counts, never recover or log attacker payloads.


def normalize(text: str) -> Normalized:
    findings: set[str] = set()
    visible: list[str] = []
    hidden_length = 0
    for ch in text:
        code = ord(ch)
        category = unicodedata.category(ch)
        if 0xE0000 <= code <= 0xE007F:
            findings.add("unicode_tag_payload")
            hidden_length += 1
        elif category in {"Cf", "Cs"} or (category == "Cc" and ch not in "\n\t"):
            findings.add("invisible_or_control")
        else:
            visible.append(ch)
    original = "".join(visible)
    cleaned = unicodedata.normalize("NFKC", original)
    if cleaned != original:
        findings.add("compatibility_forms")
    return Normalized(cleaned, tuple(sorted(findings)), hidden_length)
