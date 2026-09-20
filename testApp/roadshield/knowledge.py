"""Load the synthetic policy manual into stable, retrieval-sized sections."""

import re
from pathlib import Path

KNOWLEDGE_FILE = Path(__file__).parents[1] / "knowledge" / "roadshield_auto_policy.md"


def policy_sections() -> list[tuple[str, str]]:
    """Convert each level-two heading into a stable RAG document."""
    source = KNOWLEDGE_FILE.read_text(encoding="utf-8")
    chunks = re.split(r"(?m)^## ", source)
    sections = []
    for chunk in chunks[1:]:
        title, _, body = chunk.partition("\n")
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
        content = f"RoadShield Personal Auto Policy Guide\nSection: {title}\n\n{body.strip()}"
        if not slug or not body.strip() or len(content) > 10000:
            raise ValueError("invalid RoadShield knowledge section")
        sections.append((f"policy-{slug}", content))
    if not sections:
        raise ValueError("RoadShield knowledge file has no sections")
    return sections
