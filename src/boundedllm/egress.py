"""Conservative output policy: model answers contain no actionable network references."""

import re

from boundedllm.errors import OutputBlocked

# Host allowlists alone allow data in paths, queries, fragments, and redirects.
# This library returns text, with no model-generated links. Applications needing
# citations must map authorized document IDs to trusted server-generated URLs.
#
# A scheme is not required for a reference to be actionable. Chat surfaces, mail
# clients, and terminals autolink "host.tld/path", a reader will follow one
# regardless, and an attacker can split the authority and the path across prose
# ("visit evil.invalid, then add /collect?d=...") to evade any rule that only
# matches a complete URL. Bare hostnames are therefore rejected outright. That is
# deliberately stricter than a link check: a model has no authorized way to name
# a network location, and an application that needs a citation maps a stored
# document ID to a server-generated link instead of echoing model text.
#
# Ordinary prose still has to survive this, so file names, version strings, and
# sentence boundaries are excluded below. A false positive fails closed, which is
# the correct direction for an egress control.
FILE_EXTENSION = (
    r"pdf|jpe?g|png|gif|webp|svg|docx?|xlsx?|pptx?|csv|tsv|txt|rtf|zip|gz|tar"
    r"|md|html?|json|ya?ml|xml|log|ini|cfg|toml|py|js|ts|css|sql|sh|bak|tmp"
)
LABELS = r"\b[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62})*"
# A hostname carrying a path, query, fragment, or port is unambiguous, so any
# top-level label length is rejected there. A hostname standing alone in prose is
# only rejected for plausible top-level label lengths, which keeps a missing
# space after a full stop ("applies.Comprehensive") from failing a valid answer.
AUTHORITY_WITH_TARGET = rf"{LABELS}\.(?!(?:{FILE_EXTENSION})\b)[a-z]{{2,24}}(?=[/?#:])"
BARE_AUTHORITY = rf"{LABELS}\.(?!(?:{FILE_EXTENSION})\b)[a-z]{{2,8}}\b"
NETWORK_REFERENCE = re.compile(
    r"(?i)([a-z][a-z0-9+.-]{1,24}:\s*(?://|\\\\)|\b(?:https?|ftp|file|data|javascript|mailto):"
    r"|www\.|!\[|<\s*(?:img|iframe|script|svg|object|embed|link|style)\b|\]\s*\(|\]\s*:|//[a-z0-9]"
    rf"|{AUTHORITY_WITH_TARGET}|{BARE_AUTHORITY})"
)


# An address's domain and its local part both look exactly like a hostname, so
# the rules above would reject any answer merely containing one. Email addresses
# belong to the DLP layer instead: it redacts the whole address, domain included,
# and the post-redaction egress pass still sees whatever it leaves behind. This
# keeps a redactable address from costing the entire answer, while "mailto:" and
# every bare hostname outside an address stay blocked.
# A path, query, fragment, or port after the host means this is a URL carrying
# userinfo ("user:pw@host/collect?d=..."), not an address. Those must not be
# carved out, or an attacker disguises an exfiltration URL as an email.
# The lookahead spans the rest of the host, not just the next character. Checking
# one character lets the engine backtrack to a shorter domain that happens to end
# before the path ("pw@help.example" inside "pw@help.example.com/collect") and
# carve out a URL anyway.
EMAIL = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b(?![\w.-]*[/?#:])")

# IDNA/UTS-46 treats these as label separators, so a browser resolves
# "evil．invalid" and "evil。invalid" to the same host as "evil.invalid".
# NFKC folds only some of them, so the rest are mapped here before matching;
# otherwise a single alternate code point walks a hostname past every rule above.
IDNA_DOTS = str.maketrans({"．": ".", "。": ".", "｡": "."})


def citation_allowlist(hosts) -> re.Pattern | None:
    """Build a matcher for hosts a deployment has decided a model may name.

    Rejecting every network reference is the right default, but a product that has
    to cite its own help centre cannot ship with it, and a team that cannot cite
    will turn the whole control off. This narrows the exception instead: an exact
    host, scheme-less or over HTTPS, with no userinfo and no port.

    It is still the weaker option. A path and a query can carry data to a host you
    allowed, so an allowlisted host is an allowlisted exfiltration channel for
    anything the model can put in a URL. Prefer mapping an authorized document ID
    to a server-generated link, which involves no model-chosen bytes at all. Use
    this when that is not available, and keep the list to hosts you operate.
    """
    hosts = [host.strip().lower() for host in hosts if host and host.strip()]
    if not hosts:
        return None
    for host in hosts:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62})+", host):
            raise ValueError(f"citation host must be a plain hostname: {host!r}")
        if re.fullmatch(r"[\d.]+", host):
            # An address literal cannot be reasoned about, is frequently internal,
            # and is never what a customer-facing citation should point at.
            raise ValueError(f"citation host must not be an IP literal: {host!r}")
    alternatives = "|".join(re.escape(host) for host in sorted(hosts))
    # Anchored at a boundary so "evil-roadshield.com" cannot ride on "roadshield.com",
    # and the optional scheme is fixed to https so no other scheme slips through.
    # "@" is excluded explicitly: "attacker.invalid@help.example.com" reads as the
    # allowed host to this matcher but resolves to the attacker's host in clients
    # that honor userinfo, so the whole reference must stay blocked.
    return re.compile(rf"(?i)(?<![\w.@-])(?:https://)?(?:{alternatives})(?=[/?#\s)\].,;:!]|$)")


def inspect_egress(text: str, allowed_citations: re.Pattern | None = None) -> None:
    candidate = EMAIL.sub(" ", text.translate(IDNA_DOTS))
    if allowed_citations is not None:
        # Remove approved hosts before matching so the rest of the rules still
        # apply to everything else in the same answer.
        candidate = allowed_citations.sub(" ", candidate)
    if NETWORK_REFERENCE.search(candidate):
        raise OutputBlocked("NETWORK_REFERENCE")
