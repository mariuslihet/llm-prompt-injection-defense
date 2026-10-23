"""Conservative text egress sanitizer; never treats regex as the IFC boundary."""

import html
import re
import unicodedata
from dataclasses import dataclass

from packages.policy import allowed_url

CANARY_PATTERN = re.compile(r"FAKE_(?:PRIVATE_CANARY|SECRET|TOKEN)_[A-Za-z0-9_]+")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


@dataclass(frozen=True)
class Sanitized:
    text: str
    findings: tuple[str, ...]


def sanitize(
    text: str, hosts: frozenset[str] = frozenset(), secrets: tuple[str, ...] = ()
) -> Sanitized:
    findings: list[str] = []
    normalized = unicodedata.normalize("NFKC", text)
    clean = "".join(c for c in normalized if unicodedata.category(c) != "Cf")
    if clean != text:
        findings.append("unicode-normalized")
    for secret in secrets:
        if secret and secret in clean:
            clean = clean.replace(secret, "[REDACTED]")
            findings.append("configured-secret")
    clean, count = CANARY_PATTERN.subn("[REDACTED]", clean)
    if count:
        findings.append("canary")
    clean, count = EMAIL.subn("[EMAIL]", clean)
    if count:
        findings.append("pii-email")

    def replace_url(match: re.Match[str]) -> str:
        value = html.unescape(match.group())
        if allowed_url(value, hosts):
            return match.group()
        findings.append("egress-url")
        return "[URL-BLOCKED]"

    clean = URL.sub(replace_url, clean)
    # Raw HTML can conceal alternate URL syntax. Escape all tags, remove all
    # markdown images (including reference form), and neutralize reference links.
    clean, count = re.subn(r"!\[[^\]]*\](?:\([^\n]*?\)|\[[^\]]*\])", "[IMAGE-BLOCKED]", clean)
    if count:
        findings.append("markdown-image")
    if "<" in clean or ">" in clean:
        clean = html.escape(clean)
        findings.append("html-escaped")
    # Render plain text in UIs; sanitizer output must never be used as HTML.
    return Sanitized(clean, tuple(sorted(set(findings))))
