"""Secret scanning and redaction for agent inputs and outputs.

Agents routinely touch credentials: tool results, pasted configs, chat
history. scan() finds secrets before they leak into logs or prompts;
redact() strips them from text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple

# kind, compiled pattern, redaction placeholder. Order matters: earlier
# patterns win when two patterns overlap the same span.
PATTERNS: List[Tuple[str, "re.Pattern[str]", str]] = [
    (
        "aws_access_key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "[AWS_ACCESS_KEY_REDACTED]",
    ),
    (
        "github_token",
        re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
        "[GITHUB_TOKEN_REDACTED]",
    ),
    (
        "openai_key",
        re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
        "[OPENAI_KEY_REDACTED]",
    ),
    (
        "stripe_key",
        re.compile(r"(?:sk_live|rk_live)_[A-Za-z0-9]{24,}"),
        "[STRIPE_KEY_REDACTED]",
    ),
    (
        "labeled_secret",
        re.compile(
            r"(?i)\b(?:password|passwd|secret|api[_-]?key|auth[_-]?token)\b"
            r"\s*[:=]\s*[\"']?[A-Za-z0-9_\-+/=]{12,}[\"']?"
        ),
        "[SECRET_REDACTED]",
    ),
    (
        "high_entropy_token",
        re.compile(r"\b[A-Za-z0-9_\-]{40,}\b"),
        "[TOKEN_REDACTED]",
    ),
]


@dataclass
class Finding:
    """One detected secret."""

    kind: str
    match: str
    start: int
    end: int
    preview: str


def _preview(match: str) -> str:
    if len(match) > 10:
        return f"{match[:4]}...{match[-2:]}"
    return "*" * len(match)


def _overlaps(start: int, end: int, spans: List[Tuple[int, int]]) -> bool:
    return any(start < s_end and end > s_start for s_start, s_end in spans)


def scan(text: str) -> List[Finding]:
    """Find secrets in text. Returns findings ordered by position."""
    findings: List[Finding] = []
    claimed: List[Tuple[int, int]] = []
    for kind, pattern, _placeholder in PATTERNS:
        for m in pattern.finditer(text):
            start, end = m.span()
            if _overlaps(start, end, claimed):
                continue
            claimed.append((start, end))
            findings.append(
                Finding(
                    kind=kind,
                    match=m.group(0),
                    start=start,
                    end=end,
                    preview=_preview(m.group(0)),
                )
            )
    findings.sort(key=lambda f: f.start)
    return findings


def redact(text: str) -> str:
    """Replace every detected secret in text with its placeholder."""
    result = text
    for _kind, pattern, placeholder in PATTERNS:
        result = pattern.sub(placeholder, result)
    return result
