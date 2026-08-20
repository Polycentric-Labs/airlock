"""Log and output redaction.

Prompts, retrieved documents, tool arguments, and model outputs are never
logged verbatim. Anything that leaves the service boundary as telemetry goes
through `scrub` first; correlation happens by request id, not by content.
"""

from __future__ import annotations

import hashlib
import re

_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"AKIA[0-9A-Z]{16}"), "<redacted:aws-key-id>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "<redacted:private-key>"),
    (re.compile(r"(?i)bearer\s+[a-z0-9\-_\.=]{20,}"), "<redacted:bearer-token>"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}"), "<redacted:github-token>"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}"), "<redacted:github-pat>"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"), "<redacted:api-key>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}[A-Za-z0-9_.-]*"), "<redacted:jwt>"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted:ssn-shape>"),
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "<redacted:email>"),
)


def scrub(text: str) -> str:
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text


def content_ref(text: str) -> str:
    """A loggable stand-in for content: sha256 prefix, never the content."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
