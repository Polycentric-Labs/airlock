"""Runtime policy gate: decides on a request BEFORE any draft is released.

Decision model (fail closed, in plain English):
  BLOCK        the request may not proceed at all
  HUMAN_REVIEW the draft may be produced but is quarantined for a person
  PROCEED      the draft may be returned to the requester

Three independent checks feed the decision, and the worst outcome wins:
  1. Data classification of the request (declared + inferred).
  2. Injection heuristics over the user input AND retrieved content.
  3. Tool-call allowlist over what the drafter actually invoked.

Honest scope note: the injection heuristics are a tripwire, not a defense.
They catch the crude cases and log the rest for a human. Nothing here claims
to "solve" prompt injection; containment lives in the tool allowlist, the
corpus boundary, and the egress rules documented in SECURITY-CONTROLS.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum

from .briefing import ALLOWED_TOOLS


class Decision(IntEnum):
    PROCEED = 0
    HUMAN_REVIEW = 1
    BLOCK = 2


# Ordered least to most sensitive. Unknown classes fail closed to BLOCK.
DATA_CLASSES = ("public", "internal", "member-confidential", "restricted-pii")

CLASS_DECISION = {
    "public": Decision.PROCEED,
    "internal": Decision.PROCEED,
    "member-confidential": Decision.HUMAN_REVIEW,
    "restricted-pii": Decision.BLOCK,
}

# Crude-case tripwires. Deliberately few and legible; see docstring.
INJECTION_PATTERNS = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore (all|any|previous|prior) (instructions|rules)",
        r"disregard (the|your) (system|previous) (prompt|instructions)",
        r"reveal .{0,40}(system prompt|instructions|api key|credentials)",
        r"you are now .{0,40}(unrestricted|jailbroken|developer mode)",
        r"exfiltrate|send .{0,40}(data|contents) to http",
    )
)

# Shapes that suggest someone pasted a live credential or regulated identifier
# into a request. We refuse rather than launder it into a draft.
SECRET_SHAPES = tuple(
    re.compile(p)
    for p in (
        r"AKIA[0-9A-Z]{16}",                      # AWS access key id
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",    # PEM private key
        r"(?i)bearer\s+[a-z0-9\-_\.=]{20,}",      # bearer token
        r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}",  # GitHub token
        r"\bgithub_pat_[A-Za-z0-9_]{22,}",        # GitHub fine-grained PAT
        r"\bsk-[A-Za-z0-9_-]{20,}",               # OpenAI-style API key
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}",  # JWT
        r"\b\d{3}-\d{2}-\d{4}\b",                 # SSN shape
    )
)


@dataclass
class GateResult:
    decision: Decision
    reasons: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return {0: "proceed", 1: "human-review", 2: "block"}[int(self.decision)]


def _worst(a: Decision, b: Decision) -> Decision:
    return a if a >= b else b


def check_data_class(declared: str) -> GateResult:
    if declared not in CLASS_DECISION:
        return GateResult(Decision.BLOCK, [f"unknown data class '{declared}': failing closed"])
    d = CLASS_DECISION[declared]
    reasons = []
    if d is Decision.HUMAN_REVIEW:
        reasons.append("member-confidential data requires a human reviewer before release")
    if d is Decision.BLOCK:
        reasons.append("restricted-pii requests are not served by this assistant")
    return GateResult(d, reasons)


def check_injection(*texts: str) -> GateResult:
    # Scan each text AND their concatenation: retrieved chunks concatenate in
    # a real prompt, so a pattern split across two chunks must still trip.
    candidates = list(texts)
    if len(texts) > 1:
        candidates.append(" ".join(texts))
    for text in candidates:
        for pat in INJECTION_PATTERNS:
            if pat.search(text):
                return GateResult(
                    Decision.BLOCK,
                    [f"injection tripwire matched: /{pat.pattern}/"],
                )
        for pat in SECRET_SHAPES:
            if pat.search(text):
                return GateResult(
                    Decision.BLOCK,
                    ["request contains a credential- or PII-shaped string; refusing to process it"],
                )
    return GateResult(Decision.PROCEED)


def check_tool_calls(tool_calls: list[str]) -> GateResult:
    illegal = sorted(set(tool_calls) - ALLOWED_TOOLS)
    if illegal:
        return GateResult(
            Decision.BLOCK,
            [f"drafter invoked non-allowlisted tool(s): {', '.join(illegal)}"],
        )
    return GateResult(Decision.PROCEED)


def evaluate_input(*request_fields: str, declared_class: str) -> GateResult:
    """Pre-draft gate: run on every request field BEFORE any model runs.

    A request that fails here never reaches the drafter at all, so a blocked
    request costs no model tokens and causes no side effects. Every
    caller-controlled field belongs in request_fields, not just the obvious
    one; a gate that only reads the 'topic' invites smuggling via 'audience'.
    """
    checks = [check_data_class(declared_class), check_injection(*request_fields)]
    decision = Decision.PROCEED
    reasons: list[str] = []
    for c in checks:
        decision = _worst(decision, c.decision)
        reasons.extend(c.reasons)
    return GateResult(decision, reasons)


def evaluate_output(
    retrieved_texts: list[str] | None = None,
    tool_calls: list[str] | None = None,
) -> GateResult:
    """Post-draft gate: what the drafter retrieved and which tools it called."""
    checks = [
        check_injection(*(retrieved_texts or [])),
        check_tool_calls(tool_calls or []),
    ]
    decision = Decision.PROCEED
    reasons: list[str] = []
    for c in checks:
        decision = _worst(decision, c.decision)
        reasons.extend(c.reasons)
    return GateResult(decision, reasons)


def evaluate(
    request_text: str,
    declared_class: str,
    retrieved_texts: list[str] | None = None,
    tool_calls: list[str] | None = None,
) -> GateResult:
    """Combine all checks; the worst individual outcome is the decision.

    Convenience wrapper over evaluate_input + evaluate_output for tests and
    single-shot callers. Serving paths should call the two stages separately
    so blocked input never reaches the model (see function_app.py).
    """
    a = evaluate_input(request_text, declared_class=declared_class)
    b = evaluate_output(retrieved_texts, tool_calls)
    return GateResult(_worst(a.decision, b.decision), a.reasons + b.reasons)
