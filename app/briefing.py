"""Deterministic mock-LLM briefing drafter, grounded in a local corpus.

This stands in for the model call so the whole service runs keyless and the
pipeline can be exercised end to end. The interface is the point: the drafter
can only see documents returned by the corpus tools, must cite what it used,
and returns a structured result the policy gate can evaluate.

Swapping in a real model changes ONE function (`_compose`) and nothing about
the controls around it. That is deliberate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"

# The only tools the drafter is permitted to invoke. Anything else is a
# policy violation surfaced by the gate (see policy_gate.check_tool_calls).
ALLOWED_TOOLS = frozenset({"corpus.search", "corpus.read"})


@dataclass
class Draft:
    topic: str
    audience: str
    body: str
    citations: list[str] = field(default_factory=list)
    tool_calls: list[str] = field(default_factory=list)


def _tokenize(text: str) -> set[str]:
    return {w.lower() for w in re.findall(r"[a-zA-Z]{3,}", text)}


def corpus_search(query: str) -> list[Path]:
    """Rank corpus documents by naive token overlap with the query."""
    q = _tokenize(query)
    scored: list[tuple[int, Path]] = []
    for doc in sorted(CORPUS_DIR.glob("*.md")):
        overlap = len(q & _tokenize(doc.read_text(encoding="utf-8")))
        if overlap:
            scored.append((overlap, doc))
    scored.sort(key=lambda t: (-t[0], t[1].name))
    return [doc for _, doc in scored[:2]]


def corpus_read(doc: Path) -> str:
    resolved = doc.resolve()
    if resolved.parent != CORPUS_DIR or resolved.suffix != ".md":
        raise PermissionError(f"corpus.read outside corpus dir: {doc}")
    return resolved.read_text(encoding="utf-8")


def _first_paragraphs(text: str, n: int = 2) -> list[str]:
    paras = [p.strip() for p in text.split("\n\n") if p.strip() and not p.startswith("#")]
    return paras[:n]


def _compose(topic: str, audience: str, sources: dict[str, str]) -> str:
    """The 'model'. Deterministic: stitches cited paragraphs, no generation."""
    lines = [f"BRIEFING: {topic}", f"Audience: {audience}", ""]
    for name, text in sources.items():
        for para in _first_paragraphs(text):
            lines.append(f"{para} [source: {name}]")
        lines.append("")
    lines.append("Every statement above is traceable to a cited corpus document.")
    return "\n".join(lines).strip()


def draft_briefing(topic: str, audience: str = "internal staff") -> Draft:
    """Draft a briefing using only allowlisted corpus tools, with citations."""
    tool_calls = ["corpus.search"]
    docs = corpus_search(topic)
    sources: dict[str, str] = {}
    for doc in docs:
        tool_calls.append("corpus.read")
        sources[doc.name] = corpus_read(doc)
    if not sources:
        body = (
            f"BRIEFING: {topic}\nAudience: {audience}\n\n"
            "No grounded sources found in the corpus for this topic. "
            "Declining to draft rather than inventing content."
        )
        return Draft(topic, audience, body, citations=[], tool_calls=tool_calls)
    body = _compose(topic, audience, sources)
    return Draft(topic, audience, body, citations=sorted(sources), tool_calls=tool_calls)
