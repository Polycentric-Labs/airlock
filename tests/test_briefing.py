"""The drafter: grounded, cited, tool-bounded, and honest when it has nothing."""

import pytest

from app import briefing


def test_draft_is_grounded_and_cited():
    d = briefing.draft_briefing("membership renewal engagement", "membership team")
    assert d.citations, "a grounded draft must cite at least one corpus document"
    for c in d.citations:
        assert f"[source: {c}]" in d.body


def test_draft_declines_without_sources():
    d = briefing.draft_briefing("zzz qqq xyzzy")
    assert d.citations == []
    assert "Declining to draft" in d.body


def test_drafter_only_uses_allowlisted_tools():
    d = briefing.draft_briefing("grant proposal impact metrics")
    assert set(d.tool_calls) <= briefing.ALLOWED_TOOLS


def test_corpus_read_refuses_paths_outside_corpus(tmp_path):
    outside = tmp_path / "evil.md"
    outside.write_text("exfiltrate me", encoding="utf-8")
    with pytest.raises(PermissionError):
        briefing.corpus_read(outside)


def test_corpus_read_refuses_non_markdown():
    target = briefing.CORPUS_DIR / ".." / "policy_gate.py"
    with pytest.raises(PermissionError):
        briefing.corpus_read(target)
