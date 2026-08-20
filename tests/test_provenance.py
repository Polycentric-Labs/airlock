"""Provenance binding: build, verify, and prove that tampering fails."""

import json

from app import provenance


def _make_artifact(tmp_path, content=b"artifact-bytes-v1"):
    artifact = tmp_path / "airlock-app.zip"
    artifact.write_bytes(content)
    return artifact


def test_statement_verifies_against_untouched_artifact(tmp_path):
    artifact = _make_artifact(tmp_path)
    verdict = json.dumps({"decision": "promote", "reasons": []})
    st = provenance.build_statement(artifact, "c" * 40, "ci:test", verdict)
    ok, problems = provenance.verify_statement(
        st, artifact, expected_commit="c" * 40, policy_verdict_json=verdict
    )
    assert ok, problems


def test_tampered_artifact_fails_verification(tmp_path):
    artifact = _make_artifact(tmp_path)
    st = provenance.build_statement(artifact, "c" * 40, "ci:test", "{}")
    artifact.write_bytes(b"artifact-bytes-v1 PLUS ONE MALICIOUS BYTE")
    ok, problems = provenance.verify_statement(st, artifact)
    assert not ok
    assert any("digest mismatch" in p for p in problems)


def test_wrong_commit_fails_verification(tmp_path):
    artifact = _make_artifact(tmp_path)
    st = provenance.build_statement(artifact, "c" * 40, "ci:test", "{}")
    ok, problems = provenance.verify_statement(st, artifact, expected_commit="d" * 40)
    assert not ok
    assert any("sourceCommit" in p for p in problems)


def test_swapped_policy_verdict_fails_verification(tmp_path):
    artifact = _make_artifact(tmp_path)
    honest = json.dumps({"decision": "block", "reasons": ["sast failed"]})
    st = provenance.build_statement(artifact, "c" * 40, "ci:test", honest)
    forged = json.dumps({"decision": "promote", "reasons": []})
    ok, problems = provenance.verify_statement(st, artifact, policy_verdict_json=forged)
    assert not ok
    assert any("verdict digest" in p for p in problems)


def test_statement_roundtrip(tmp_path):
    artifact = _make_artifact(tmp_path)
    st = provenance.build_statement(artifact, "c" * 40, "ci:test", "{}")
    out = tmp_path / "provenance.json"
    provenance.write_statement(st, out)
    assert provenance.read_statement(out) == st
