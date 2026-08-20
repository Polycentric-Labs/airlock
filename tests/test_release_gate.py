"""The promotion gate: one happy path, four demonstrable rejections, fail-closed edges."""

import copy

from app import release_gate

GOOD = {
    "artifact": {"name": "airlock-app.zip", "sha256": "a" * 64},
    "source": {"commit": "b" * 40},
    "change": {"risk_tier": "standard", "approvals": []},
    "evidence": {
        "tests": {"result": "pass", "count": 25},
        "secret_scan": {"result": "pass"},
        "sast": {"result": "pass"},
        "dependency_audit": {"result": "pass"},
        "sbom": {"present": True},
        "provenance": {"verified": True, "subject_sha256": "a" * 64},
    },
}


def test_happy_path_promotes():
    assert release_gate.evaluate(copy.deepcopy(GOOD)).decision == "promote"


# --- The four demonstrable rejection cases -------------------------------

def test_rejection_1_failed_sast_blocks():
    m = copy.deepcopy(GOOD)
    m["evidence"]["sast"]["result"] = "fail"
    v = release_gate.evaluate(m)
    assert v.decision == "block"
    assert any("static analysis" in r for r in v.reasons)


def test_rejection_2_missing_sbom_blocks():
    m = copy.deepcopy(GOOD)
    m["evidence"]["sbom"]["present"] = False
    v = release_gate.evaluate(m)
    assert v.decision == "block"
    assert any("SBOM" in r for r in v.reasons)


def test_rejection_3_provenance_digest_mismatch_blocks():
    m = copy.deepcopy(GOOD)
    m["evidence"]["provenance"]["subject_sha256"] = "c" * 64
    v = release_gate.evaluate(m)
    assert v.decision == "block"
    assert any("does not match the artifact digest" in r for r in v.reasons)


def test_rejection_4_high_tier_without_approvals_blocks():
    m = copy.deepcopy(GOOD)
    m["change"]["risk_tier"] = "high"
    m["change"]["approvals"] = ["one.person"]
    v = release_gate.evaluate(m)
    assert v.decision == "block"
    assert any("2 distinct named human approval" in r for r in v.reasons)


# --- Fail-closed edges ----------------------------------------------------

def test_unknown_risk_tier_fails_closed():
    m = copy.deepcopy(GOOD)
    m["change"]["risk_tier"] = "yolo"
    assert release_gate.evaluate(m).decision == "block"


def test_missing_field_fails_closed():
    m = copy.deepcopy(GOOD)
    del m["evidence"]["tests"]
    v = release_gate.evaluate(m)
    assert v.decision == "block"
    assert any("missing required field" in r for r in v.reasons)


def test_low_test_count_blocks():
    m = copy.deepcopy(GOOD)
    m["evidence"]["tests"]["count"] = 3
    v = release_gate.evaluate(m)
    assert v.decision == "block"
    assert any("below the policy minimum" in r for r in v.reasons)


def test_all_reasons_are_reported_not_just_first():
    m = copy.deepcopy(GOOD)
    m["evidence"]["sast"]["result"] = "fail"
    m["evidence"]["sbom"]["present"] = False
    v = release_gate.evaluate(m)
    assert len(v.reasons) >= 2
