"""The promotion gate: evidence in, verdict out, fail closed.

A release manifest describes one artifact and the evidence gathered for it.
The gate evaluates that manifest against gate/policy.json and returns
PROMOTE or BLOCK with every reason listed. Anything missing, malformed,
unknown, or unverified is a BLOCK. There is no "warn" state on purpose:
warnings in a promotion path decay into wallpaper.

Enforcement honesty (also in SECURITY-CONTROLS.md): this gate is a REFERENCE
implementation. Exit codes cannot stop a determined maintainer; branch
protection, required status checks, environment approvals, and the deploy
identity's federated-credential conditions are what make it binding. This
module is the decision; the platform configuration is the enforcement.

CLI:
    python -m app.release_gate examples/manifest-pass.json
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

POLICY_PATH = Path(__file__).resolve().parent.parent / "gate" / "policy.json"

RISK_TIERS = ("standard", "elevated", "high")


@dataclass
class Verdict:
    decision: str  # "promote" | "block"
    reasons: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps({"decision": self.decision, "reasons": self.reasons}, indent=2)


def load_policy(path: Path = POLICY_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _require(manifest: dict, dotted: str) -> tuple[object | None, str | None]:
    node: object = manifest
    for key in dotted.split("."):
        if not isinstance(node, dict) or key not in node:
            return None, f"manifest missing required field '{dotted}'"
        node = node[key]
    return node, None


def evaluate(manifest: dict, policy: dict | None = None) -> Verdict:
    policy = policy or load_policy()
    reasons: list[str] = []

    tier, err = _require(manifest, "change.risk_tier")
    if err:
        reasons.append(err)
        tier = None
    elif tier not in RISK_TIERS:
        reasons.append(f"unknown risk tier '{tier}': failing closed")
        tier = None

    # Evidence checks required for every tier.
    for dotted, expected, why in (
        ("evidence.tests.result", "pass", "test suite must pass"),
        ("evidence.secret_scan.result", "pass", "secret scan must pass"),
        ("evidence.sast.result", "pass", "static analysis must pass"),
        ("evidence.dependency_audit.result", "pass", "dependency audit must pass"),
    ):
        value, err = _require(manifest, dotted)
        if err:
            reasons.append(err)
        elif value != expected:
            reasons.append(f"{why} (got '{value}')")

    count, err = _require(manifest, "evidence.tests.count")
    if not err and isinstance(count, int) and count < policy["minimum_test_count"]:
        reasons.append(
            f"test count {count} is below the policy minimum {policy['minimum_test_count']}"
        )

    # Artifact integrity: digest present, and SBOM + provenance bound to it.
    digest, err = _require(manifest, "artifact.sha256")
    if err:
        reasons.append(err)
    sbom_present, err = _require(manifest, "evidence.sbom.present")
    if err or sbom_present is not True:
        reasons.append("CycloneDX SBOM must be present for the exact artifact")
    prov_verified, err = _require(manifest, "evidence.provenance.verified")
    if err or prov_verified is not True:
        reasons.append("provenance statement must verify against the artifact digest")
    prov_subject, err = _require(manifest, "evidence.provenance.subject_sha256")
    if not err and digest and prov_subject != digest:
        reasons.append("provenance subject digest does not match the artifact digest")

    # Tier-scaled human approval.
    if tier in ("elevated", "high"):
        approvals, err = _require(manifest, "change.approvals")
        needed = policy["approvals_required"][tier]
        got = len(approvals) if isinstance(approvals, list) else 0
        if err or got < needed:
            reasons.append(
                f"risk tier '{tier}' requires {needed} named human approval(s), found {got}"
            )

    return Verdict("block", reasons) if reasons else Verdict("promote")


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python -m app.release_gate <manifest.json>", file=sys.stderr)
        return 2
    manifest = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    verdict = evaluate(manifest)
    print(verdict.to_json())
    return 0 if verdict.decision == "promote" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
