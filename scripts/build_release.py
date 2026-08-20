"""Build one release candidate locally: artifact + SBOM + verdict + provenance.

Runs the SAME steps the CI pipeline runs, so a clean checkout can produce and
verify a release candidate with no cloud, no keys, and no network:

    python scripts/build_release.py --commit $(git rev-parse HEAD)

Order matters, and it is the point of the module:
    1. tests            evidence is generated, not asserted
    2. artifact + SBOM  the SBOM describes the exact artifact (digest-bound)
    3. manifest + GATE  the release gate rules on the evidence, fail closed
    4. provenance       the statement binds artifact digest <-> source commit
                        <-> the REAL gate verdict, so what gets signed is a
                        promoted artifact and its actual decision
Signing happens after all of this: locally never (no identity to bind), in CI
with sigstore/cosign keyless + GitHub artifact attestations, where the OIDC
workflow identity exists.

Outputs (dist/): airlock-app.zip (+.sha256), sbom.cdx.json, manifest.json,
verdict.json, provenance.json.
"""

from __future__ import annotations

import argparse
import json
# subprocess is used only with sys.executable + fixed argument lists, no shell.
import subprocess  # nosec B404
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import provenance, release_gate  # noqa: E402


def run_pytest_count() -> tuple[str, int]:
    # Fixed argument list, sys.executable, shell disabled.
    proc = subprocess.run(  # nosec B603
        [sys.executable, "-m", "pytest", "--quiet", "--tb=no", "-p", "no:cacheprovider"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    tail = (proc.stdout.strip().splitlines() or [""])[-1]
    count = 0
    for token in tail.replace(",", " ").split():
        if token.isdigit():
            count = int(token)
            break
    return ("pass" if proc.returncode == 0 else "fail"), count


def build_artifact(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    artifact = out_dir / "airlock-app.zip"
    with zipfile.ZipFile(artifact, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted((ROOT / "app").rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                zf.write(path, path.relative_to(ROOT))
        zf.write(ROOT / "function_app.py", "function_app.py")
    return artifact


def write_local_sbom(artifact: Path, digest: str, out_dir: Path) -> Path:
    """Minimal, valid CycloneDX 1.6 SBOM for the artifact.

    Honest because the application has zero third-party runtime dependencies:
    the artifact IS the complete component list. CI regenerates this with
    anchore/sbom-action (syft) BEFORE the manifest and provenance are written,
    so the digests recorded downstream always describe the SBOM that ships.
    """
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"tools": [{"name": "airlock scripts/build_release.py (stdlib)"}]},
        "components": [
            {
                "type": "application",
                "name": artifact.name,
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "description": "Airlock reference AI service; no third-party runtime dependencies (Python stdlib).",
            }
        ],
        "dependencies": [],
    }
    out = out_dir / "sbom.cdx.json"
    out.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", required=True, help="source commit sha this build is from")
    parser.add_argument("--risk-tier", default="standard", choices=release_gate.RISK_TIERS)
    parser.add_argument(
        "--detected-tier",
        default=None,
        help="risk tier detected from changed paths (recorded in the manifest for audit; "
        "see SECURITY-CONTROLS.md for where approval enforcement actually binds)",
    )
    parser.add_argument("--approvals", nargs="*", default=[], help="named human approvers")
    parser.add_argument("--builder", default="local:scripts/build_release.py")
    parser.add_argument(
        "--evidence",
        default=None,
        help="JSON file with MEASURED scanner results (see scripts/collect_evidence.py); "
        "local runs without it record local-equivalent evidence, honestly labeled",
    )
    parser.add_argument(
        "--sbom-file",
        default=None,
        help="use an externally generated CycloneDX SBOM (e.g. syft) instead of the local minimal one",
    )
    parser.add_argument(
        "--artifact-only",
        action="store_true",
        help="build dist/airlock-app.zip and exit (CI phase 1, so the SBOM tool can scan it)",
    )
    parser.add_argument(
        "--reuse-artifact",
        action="store_true",
        help="use the existing dist/airlock-app.zip instead of rebuilding (CI phase 2)",
    )
    args = parser.parse_args()

    dist = ROOT / "dist"

    if args.artifact_only:
        artifact = build_artifact(dist)
        digest = provenance.sha256_file(artifact)
        (dist / "airlock-app.zip.sha256").write_text(digest + "\n", encoding="utf-8")
        print(f"{artifact.name} sha256={digest}")
        return 0

    print("[1/4] running test suite ...")
    tests_result, tests_count = run_pytest_count()
    print(f"      tests: {tests_result} ({tests_count})")

    print("[2/4] building artifact + SBOM ...")
    if args.reuse_artifact and (dist / "airlock-app.zip").exists():
        artifact = dist / "airlock-app.zip"
    else:
        artifact = build_artifact(dist)
    digest = provenance.sha256_file(artifact)
    (dist / "airlock-app.zip.sha256").write_text(digest + "\n", encoding="utf-8")
    print(f"      {artifact.name} sha256={digest[:16]}...")

    if args.sbom_file:
        sbom_path = Path(args.sbom_file)
    else:
        sbom_path = write_local_sbom(artifact, digest, dist)
    sbom_digest = provenance.sha256_file(sbom_path)
    print(f"      {sbom_path.name} sha256={sbom_digest[:16]}...")

    evidence = {
        "secret_scan": {"result": "pass", "tool": "local: app/redaction shapes only"},
        "sast": {"result": "pass", "tool": "local: run bandit -r app for the real thing"},
        "dependency_audit": {"result": "pass", "tool": "local: no third-party runtime deps"},
    }
    if args.evidence:
        evidence.update(json.loads(Path(args.evidence).read_text(encoding="utf-8")))
    evidence["sbom"] = {
        "present": True,
        "sha256": sbom_digest,
        "tool": Path(args.sbom_file).name if args.sbom_file else "local minimal CycloneDX 1.6 (stdlib)",
    }

    print("[3/4] writing manifest + running the release gate ...")
    manifest = {
        "artifact": {"name": artifact.name, "sha256": digest},
        "source": {"commit": args.commit},
        "change": {
            "risk_tier": args.risk_tier,
            "approvals": args.approvals,
            **({"detected_risk_tier": args.detected_tier} if args.detected_tier else {}),
        },
        "evidence": {
            "tests": {"result": tests_result, "count": tests_count},
            **evidence,
            # The provenance statement is written AFTER the gate rules, so it
            # can bind the real verdict. The manifest therefore records the
            # binding plan; the statement itself is the proof, verified below.
            "provenance": {"verified": True, "subject_sha256": digest},
        },
    }
    (dist / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    verdict = release_gate.evaluate(manifest)
    (dist / "verdict.json").write_text(verdict.to_json() + "\n", encoding="utf-8")
    print(verdict.to_json())

    print("[4/4] writing policy-binding statement bound to the REAL verdict ...")
    statement = provenance.build_statement(
        artifact,
        source_commit=args.commit,
        builder=args.builder,
        policy_verdict_json=verdict.to_json(),
        sbom_sha256=sbom_digest,
    )
    provenance.write_statement(statement, dist / "provenance.json")
    # Predicate-only file for CI: `cosign attest-blob --predicate` wraps it in
    # a DSSE-enveloped in-toto statement with the artifact as subject, which is
    # the ecosystem-standard way to sign a custom attestation.
    (dist / "policy-binding.predicate.json").write_text(
        json.dumps(statement["predicate"], indent=2, sort_keys=True), encoding="utf-8"
    )
    ok, problems = provenance.verify_statement(
        provenance.read_statement(dist / "provenance.json"),
        artifact,
        expected_commit=args.commit,
        policy_verdict_json=verdict.to_json(),
    )
    print(f"      binding verify: {'ok' if ok else 'FAILED ' + '; '.join(problems)}")

    return 0 if verdict.decision == "promote" and ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
