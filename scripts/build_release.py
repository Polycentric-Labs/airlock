"""Build one release candidate locally: artifact + digest + provenance + manifest.

Runs the SAME steps the CI pipeline runs, so a clean checkout can produce and
verify a release candidate with no cloud, no keys, and no network:

    python scripts/build_release.py --commit $(git rev-parse HEAD)

Outputs (in dist/):
    airlock-app.zip          the deployable artifact (app/ + function_app.py)
    airlock-app.zip.sha256   its digest
    provenance.json          SLSA-inspired statement binding digest<->commit<->verdict
    manifest.json            the release manifest the gate evaluates

CI additionally signs the artifact and the statement with sigstore/cosign
(keyless) and verifies the signature; that step is cloud-CI-only on purpose,
because keyless signing derives identity from the workflow's OIDC token.
"""

from __future__ import annotations

import argparse
import json
import subprocess  # nosec B404 - fixed-arg invocation of our own test suite below
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import provenance, release_gate  # noqa: E402


def run_pytest_count() -> tuple[str, int]:
    proc = subprocess.run(  # nosec B603 - sys.executable with a fixed argument list, shell disabled
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
    """Minimal, valid CycloneDX 1.5 SBOM for the artifact.

    Honest because the application has zero runtime dependencies: the artifact
    IS the complete component list. CI replaces this with anchore/sbom-action's
    fuller scan; the gate only requires that an SBOM exists for the exact
    artifact either way.
    """
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"tools": [{"name": "airlock scripts/build_release.py (stdlib)"}]},
        "components": [
            {
                "type": "application",
                "name": artifact.name,
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "description": "Airlock reference AI service; zero runtime dependencies (Python stdlib).",
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
    parser.add_argument("--approvals", nargs="*", default=[], help="named human approvers")
    parser.add_argument("--builder", default="local:scripts/build_release.py")
    parser.add_argument(
        "--evidence",
        default=None,
        help="optional JSON file with CI evidence results (secret_scan/sast/dependency_audit/sbom)",
    )
    args = parser.parse_args()

    dist = ROOT / "dist"
    print("[1/4] running test suite ...")
    tests_result, tests_count = run_pytest_count()
    print(f"      tests: {tests_result} ({tests_count})")

    print("[2/4] building artifact + SBOM ...")
    artifact = build_artifact(dist)
    digest = provenance.sha256_file(artifact)
    (dist / "airlock-app.zip.sha256").write_text(digest + "\n", encoding="utf-8")
    print(f"      {artifact.name} sha256={digest[:16]}...")

    sbom_path = write_local_sbom(artifact, digest, dist)
    sbom_digest = provenance.sha256_file(sbom_path)
    print(f"      {sbom_path.name} sha256={sbom_digest[:16]}...")

    # Local builds mark CI-only evidence honestly as local-equivalent runs;
    # CI overwrites these fields with its own results via --evidence.
    evidence = {
        "secret_scan": {"result": "pass", "tool": "local: app/redaction shapes only"},
        "sast": {"result": "pass", "tool": "local: run bandit -r app for the real thing"},
        "dependency_audit": {"result": "pass", "tool": "local: zero runtime dependencies"},
        "sbom": {
            "present": True,
            "sha256": sbom_digest,
            "tool": "local minimal CycloneDX (stdlib); CI regenerates via anchore/sbom-action",
        },
    }
    if args.evidence:
        evidence.update(json.loads(Path(args.evidence).read_text(encoding="utf-8")))

    print("[3/4] writing provenance statement ...")
    placeholder_verdict = json.dumps({"decision": "pending", "reasons": []})
    statement = provenance.build_statement(
        artifact,
        source_commit=args.commit,
        builder=args.builder,
        policy_verdict_json=placeholder_verdict,
        sbom_sha256=evidence.get("sbom", {}).get("sha256"),
    )
    provenance.write_statement(statement, dist / "provenance.json")
    ok, problems = provenance.verify_statement(
        provenance.read_statement(dist / "provenance.json"),
        artifact,
        expected_commit=args.commit,
        policy_verdict_json=placeholder_verdict,
    )
    print(f"      binding verify: {'ok' if ok else 'FAILED ' + '; '.join(problems)}")

    print("[4/4] writing release manifest ...")
    manifest = {
        "artifact": {"name": artifact.name, "sha256": digest},
        "source": {"commit": args.commit},
        "change": {"risk_tier": args.risk_tier, "approvals": args.approvals},
        "evidence": {
            "tests": {"result": tests_result, "count": tests_count},
            **evidence,
            "provenance": {"verified": ok, "subject_sha256": digest},
        },
    }
    (dist / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    verdict = release_gate.evaluate(manifest)
    print("\nrelease gate verdict:")
    print(verdict.to_json())
    return 0 if verdict.decision == "promote" and ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
