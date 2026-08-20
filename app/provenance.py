"""SLSA-inspired provenance statement: build one, verify one.

What this IS: an in-toto-style statement that binds, by sha256,
  artifact digest <-> source commit <-> builder <-> policy verdict
and a verifier that recomputes and checks those bindings from disk.

What this is NOT: a claim of any audited SLSA level, and the local verifier
checks BINDING, not signatures. The cryptographic signature over the
statement (and the artifact) is applied in CI with sigstore/cosign keyless
signing, and verified there with `cosign verify-blob`; see the workflow.
Precision about that line is the point of the exercise.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

PREDICATE_TYPE = "https://polycentriclabs.com/airlock/provenance/v0.1"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_statement(
    artifact: Path,
    source_commit: str,
    builder: str,
    policy_verdict_json: str,
    sbom_sha256: str | None = None,
) -> dict:
    subject_digest = sha256_file(artifact)
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": artifact.name, "digest": {"sha256": subject_digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "sourceCommit": source_commit,
            "builder": builder,
            "policyVerdictSha256": sha256_text(policy_verdict_json),
            "materials": ({"sbomSha256": sbom_sha256} if sbom_sha256 else {}),
        },
    }


def verify_statement(
    statement: dict,
    artifact: Path,
    expected_commit: str | None = None,
    policy_verdict_json: str | None = None,
) -> tuple[bool, list[str]]:
    """Recompute every binding the statement asserts. Any mismatch fails."""
    problems: list[str] = []

    subjects = statement.get("subject", [])
    if len(subjects) != 1:
        problems.append(f"expected exactly 1 subject, found {len(subjects)}")
    else:
        claimed = subjects[0].get("digest", {}).get("sha256")
        actual = sha256_file(artifact)
        if claimed != actual:
            problems.append(
                "artifact digest mismatch: statement says "
                f"{claimed[:12]}..., disk says {actual[:12]}..."
            )
        if subjects[0].get("name") != artifact.name:
            problems.append("subject name does not match the artifact filename")

    if statement.get("predicateType") != PREDICATE_TYPE:
        problems.append("unexpected predicateType")

    predicate = statement.get("predicate", {})
    if expected_commit is not None and predicate.get("sourceCommit") != expected_commit:
        problems.append("sourceCommit does not match the expected commit")
    if policy_verdict_json is not None:
        if predicate.get("policyVerdictSha256") != sha256_text(policy_verdict_json):
            problems.append("policy verdict digest does not match the recorded verdict")

    return (not problems), problems


def write_statement(statement: dict, out: Path) -> None:
    out.write_text(json.dumps(statement, indent=2, sort_keys=True), encoding="utf-8")


def read_statement(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
