"""Derive the risk tier of a change from the paths it touched.

The tier definitions live in gate/policy.json (risk_tier_guidance); this
module makes them computable so CI can RECORD the detected tier in the
release manifest instead of hardcoding 'standard'. Detection is recorded for
audit; approval ENFORCEMENT binds in the pull-request lane (CODEOWNERS +
branch protection), as SECURITY-CONTROLS.md spells out. Printing 'high' here
does not conjure two approvers into a manifest; it makes the mismatch visible.

    python scripts/derive_tier.py path1 path2 ...
    git diff --name-only HEAD^ HEAD | python scripts/derive_tier.py -
"""

from __future__ import annotations

import sys

HIGH_PREFIXES = (
    ".github/workflows/",
    "gate/",
    "app/policy_gate.py",
    "app/release_gate.py",
    "app/provenance.py",
    "scripts/build_release.py",
    "scripts/collect_evidence.py",
    "scripts/derive_tier.py",
    "SECURITY-CONTROLS.md",
)
ELEVATED_PREFIXES = ("app/", "scripts/", "function_app.py", "requirements")


def tier_for(paths: list[str]) -> str:
    normalized = [p.strip().replace("\\", "/") for p in paths if p.strip()]
    if any(p.startswith(HIGH_PREFIXES) for p in normalized):
        return "high"
    if any(p.startswith(ELEVATED_PREFIXES) for p in normalized):
        return "elevated"
    return "standard"


def main(argv: list[str]) -> int:
    paths = sys.stdin.read().splitlines() if argv == ["-"] else argv
    print(tier_for(list(paths)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
