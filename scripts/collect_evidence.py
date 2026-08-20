"""Run the scanners and record their MEASURED results as release evidence.

This exists so the manifest's evidence section is generated, never asserted:
each tool actually runs here, its exit code decides pass/fail, and its version
is captured. A pipeline that hardcodes {"result": "pass"} has a policy gate in
name only; this script is the difference.

    python scripts/collect_evidence.py --out dist/evidence.json
    (add --skip-secret-scan where the scanner binary is managed by the caller,
     e.g. the CI step that downloads a checksum-pinned gitleaks)

Exit code is nonzero if any executed scanner failed, so the calling step
fails closed even before the gate reads the evidence file.
"""

from __future__ import annotations

import argparse
import json
# subprocess is used only with fixed argument lists of pinned dev tools, no shell.
import subprocess  # nosec B404
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(cmd: list[str]) -> tuple[int, str]:
    # Fixed argument lists, shell disabled.
    proc = subprocess.run(  # nosec B603
        cmd, cwd=ROOT, capture_output=True, text=True
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out.strip()


def tool_version(module: str) -> str:
    code, out = run([sys.executable, "-m", module, "--version"])
    return out.splitlines()[0] if code == 0 and out else "unknown"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--gitleaks-result",
        choices=["pass", "fail"],
        default=None,
        help="measured result from a caller-managed gitleaks run (CI downloads "
        "the checksum-pinned binary itself; pass its outcome through here)",
    )
    parser.add_argument("--gitleaks-version", default=None)
    args = parser.parse_args()

    failures: list[str] = []

    sast_code, _ = run([sys.executable, "-m", "bandit", "-r", "app", "scripts", "-q"])
    sast = {"result": "pass" if sast_code == 0 else "fail", "tool": tool_version("bandit")}
    if sast_code != 0:
        failures.append("bandit")

    dep_code, _ = run([sys.executable, "-m", "pip_audit", "-r", "requirements-dev.txt"])
    dep = {"result": "pass" if dep_code == 0 else "fail", "tool": tool_version("pip_audit")}
    if dep_code != 0:
        failures.append("pip-audit")

    evidence: dict = {"sast": sast, "dependency_audit": dep}
    if args.gitleaks_result:
        evidence["secret_scan"] = {
            "result": args.gitleaks_result,
            "tool": args.gitleaks_version or "gitleaks (caller-managed, checksum-pinned)",
        }
        if args.gitleaks_result != "pass":
            failures.append("gitleaks")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))

    if failures:
        print(f"MEASURED FAILURES: {', '.join(failures)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
