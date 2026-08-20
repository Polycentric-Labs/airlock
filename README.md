# Airlock

**A fail-closed promotion path for AI services: from experimentation to
production without trusting anyone's good day.**

One claim, end to end: *an AI service cannot be promoted unless its source,
dependencies, policy decision, and deploy identity meet explicit, verifiable
controls, and every failure fails closed.*

Teams building with AI are fast now. Vibe-coded prototypes become real
products in days. The place organizations get hurt is not the prototype; it
is the jump from prototype to production, where a mistake stops being a bug
and starts being an attack surface. Airlock is a deliberately small reference
implementation of that jump for a Python AI service on the Azure Functions
model, built so every control is legible, testable, and honest about its
limits.

## What is actually here

One AI request path, one release path, four demonstrated rejections.

```mermaid
flowchart LR
    subgraph runtime [Runtime path]
        U[Request] --> B[Drafter, corpus-grounded, cited]
        B --> P{Policy gate}
        P -->|proceed| R[Draft + citations]
        P -->|human-review| Q[Quarantine for a person]
        P -->|block| X[Refused, reasons logged]
    end
    subgraph promotion [Promotion path]
        C[Commit] --> V[Tests, SAST, secret scan, dep audit]
        V --> A[Artifact + SBOM]
        A --> PR[Provenance: digest binds commit and verdict]
        PR --> S[Sigstore keyless sign + verify in CI]
        S --> G{Release gate, fail closed}
        G -->|promote| D[Deploy via OIDC, no stored secrets]
        G -->|block| N[Blocked, every reason listed]
    end
```

- **Runtime path** (`app/`): a briefing drafter that only speaks from a local
  corpus with citations, behind a policy gate that classifies data
  (member-confidential quarantines for a human, restricted PII refuses,
  unknown classes fail closed), trips on crude injection patterns in input
  AND retrieved content, enforces a tool allowlist, and never logs content,
  only hashes. The model is a deterministic mock so everything runs keyless;
  swapping in a real model changes one function and none of the controls.
- **Promotion path** (`app/release_gate.py`, `app/provenance.py`,
  `scripts/build_release.py`, `.github/workflows/airlock.yml`): evidence in,
  verdict out. A release manifest must show passing tests above a count
  floor, clean scans, an SBOM for the exact artifact, and a provenance
  statement whose digests bind artifact to commit to policy verdict. Risk
  tiers scale human approval: touching the gate itself takes two named
  people. In CI the artifact and statement are signed with sigstore/cosign
  keyless signing and verified against the workflow's own identity.
- **The docs are half the point**: [THREAT-MODEL.md](THREAT-MODEL.md) maps
  each control to the threat it addresses and states what it does NOT stop.
  [SECURITY-CONTROLS.md](SECURITY-CONTROLS.md) is the honest boundary
  between decision (this repo) and enforcement (branch protection,
  environments, Azure federated-credential claims).
  [LIMITATIONS.md](LIMITATIONS.md) says plainly what is real, what is a
  template, and what only a tenant review can verify.

## Run it (no keys, no cloud, no network needed)

```bash
pip install -r requirements-dev.txt
python -m pytest -q                                    # 31 tests
python scripts/build_release.py --commit $(git rev-parse HEAD)
```

The build runs the suite, produces the artifact, writes a CycloneDX SBOM and
a provenance statement, verifies the bindings from disk, and asks the release
gate for a verdict. Then watch it refuse:

```bash
python -m app.release_gate examples/manifest-block-tampered.json    # digest mismatch
python -m app.release_gate examples/manifest-block-high-tier.json   # missing second approver
```

Both exit nonzero with every reason listed. The tamper case also exists at
the byte level: `tests/test_provenance.py` flips one byte of a signed-over
artifact and shows verification fail.

## Design positions (the part that is actually about security)

1. **Fail closed, no warn state.** Warnings in a promotion path decay into
   wallpaper. Anything missing, malformed, or unknown is a block with a
   reason.
2. **Zero runtime dependencies.** The application is Python stdlib. The SBOM
   is short because the attack surface is short. Dev tooling is separate and
   audited.
3. **Bind, then sign.** Digests bind artifact to commit to policy verdict
   before anything is signed, so a signature covers a specific, reconstructable
   claim. A signature proves workflow identity, never code safety.
4. **Humans scale with risk.** Standard changes flow. Elevated changes take a
   named person. Changes to the gate itself take two, because the quietest
   attack is editing the definition of passing.
5. **The pipeline is an attack surface.** Actions pinned to commit SHAs,
   read-only default token, no privileged jobs on fork PRs, no stored cloud
   secrets anywhere: deploy identity is OIDC federation with claims scoped to
   repo and environment.
6. **Assist, do not replace.** The runtime gate returns plain-English reasons
   and quarantines rather than lecturing; blocked and quarantined requests are
   review input for tuning the rules, with the explicit goal of reducing
   friction for safe requests.

## First 10 business days on a real greenfield AI product

This repo is the shape of the first two weeks, not a finished platform:
map data flows, identities, tools, and deploy paths (days 1 to 3); stand up
the minimum promotion gate on the first service and get one real release
through it (days 3 to 6); threat-model the highest-risk workflow with the
team, not at them (days 6 to 8); wire evidence generation into CI so the gate
stops being advisory (days 8 to 10); leave behind a one-page exception path
with expiry dates, because a gate without a legible exception path gets
bypassed, not respected.

## Portability

The workflow is GitHub Actions because that is where this reference lives;
the pattern (evidence jobs, OIDC deploy identity, environment approvals,
pinned dependencies) maps one-to-one onto Azure DevOps Pipelines with
service connections and environment checks. The gate and provenance modules
are plain Python and do not care who runs them.

## Provenance of this repo, stated plainly

Built AI-assisted in a compressed window, the same acceleration pattern most
AI teams use now, with the controls applied to the acceleration itself: scope
cut deliberately small, every module reviewed, 31 tests written and green,
scanners run locally, limitations documented instead of discovered. The
deeper, slower record of the same discipline is public:
[Evidentia](https://github.com/Polycentric-Labs/evidentia) (open-source GRC
platform: signed evidence, SBOM, Sigstore, 4,900+ tests),
[Voidseal](https://github.com/Polycentric-Labs/voidseal) (fail-closed,
risk-tiered sandboxing for untrusted code and agents), and
[RegRails](https://github.com/Polycentric-Labs/regrails) (policy-as-code
guardrail that decides before a model speaks).

## License

Apache-2.0
