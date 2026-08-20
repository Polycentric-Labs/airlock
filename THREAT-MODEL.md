# Threat Model: the experimentation-to-production jump

Scope: one AI service, one release path, from a developer's working tree to a
running cloud function. Assumed adversary: patient, well-resourced, and happy
to enter through the delivery pipeline rather than the front door. That
assumption is the design constraint, not a marketing line: the pipeline is
treated as an attack surface equal to the application.

Out of scope here, addressed in LIMITATIONS.md: platform-level enforcement
(branch protection, environment approvals, federated-credential conditions),
runtime network egress control, and everything a real tenant review would add.

## Assets

| Asset | Why an adversary wants it |
|---|---|
| The deployable artifact | Ship their code with your identity |
| The deploy identity (OIDC federation) | Deploy anything, anytime |
| The corpus / grounding data | Poison what the assistant tells staff |
| Member-confidential content in requests | Exfiltration, extortion, targeting |
| The policy and release gates themselves | Turn the controls off quietly |

## Threats and controls

Each control names what it does and, just as important, what it does NOT do.

| # | Threat | Control in this repo | What the control does NOT do |
|---|---|---|---|
| T1 | Dependency tampering / malicious package | Zero runtime dependencies; CycloneDX SBOM per artifact; pip-audit on dev tooling | Does not protect the CI runners' own toolchain; does not vet the pinned actions' transitive code |
| T2 | Artifact swapped after checks pass | Provenance statement binds artifact sha256 to source commit and policy verdict; verifier recomputes from disk; cosign keyless signature in CI | Local verifier checks binding, not signatures; signature proves workflow identity, not code safety |
| T3 | Workflow or gate quietly modified | Gate/policy/workflow changes are 'high' risk tier requiring 2 named approvals; actions pinned to commit SHAs; workflow permissions default contents:read | Exit codes alone cannot stop a maintainer; binding needs branch protection + required checks (SECURITY-CONTROLS.md) |
| T4 | Stolen cloud credential deploys directly | No stored cloud secrets anywhere; deploy uses GitHub OIDC federated to Azure, restricted by repo + environment claims | The federation conditions live in Azure config, not in this repo; template until configured |
| T5 | Prompt injection via user input | Injection tripwires block crude patterns; refusal on credential/PII-shaped input | Heuristics are a tripwire, not a defense; novel injections will pass them |
| T6 | Indirect injection via poisoned corpus | Retrieved content runs through the same tripwires; corpus reads are path-locked to the corpus directory | Cannot detect semantic poisoning that avoids the patterns; corpus provenance is a process control |
| T7 | Tool abuse / agent calls something it shouldn't | Explicit tool allowlist; any non-allowlisted call is a BLOCK with the tool named in the reasons | Allowlist is enforced in-process; a compromised process bypasses it (that is what T2/T3/T4 layers are for) |
| T8 | Sensitive data exfiltrated via logs | Telemetry carries request ids and content hashes, never content; secret-shape and PII redaction on anything that leaves | Redaction shapes are finite; new secret formats need new patterns |
| T9 | Member-confidential data released without review | Data-class gate: member-confidential quarantines for a human, restricted-pii refuses outright, unknown classes fail closed | Declared class can be wrong; classification-at-source and DLP are the platform layer |
| T10 | Untested / unreviewed change promoted | Release gate requires passing tests above a count floor, scans, SBOM, verified provenance; risk-tier scaled human approvals; no warn state | The gate evaluates evidence it is given; falsified evidence upstream defeats it, which is why CI generates the evidence in the same job |

## The four demonstrated rejections

Not hypothetical: each is a test in `tests/` and two are runnable CLI examples.

1. Static analysis fails: BLOCK (`test_rejection_1_failed_sast_blocks`)
2. SBOM missing for the artifact: BLOCK (`test_rejection_2_missing_sbom_blocks`)
3. Artifact digest no longer matches provenance (tamper): BLOCK
   (`test_rejection_3...`, `examples/manifest-block-tampered.json`, and
   `test_tampered_artifact_fails_verification` for the byte-level version)
4. High-tier change without two named humans: BLOCK
   (`test_rejection_4...`, `examples/manifest-block-high-tier.json`)

## What would have to be true for this to fail

Honesty section. The pipeline fails if: the platform controls in
SECURITY-CONTROLS.md are not actually configured (the gate becomes advisory);
a maintainer account with bypass rights is compromised (platform controls
again); the CI runner itself is compromised (evidence generation and signing
share a trust domain); or the policy is edited through the very approval path
it defines and reviewers rubber-stamp it. None of these are solved by more
YAML. They are solved by configuration, key hygiene, and review culture, which
is why they are written down instead of claimed away.
