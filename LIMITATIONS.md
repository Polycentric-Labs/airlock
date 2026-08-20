# Limitations (read this before believing the README)

This is a reference implementation built to demonstrate judgment, not a
production security platform. Known boundaries, stated plainly:

1. **The mock model is a stand-in.** `app/briefing.py` composes drafts
   deterministically from the corpus so the whole path runs keyless. The
   controls around it (gate, allowlist, redaction, citations) are the point;
   swapping in a real model via Azure OpenAI or Foundry changes `_compose`
   and adds an egress rule, nothing else by design, but that swap has NOT
   been exercised here.
2. **Enforcement is configuration.** Every control in this repo is advisory
   until the platform settings in SECURITY-CONTROLS.md exist. The repo ships
   the decision logic and the checklist, not the enforcement.
3. **The deploy job is a template.** It has never deployed anywhere: no
   Azure tenant is attached to a public demo. The OIDC federation pattern is
   standard and documented, but "documented" is not "verified in your
   tenant."
4. **Injection heuristics are tripwires.** They catch crude, known patterns
   and refuse credential-shaped input. A motivated prompt injector will get
   past regexes; containment relies on the tool allowlist, the corpus path
   lock, egress control (platform-side), and human review tiers.
5. **The provenance verifier checks binding, not signatures.** Cryptographic
   signature creation and verification happen in CI with sigstore/cosign
   keyless signing, where the OIDC identity exists. Locally you verify that
   digests bind artifact to commit to verdict; you do not verify who signed.
6. **Signed does not mean safe.** A valid signature proves which workflow
   built the artifact. It says nothing about whether the code is good. That
   is what the evidence set and the human tiers are for.
7. **The evidence trail is per-run files, not a ledger.** Verdicts and
   statements are written and signed per release. Durable append-only
   storage, retention, and tamper-evident history are deployment concerns,
   deliberately not imitated here with a homegrown "immutable" log.
8. **Scanners are representative, not exhaustive.** One SAST tool, one
   secret scanner, one dependency auditor, chosen for legibility. A real
   estate adds SCA depth, IaC scanning, and runtime posture in Defender for
   Cloud or equivalent.

## What I would verify before production

Tenant OIDC claims and role scopes; egress rules against a real model
endpoint; DLP and sensitivity-label behavior on the data sources the agent
grounds in (Purview DSPM for AI and DLP for Copilot on the M365 side);
load-time and failure-mode behavior of the gate under real traffic; an
incident drill: rotate the federation, revoke a signature identity, and
re-key the corpus trust in under an hour.
