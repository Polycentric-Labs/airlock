# Design decisions and honest tradeoffs

Short notes a reviewer can disagree with. Each entry: the call, why, the cost.

**Mock model instead of a real API call.** The controls are the demo; a real
model adds a key, an egress path, and nondeterministic tests while proving
nothing new about the gate. Cost: the model-swap seam (`briefing._compose`)
is asserted by design, not exercised.

**Stdlib only at runtime.** Shortest possible SBOM, nothing to audit, and it
forces the honest realization that most of this pattern is decisions and
bindings, not frameworks. Cost: the local SBOM is minimal; CI regenerates a
fuller one with syft.

**No warn state in the release gate.** Every seasoned reviewer has watched
warnings become wallpaper. Cost: teams must triage blocks quickly or the
gate gets bypassed; the exception path with expiry dates (README, first-10-days)
is the pressure valve.

**Provenance verifier checks binding, not signatures, locally.** Keyless
signing derives identity from the CI OIDC token; pretending to do it locally
would mean a fake key and a misleading claim. Cost: a clean checkout proves
digest bindings only; signature verification is CI-side with
`cosign verify-blob` pinned to the workflow identity.

**Per-release signed records, not a homegrown append-only ledger.** An
"immutable log" you wrote yourself in a day is a liability wearing a
compliment. Durable audit storage is a deployment concern named in
LIMITATIONS.md. Cost: no cross-release tamper evidence inside this repo.

**Injection tripwires kept small and legible.** Five patterns you can read
beat five hundred you cannot, when the honest claim is "tripwire, not
defense." Containment is layered elsewhere (allowlist, path lock, egress,
human tiers). Cost: trivially bypassable by a motivated attacker, which is
stated wherever the tripwires are mentioned.

**Risk tiers keyed to what changed, with the gate itself hardest.** The
quietest way to defeat a control system is to edit the control system.
Cost: friction on legitimate gate improvements; that is the intended price.

**GitHub Actions as the reference CI.** It is where the public repo lives
and where keyless signing is most legible. Cost: an Azure DevOps translation
is described, not shipped.
