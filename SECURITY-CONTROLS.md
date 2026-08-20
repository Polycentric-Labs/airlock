# What the code cannot enforce (and what must be configured so it can)

A YAML file and an exit code do not stop a determined maintainer. This page is
the honest boundary between the DECISION (this repo) and the ENFORCEMENT
(platform configuration). A reviewer should treat every item below as
unchecked until verified in the actual tenant and org settings.

## GitHub repository settings (required for the gate to bind)

- [ ] Branch protection on `main`: require pull requests, require the
      `verify` status check, no force pushes, no deletions.
- [ ] Required status checks include the release gate job for tag builds.
- [ ] `production` environment exists with required reviewers (the human
      approval that the deploy job's `environment: production` line invokes).
- [ ] Tag protection on `v*` so releases cannot be minted by arbitrary pushes.
- [ ] Actions settings: default workflow permissions read-only; fork PRs get
      no secrets and no id-token (this workflow also guards with
      `if: github.event_name == 'push'` on privileged jobs).
- [ ] CODEOWNERS routes changes to `gate/`, `app/policy_gate.py`,
      `app/release_gate.py`, `app/provenance.py`, and
      `.github/workflows/` to security reviewers (the 'high' tier in
      gate/policy.json, made structural).
- [ ] Third-party actions remain pinned to full commit SHAs (they are, today;
      keep them that way and review on bump). The gitleaks binary download in
      `verify` must get a pinned sha256 check at adoption time.

## Azure configuration (required before the deploy job means anything)

- [ ] An Entra app registration with a **federated credential** whose subject
      claims are restricted to THIS repository AND the `production`
      environment (`repo:<org>/<repo>:environment:production`). No client
      secrets created, ever.
- [ ] The service principal's role assignment is scoped to the single
      Function App (deployment permission), not the subscription.
- [ ] The Function App's managed identity (runtime identity, distinct from
      the deploy identity) starts with zero data-plane permissions and gains
      them per data source, explicitly.
- [ ] Outbound network egress for the Function App restricted to the model
      endpoint and approved data sources (VNet integration + NSG or the
      platform's outbound controls). The in-process tool allowlist is a
      seatbelt; the network boundary is the wall.
- [ ] Diagnostic/log retention configured; logs carry the request ids this
      app emits and never raw content (the app already redacts; retention
      and access control are platform-side).

## Identity note for AI agents (production path, not in this demo)

In a production M365/Azure estate, the agent itself gets first-class
identity: Microsoft Entra Agent ID is generally available for exactly this,
so conditional access and lifecycle rules apply to agents like they do to
people. This reference repo runs as a plain workload identity because a
public demo has no tenant; the seam where Agent ID slots in is the Function
App's runtime identity above.

## Change control for this file

Edits to this document and to `gate/policy.json` are 'high' risk tier: two
named approvals, because the quietest way to defeat a gate is to edit the
definition of passing it.
