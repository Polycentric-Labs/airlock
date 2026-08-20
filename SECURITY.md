# Security Policy

## Reporting a vulnerability

Preferred: GitHub **private vulnerability reporting** on this repository
(Security tab, "Report a vulnerability"). Alternative: email
`allen@allenfbyrd.com` with "airlock security" in the subject.

You can expect an acknowledgement within **7 days** and a coordinated fix or
a documented decision within **90 days**. Please include a reproduction; this
repo is small enough that a failing test is the perfect report.

## Scope and supported versions

Airlock is a reference implementation, versioned from `main`. Only the
latest `main` (and the latest tagged release, if any) is supported. There
are no maintained release branches, and that is stated rather than implied.

## Honest posture notes

- This is currently a **single-maintainer** repository. The two-person
  approval tier that gate/policy.json defines is therefore aspirational
  here and real only in a team estate; THREAT-MODEL.md lists this as a
  residual risk instead of pretending otherwise.
- Secret scanning runs three ways: GitHub push protection (platform),
  gitleaks in CI (checksum-pinned binary), and the app's own redaction
  shapes at runtime. Defense in depth, not a novelty claim.
