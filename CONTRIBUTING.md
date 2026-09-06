# Contributing to Airlock

Airlock is a reference implementation, Apache-2.0 licensed, and deliberately
small so every control stays legible. Keep contributions in that spirit:
prefer removing a control's ambiguity over adding scope.

## Setup

```bash
git clone https://github.com/Polycentric-Labs/airlock.git && cd airlock
pip install -r requirements-dev.txt
```

## Running the checks

```bash
python -m pytest -q
python scripts/build_release.py --commit $(git rev-parse HEAD)
```

The second command reproduces the whole promotion path locally: tests, the
built artifact, its SBOM, and the release gate's verdict.

## AI-assisted contributions

You may use AI tools while contributing. Two rules apply, and they mirror the
project's own disclosure in [`docs/ai-assistance.md`](docs/ai-assistance.md):

- **You are the author.** Understand the change and be able to explain it in
  your own words; review questions are answered by you, not by a tool. Pull
  requests opened by autonomous agents are closed.
- **Disclose significant assistance.** Say so in the pull request description,
  or add an `Assisted-by: <tool>` trailer to the commit message. Do not add
  `Co-authored-by` trailers naming AI tools: they create a contributor identity
  in the repository record, and only people are contributors here.
