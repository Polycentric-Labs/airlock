"""Airlock: a fail-closed promotion path for AI services.

Runtime path:   briefing (mock-LLM drafter) -> policy_gate -> redaction
Promotion path: build_release -> provenance -> release_gate

Zero runtime dependencies by design: every module here is Python stdlib only.
"""

__version__ = "0.1.0"
