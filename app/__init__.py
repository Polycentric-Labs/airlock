"""Airlock: a fail-closed promotion path for AI services.

Runtime path:   briefing (mock-LLM drafter) -> policy_gate -> redaction
Promotion path: build_release -> provenance -> release_gate

No third-party runtime dependencies by design: every module in this package
is Python stdlib only. (The Azure Functions host SDK used by the adapter in
function_app.py is the deploy-time exception, listed in requirements-azure.txt.)
"""

__version__ = "0.1.0"
