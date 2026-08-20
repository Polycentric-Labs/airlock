"""Azure Functions (v2 programming model) adapter for the Airlock service.

Thin by design: HTTP in, policy-gated draft out. All decisions live in
app/policy_gate.py and all drafting in app/briefing.py, so the core is fully
testable without Azure and this file stays boring.

Requires the `azure-functions` package at deploy time (requirements-azure.txt).
The core app never imports Azure anything.
"""

from __future__ import annotations

import json
import logging
import uuid

try:
    import azure.functions as func
except ImportError:  # pragma: no cover - local dev without the Azure SDK
    func = None

from app import briefing, policy_gate, redaction

if func is not None:  # pragma: no cover - exercised only inside Azure Functions
    app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

    @app.route(route="brief", methods=["POST"])
    def brief(req: func.HttpRequest) -> func.HttpResponse:
        request_id = str(uuid.uuid4())
        try:
            payload = req.get_json()
        except ValueError:
            return func.HttpResponse(
                json.dumps({"error": "invalid JSON", "request_id": request_id}),
                status_code=400,
                mimetype="application/json",
            )

        topic = str(payload.get("topic", ""))[:500]
        audience = str(payload.get("audience", "internal staff"))[:100]
        declared_class = str(payload.get("data_class", "internal"))

        # Stage 1: gate EVERY caller-controlled field before the model runs.
        # A blocked request never reaches the drafter: no tokens, no side
        # effects, and no smuggling via secondary fields like 'audience'.
        result = policy_gate.evaluate_input(topic, audience, declared_class=declared_class)
        if result.decision is not policy_gate.Decision.BLOCK:
            draft = briefing.draft_briefing(topic, audience)
            retrieved = [briefing.corpus_read(briefing.CORPUS_DIR / c) for c in draft.citations]
            # Stage 2: gate what actually happened - retrieved content and
            # the tools the drafter invoked. Worst decision wins.
            post = policy_gate.evaluate_output(retrieved, draft.tool_calls)
            worst = max(result.decision, post.decision)
            result = policy_gate.GateResult(worst, result.reasons + post.reasons)

        # Telemetry: request id + content hashes + decision. Never content.
        logging.info(
            "airlock request=%s topic_ref=%s decision=%s reasons=%d",
            request_id,
            redaction.content_ref(topic),
            result.label,
            len(result.reasons),
        )

        body: dict = {"request_id": request_id, "decision": result.label, "reasons": result.reasons}
        if result.decision is policy_gate.Decision.PROCEED:
            body["draft"] = redaction.scrub(draft.body)
            body["citations"] = draft.citations
        elif result.decision is policy_gate.Decision.HUMAN_REVIEW:
            body["status"] = "quarantined for human review; draft not returned inline"
        status = 200 if result.decision is not policy_gate.Decision.BLOCK else 403
        return func.HttpResponse(json.dumps(body), status_code=status, mimetype="application/json")
