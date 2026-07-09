"""Gatekeep — prompt firewall / LLM governance proxy.

POST /v1/messages: scan -> decide (block / redact / allow) -> route -> forward.
GET /health. GET /audit: query the decision trail (hashes only, never raw text).
"""

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from . import audit, forwarder
from .config import load_policies
from .detectors import run_all
from .extract import apply_texts, extract_texts
from .policy import decide
from .router import route_model

app = FastAPI(title="Gatekeep")
POLICIES = load_policies("policies.yaml")
audit.init_db()

# Regex safety on enormous inputs: only the first 200k chars of each text are scanned.
SCAN_CAP = 200_000


def _anthropic_error(status: int, message: str) -> JSONResponse:
    """Anthropic error shape so the stock SDK surfaces it as APIStatusError cleanly."""
    return JSONResponse(
        status_code=status,
        content={"type": "error", "error": {"type": "invalid_request_error", "message": message}},
    )


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/audit")
def audit_query(action: Optional[str] = None, since: Optional[str] = None, limit: int = 100) -> list[dict]:
    return audit.query_events(action=action, since=since, limit=limit)


@app.post("/v1/messages")
async def messages(request: Request) -> Response:
    t0 = time.perf_counter()
    raw = await request.body()
    headers = dict(request.headers)

    try:
        body = json.loads(raw)
        if not isinstance(body, dict):
            raise ValueError("body is not a JSON object")
    except (ValueError, json.JSONDecodeError):
        if POLICIES.on_parse_failure == "block":
            return _anthropic_error(400, "Gatekeep: request body could not be parsed for scanning")
        upstream = await forwarder.forward(raw, headers)
        return _relay(upstream)

    # Scan BEFORE the stream check (PLAN.md §5): a secret in a streaming request
    # still blocks with 403 rather than leaking into a plain "no streaming" 400.
    refs = extract_texts(body)
    texts = [r.text for r in refs]
    findings_per_text = [run_all(t[:SCAN_CAP], POLICIES) for t in texts]
    decision = decide(texts, findings_per_text, POLICIES)

    prompt_sha256 = hashlib.sha256("".join(texts).encode()).hexdigest()
    categories = ",".join(sorted({f.category for fs in findings_per_text for f in fs}))
    detector_names = sorted({f.detector for fs in findings_per_text for f in fs})
    if any(len(t) > SCAN_CAP for t in texts):
        detector_names.append("scan_truncated")
    detectors_csv = ",".join(detector_names)
    model_requested = body.get("model")

    def _log(action: str, model_routed: Optional[str] = None, status_upstream: Optional[int] = None) -> None:
        audit.log_event(audit.AuditEvent(
            ts_utc=_now_utc(),
            action=action,
            categories=categories,
            detectors=detectors_csv,
            prompt_sha256=prompt_sha256,
            model_requested=model_requested,
            model_routed=model_routed,
            status_upstream=status_upstream,
            latency_ms=(time.perf_counter() - t0) * 1000,
        ))

    if decision.action == "block":
        _log("block")
        cats = categories.replace(",", ", ")
        return _anthropic_error(403, f"Gatekeep policy violation: {cats}")

    if body.get("stream"):
        _log("reject_stream")
        return _anthropic_error(400, "Gatekeep: streaming inspection not supported in v1")

    if decision.action == "redact":
        body = apply_texts(body, refs, decision.redacted_texts)

    routed = route_model(body.get("model", ""), decision, POLICIES)
    body["model"] = routed

    upstream = await forwarder.forward(json.dumps(body).encode(), headers)
    _log(decision.action, model_routed=routed, status_upstream=upstream.status_code)
    return _relay(upstream)


def _relay(upstream) -> Response:
    """Return upstream status + body verbatim. content-encoding/length are dropped:
    httpx already decompressed the body, so those headers would be stale."""
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type"),
    )
