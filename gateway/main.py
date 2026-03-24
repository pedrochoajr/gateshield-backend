from fastapi import FastAPI, Request, Response
import httpx
import json
import uuid
from datetime import datetime, timezone

from gateway.models import (
    RequestInspection,
    RuleMatch,
    RequestSummary,
    SecurityEvent,
)
from gateway.rules import (
    is_sensitive_path,
    try_parse_json,
    evaluate_rules,
    compute_risk_score,
    decide_action,
)

app = FastAPI(title="GateShield Gateway")

PROTECTED_API_BASE = "http://127.0.0.1:8001"
EVENT_STORE = []


async def inspect_request(request: Request, path: str, body: bytes) -> RequestInspection:
    headers = dict(request.headers)
    parsed_json = try_parse_json(body)

    return RequestInspection(
        method=request.method,
        path=f"/{path}",
        query_params=dict(request.query_params),
        has_auth_header="authorization" in headers,
        content_type=headers.get("content-type"),
        body_size=len(body),
        parsed_json=parsed_json,
        is_sensitive_endpoint=is_sensitive_path(path),
        client_host=request.client.host if request.client else None,
    )


def build_security_event(
    inspection: RequestInspection,
    rule_matches: list[RuleMatch],
    risk_score: int,
    decision: str,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        request_summary=RequestSummary(
            method=inspection.method,
            path=inspection.path,
            client_host=inspection.client_host,
            content_type=inspection.content_type,
            body_size=inspection.body_size,
            has_auth_header=inspection.has_auth_header,
            is_sensitive_endpoint=inspection.is_sensitive_endpoint,
        ),
        query_params=inspection.query_params,
        parsed_json=inspection.parsed_json,
        rule_matches=rule_matches,
        risk_score=risk_score,
        decision=decision,
    )


def log_security_event(event: SecurityEvent) -> None:
    EVENT_STORE.append(event)

    print("\n=== GateShield Security Event ===")
    print(event.model_dump_json(indent=2))


@app.get("/health")
def health():
    return {"status": "ok", "service": "gateway"}


@app.get("/events")
def list_events():
    return {
        "count": len(EVENT_STORE),
        "events": [event.model_dump() for event in EVENT_STORE],
    }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(path: str, request: Request):
    target_url = f"{PROTECTED_API_BASE}/{path}"
    body = await request.body()

    inspection = await inspect_request(request, path, body)
    rule_matches = evaluate_rules(inspection)
    risk_score = compute_risk_score(rule_matches)
    decision = decide_action(risk_score)

    event = build_security_event(
        inspection=inspection,
        rule_matches=rule_matches,
        risk_score=risk_score,
        decision=decision,
    )
    log_security_event(event)

    if decision == "block":
        return Response(
            content=json.dumps({
                "message": "Request blocked by GateShield",
                "event_id": event.event_id,
                "risk_score": risk_score,
                "rule_matches": [match.model_dump() for match in rule_matches],
            }),
            status_code=403,
            media_type="application/json",
        )

    headers = dict(request.headers)
    headers.pop("host", None)

    async with httpx.AsyncClient() as client:
        upstream_response = await client.request(
            method=request.method,
            url=target_url,
            params=request.query_params,
            content=body,
            headers=headers,
        )

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=dict(upstream_response.headers),
        media_type=upstream_response.headers.get("content-type"),
    )