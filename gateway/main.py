from pathlib import Path
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from fastapi import FastAPI, Request, Response, Query
import os
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
from gateway.database.db import (
    init_db,
    save_security_event,
    get_all_events,
    get_event_summary,
    delete_events_by_client,  # assuming you already added this
)

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="GateShield Gateway")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

PROTECTED_API_BASE = os.getenv(
    "PROTECTED_API_BASE",
    "http://127.0.0.1:8001"  # fallback for local dev
)

init_db()


async def inspect_request(request: Request, path: str, body: bytes) -> RequestInspection:
    headers = {k.lower(): v for k, v in request.headers.items()}
    parsed_json = try_parse_json(body)

    return RequestInspection(
        method=request.method,
        path=f"/{path}",
        query_params=dict(request.query_params),
        headers=headers,
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
    save_security_event(event)

    print("\n=== GateShield Security Event ===")
    print(event.model_dump_json(indent=2))


def get_recent_history_for_client(
    client_host: str | None,
    limit: int = 100,
) -> list[dict]:
    if not client_host:
        return []

    recent_events = get_all_events(limit=limit)
    return [event for event in recent_events if event.get("client_host") == client_host]


def compute_live_client_risk(history: list[dict]) -> dict:
    """
    Computes a live risk score from recent client history.
    This is intentionally separate from per-request scoring.
    """
    flagged_count = sum(1 for event in history if event.get("decision") == "flag")
    blocked_count = sum(1 for event in history if event.get("decision") == "block")
    sensitive_count = sum(
        1 for event in history if event.get("is_sensitive_endpoint") is True
    )

    # Risk model for demo purposes
    risk_score = (
        flagged_count * 15
        + blocked_count * 30
        + min(sensitive_count * 5, 20)
    )

    if risk_score >= 90:
        risk_level = "critical"
    elif risk_score >= 60:
        risk_level = "high"
    elif risk_score >= 30:
        risk_level = "elevated"
    else:
        risk_level = "low"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "recent_event_count": len(history),
        "flagged_count": flagged_count,
        "blocked_count": blocked_count,
        "sensitive_count": sensitive_count,
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "gateway"}


@app.get("/events/summary")
def events_summary(
    decision: str | None = Query(default=None),
    path: str | None = Query(default=None),
):
    return get_event_summary(decision=decision, path=path)


@app.get("/events")
def list_events(
    decision: str | None = Query(default=None),
    path: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
):
    return {
        "summary": get_event_summary(decision=decision, path=path),
        "events": get_all_events(decision=decision, path=path, limit=limit),
    }


@app.get("/risk/me")
def get_my_risk(request: Request):
    client_host = request.client.host if request.client else None
    history = get_recent_history_for_client(client_host=client_host, limit=100)
    risk = compute_live_client_risk(history)

    return {
        "client_host": client_host,
        **risk,
    }


@app.delete("/events/reset/me")
def reset_my_events(request: Request):
    client_host = request.client.host if request.client else None
    deleted_count = delete_events_by_client(client_host) if client_host else 0

    return {
        "message": f"Cleared events for {client_host}",
        "deleted_count": deleted_count,
    }


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(path: str, request: Request):
    target_url = f"{PROTECTED_API_BASE}/{path}"
    print("Forwarding to:", target_url)
    body = await request.body()

    inspection = await inspect_request(request, path, body)

    recent_history = get_recent_history_for_client(
        client_host=inspection.client_host,
        limit=100,
    )

    rule_matches = evaluate_rules(inspection, history=recent_history)
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