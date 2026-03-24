from pydantic import BaseModel
from typing import Any


class RequestInspection(BaseModel):
    method: str
    path: str
    query_params: dict[str, str]
    has_auth_header: bool
    content_type: str | None
    body_size: int
    parsed_json: Any
    is_sensitive_endpoint: bool
    client_host: str | None


class RuleMatch(BaseModel):
    rule: str
    reason: str
    score: int


class RequestSummary(BaseModel):
    method: str
    path: str
    client_host: str | None
    content_type: str | None
    body_size: int
    has_auth_header: bool
    is_sensitive_endpoint: bool


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: str
    request_summary: RequestSummary
    query_params: dict[str, str]
    parsed_json: Any
    rule_matches: list[RuleMatch]
    risk_score: int
    decision: str