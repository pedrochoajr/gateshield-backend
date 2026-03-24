# rules.py

import json

from gateway.models import RequestInspection, RuleMatch

SENSITIVE_PATHS = {
    "/login",
    "/payments",
    "/account",
    "/admin",
}

MAX_BODY_SIZE = 1024  # bytes


def is_sensitive_path(path: str) -> bool:
    normalized = f"/{path.strip('/')}" if path else "/"
    return normalized in SENSITIVE_PATHS


def try_parse_json(body: bytes):
    if not body:
        return None

    try:
        return json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def contains_suspicious_sql_pattern(value):
    if not isinstance(value, str):
        return False

    lowered = value.lower()

    suspicious_patterns = [
        "' or 1=1",
        '" or 1=1',
        "union select",
        "drop table",
        "select * from",
        "--",
    ]

    return any(pattern in lowered for pattern in suspicious_patterns)


def json_contains_suspicious_pattern(data):
    if isinstance(data, dict):
        return any(json_contains_suspicious_pattern(v) for v in data.values())

    if isinstance(data, list):
        return any(json_contains_suspicious_pattern(item) for item in data)

    return contains_suspicious_sql_pattern(data)


def evaluate_rules(inspection: RequestInspection) -> list[RuleMatch]:
    matches = []

    if inspection.is_sensitive_endpoint and not inspection.has_auth_header:
        matches.append(
            RuleMatch(
                rule="missing_auth_on_sensitive_endpoint",
                reason="Sensitive endpoint was accessed without an Authorization header.",
                score=25,
            )
        )

    if inspection.body_size > MAX_BODY_SIZE:
        matches.append(
            RuleMatch(
                rule="oversized_payload",
                reason=f"Payload size {inspection.body_size} exceeds limit of {MAX_BODY_SIZE} bytes.",
                score=15,
            )
        )

    content_type = inspection.content_type or ""
    if "application/json" in content_type:
        if inspection.body_size > 0 and inspection.parsed_json is None:
            matches.append(
                RuleMatch(
                    rule="invalid_json_body",
                    reason="Request declared JSON content but body could not be parsed as valid JSON.",
                    score=20,
                )
            )

    if inspection.parsed_json is not None:
        if json_contains_suspicious_pattern(inspection.parsed_json):
            matches.append(
                RuleMatch(
                    rule="suspicious_sql_pattern",
                    reason="Request body contains SQL-injection-like input patterns.",
                    score=35,
                )
            )

    return matches


def compute_risk_score(rule_matches: list[RuleMatch]) -> int:
    return sum(match.score for match in rule_matches)


def decide_action(score: int) -> str:
    if score >= 60:
        return "block"
    if score >= 30:
        return "flag"
    return "allow"