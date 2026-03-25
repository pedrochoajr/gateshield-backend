import json
import re

from gateway.models import RequestInspection, RuleMatch

SENSITIVE_PATHS = {
    "/login",
    "/payments",
    "/account",
    "/admin",
}

MAX_BODY_SIZE = 1024  # bytes

SUSPICIOUS_HEADERS = {
    "x-original-url",
    "x-rewrite-url",
    "x-forwarded-host",
}

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"/etc/passwd",
    r"boot\.ini",
]

XSS_PATTERNS = [
    r"<script.*?>.*?</script>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"<img.*?onerror\s*=",
]


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


def contains_suspicious_sql_pattern(value) -> bool:
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


def contains_path_traversal_pattern(value) -> bool:
    if not isinstance(value, str):
        return False

    lowered = value.lower()
    return any(re.search(pattern, lowered) for pattern in PATH_TRAVERSAL_PATTERNS)


def contains_xss_pattern(value) -> bool:
    if not isinstance(value, str):
        return False

    lowered = value.lower()
    return any(re.search(pattern, lowered) for pattern in XSS_PATTERNS)


def json_contains_suspicious_pattern(data) -> bool:
    if isinstance(data, dict):
        return any(json_contains_suspicious_pattern(v) for v in data.values())

    if isinstance(data, list):
        return any(json_contains_suspicious_pattern(item) for item in data)

    return contains_suspicious_sql_pattern(data)


def json_contains_path_traversal(data) -> bool:
    if isinstance(data, dict):
        return any(json_contains_path_traversal(v) for v in data.values())

    if isinstance(data, list):
        return any(json_contains_path_traversal(item) for item in data)

    return contains_path_traversal_pattern(data)


def json_contains_xss(data) -> bool:
    if isinstance(data, dict):
        return any(json_contains_xss(v) for v in data.values())

    if isinstance(data, list):
        return any(json_contains_xss(item) for item in data)

    return contains_xss_pattern(data)


def has_suspicious_headers(inspection: RequestInspection) -> list[str]:
    suspicious = []

    for header_name in SUSPICIOUS_HEADERS:
        if header_name in inspection.headers:
            suspicious.append(header_name)

    return suspicious


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

    if contains_path_traversal_pattern(inspection.path):
        matches.append(
            RuleMatch(
                rule="path_traversal_path",
                reason="Request path contains path-traversal-like patterns.",
                score=35,
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

        if json_contains_path_traversal(inspection.parsed_json):
            matches.append(
                RuleMatch(
                    rule="path_traversal_body",
                    reason="Request body contains path-traversal-like input patterns.",
                    score=30,
                )
            )

        if json_contains_xss(inspection.parsed_json):
            matches.append(
                RuleMatch(
                    rule="xss_body",
                    reason="Request body contains XSS-like input patterns.",
                    score=30,
                )
            )

    suspicious_headers = has_suspicious_headers(inspection)
    if suspicious_headers:
        matches.append(
            RuleMatch(
                rule="suspicious_headers",
                reason=f"Request contains suspicious routing or proxy-style headers: {', '.join(suspicious_headers)}",
                score=20,
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