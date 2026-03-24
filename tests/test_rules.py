from gateway.models import RequestInspection
from gateway.rules import (
    is_sensitive_path,
    try_parse_json,
    contains_suspicious_sql_pattern,
    json_contains_suspicious_pattern,
    evaluate_rules,
    compute_risk_score,
    decide_action,
)


def make_inspection(
    *,
    method: str = "POST",
    path: str = "/login",
    query_params: dict | None = None,
    has_auth_header: bool = False,
    content_type: str | None = "application/json",
    body_size: int = 0,
    parsed_json=None,
    is_sensitive_endpoint: bool = True,
    client_host: str | None = "127.0.0.1"
) -> RequestInspection:
    return RequestInspection(
        method=method,
        path=path,
        query_params=query_params or {},
        has_auth_header=has_auth_header,
        content_type=content_type,
        body_size=body_size,
        parsed_json=parsed_json,
        is_sensitive_endpoint=is_sensitive_endpoint,
        client_host=client_host,
    )


def test_is_sensitive_path_true_for_known_sensitive_path():
    assert is_sensitive_path("login") is True
    assert is_sensitive_path("/admin") is True
    assert is_sensitive_path("payments") is True


def test_is_sensitive_path_false_for_non_sensitive_path():
    assert is_sensitive_path("search") is False
    assert is_sensitive_path("/products") is False


def test_try_parse_json_returns_dict_for_valid_json():
    body = b'{"username":"pedro","password":"secret"}'
    parsed = try_parse_json(body)

    assert parsed == {"username": "pedro", "password": "secret"}


def test_try_parse_json_returns_none_for_invalid_json():
    body = b'{"username":"pedro",'
    parsed = try_parse_json(body)

    assert parsed is None


def test_contains_suspicious_sql_pattern_detects_attack_string():
    assert contains_suspicious_sql_pattern("' OR 1=1 --") is True
    assert contains_suspicious_sql_pattern("UNION SELECT password FROM users") is True


def test_contains_suspicious_sql_pattern_ignores_normal_string():
    assert contains_suspicious_sql_pattern("pedro@example.com") is False
    assert contains_suspicious_sql_pattern("hello world") is False


def test_json_contains_suspicious_pattern_detects_nested_value():
    payload = {
        "user": {
            "email": "test@example.com",
            "input": "' OR 1=1 --"
        }
    }

    assert json_contains_suspicious_pattern(payload) is True


def test_json_contains_suspicious_pattern_returns_false_for_safe_json():
    payload = {
        "user": {
            "email": "test@example.com",
            "name": "Pedro"
        }
    }

    assert json_contains_suspicious_pattern(payload) is False


def test_evaluate_rules_flags_missing_auth_on_sensitive_endpoint():
    inspection = make_inspection(
        path="/login",
        has_auth_header=False,
        is_sensitive_endpoint=True,
        body_size=0,
        parsed_json=None,
    )

    matches = evaluate_rules(inspection)

    assert len(matches) == 1
    assert matches[0].rule == "missing_auth_on_sensitive_endpoint"
    assert matches[0].score == 25


def test_evaluate_rules_flags_oversized_payload():
    inspection = make_inspection(
        path="/upload",
        has_auth_header=True,
        is_sensitive_endpoint=False,
        body_size=2048,
        parsed_json={"data": "ok"},
    )

    matches = evaluate_rules(inspection)

    assert any(match.rule == "oversized_payload" for match in matches)


def test_evaluate_rules_flags_invalid_json_body():
    inspection = make_inspection(
        path="/login",
        has_auth_header=True,
        is_sensitive_endpoint=True,
        content_type="application/json",
        body_size=20,
        parsed_json=None,
    )

    matches = evaluate_rules(inspection)

    assert any(match.rule == "invalid_json_body" for match in matches)


def test_evaluate_rules_flags_suspicious_sql_pattern():
    inspection = make_inspection(
        path="/login",
        has_auth_header=True,
        is_sensitive_endpoint=True,
        body_size=40,
        parsed_json={"username": "admin", "password": "' OR 1=1 --"},
    )

    matches = evaluate_rules(inspection)

    assert any(match.rule == "suspicious_sql_pattern" for match in matches)


def test_evaluate_rules_returns_no_matches_for_safe_request():
    inspection = make_inspection(
        method="POST",
        path="/profile",
        has_auth_header=True,
        is_sensitive_endpoint=False,
        content_type="application/json",
        body_size=32,
        parsed_json={"name": "Pedro"},
    )

    matches = evaluate_rules(inspection)

    assert matches == []


def test_compute_risk_score_adds_all_scores():
    inspection = make_inspection(
        path="/login",
        has_auth_header=False,
        is_sensitive_endpoint=True,
        content_type="application/json",
        body_size=2048,
        parsed_json={"input": "' OR 1=1 --"},
    )

    matches = evaluate_rules(inspection)
    score = compute_risk_score(matches)

    assert score == 75


def test_decide_action_allow():
    assert decide_action(0) == "allow"
    assert decide_action(29) == "allow"


def test_decide_action_flag():
    assert decide_action(30) == "flag"
    assert decide_action(59) == "flag"


def test_decide_action_block():
    assert decide_action(60) == "block"
    assert decide_action(100) == "block"