import json
import sqlite3
from pathlib import Path
from typing import Optional

from gateway.models import SecurityEvent

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "gateshield.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                client_host TEXT,
                content_type TEXT,
                body_size INTEGER NOT NULL,
                has_auth_header INTEGER NOT NULL,
                is_sensitive_endpoint INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                decision TEXT NOT NULL,
                query_params_json TEXT,
                parsed_json TEXT,
                rule_matches_json TEXT
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_decision
            ON security_events (decision)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_path
            ON security_events (path)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
            ON security_events (timestamp)
        """)

        conn.commit()


def save_security_event(event: SecurityEvent) -> None:
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO security_events (
                event_id,
                timestamp,
                method,
                path,
                client_host,
                content_type,
                body_size,
                has_auth_header,
                is_sensitive_endpoint,
                risk_score,
                decision,
                query_params_json,
                parsed_json,
                rule_matches_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.event_id,
            event.timestamp,
            event.request_summary.method,
            event.request_summary.path,
            event.request_summary.client_host,
            event.request_summary.content_type,
            event.request_summary.body_size,
            int(event.request_summary.has_auth_header),
            int(event.request_summary.is_sensitive_endpoint),
            event.risk_score,
            event.decision,
            json.dumps(event.query_params),
            json.dumps(event.parsed_json),
            json.dumps([match.model_dump() for match in event.rule_matches]),
        ))
        conn.commit()


def _safe_json_loads(value: Optional[str]):
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _row_to_event_dict(row: sqlite3.Row) -> dict:
    return {
        "event_id": row["event_id"],
        "timestamp": row["timestamp"],
        "method": row["method"],
        "path": row["path"],
        "client_host": row["client_host"],
        "content_type": row["content_type"],
        "body_size": row["body_size"],
        "has_auth_header": bool(row["has_auth_header"]),
        "is_sensitive_endpoint": bool(row["is_sensitive_endpoint"]),
        "risk_score": row["risk_score"],
        "decision": row["decision"],
        "query_params": _safe_json_loads(row["query_params_json"]),
        "parsed_json": _safe_json_loads(row["parsed_json"]),
        "rule_matches": _safe_json_loads(row["rule_matches_json"]) or [],
    }


def get_all_events(
    decision: Optional[str] = None,
    path: Optional[str] = None,
    limit: int = 50,
) -> list[dict]:
    query = """
        SELECT *
        FROM security_events
    """
    conditions = []
    params = []

    if decision:
        conditions.append("decision = ?")
        params.append(decision)

    if path:
        conditions.append("path = ?")
        params.append(path)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()

    return [_row_to_event_dict(row) for row in rows]


def get_event_summary(
    decision: Optional[str] = None,
    path: Optional[str] = None,
) -> dict:
    base_query = "FROM security_events"
    conditions = []
    params = []

    if decision:
        conditions.append("decision = ?")
        params.append(decision)

    if path:
        conditions.append("path = ?")
        params.append(path)

    if conditions:
        base_query += " WHERE " + " AND ".join(conditions)

    with get_connection() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) AS count {base_query}",
            params
        ).fetchone()["count"]

        rows = conn.execute(
            f"""
            SELECT decision, COUNT(*) AS count
            {base_query}
            GROUP BY decision
            """,
            params
        ).fetchall()

    summary = {
        "total": total,
        "allow": 0,
        "flag": 0,
        "block": 0,
    }

    for row in rows:
        summary[row["decision"]] = row["count"]

    return summary


def clear_events() -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM security_events")
        conn.commit()