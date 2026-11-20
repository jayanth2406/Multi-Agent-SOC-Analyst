"""Database connection and query helpers for the SOC log telemetry store."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path("data/soc_telemetry.db") if Path("data/soc_telemetry.db").exists() else Path("locals/data/soc_telemetry.db")


def get_db_connection() -> sqlite3.Connection:
    """Return a connection with Row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def query_network_flows_db(
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
    limit: int = 25,
) -> List[Dict[str, Any]]:
    """Query indexed network flows (e.g. from UNSW-NB15 / CICIDS)."""
    if not DB_PATH.exists():
        return []

    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT timestamp, src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent, bytes_received, attack_cat, label, dataset_source FROM network_flows WHERE 1=1"
    params: List[Any] = []

    if src_ip:
        query += " AND src_ip = ?"
        params.append(src_ip)
    if dst_ip:
        query += " AND dst_ip = ?"
        params.append(dst_ip)
    if dst_port:
        query += " AND dst_port = ?"
        params.append(dst_port)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def query_auth_logs_db(
    user: Optional[str] = None,
    host: Optional[str] = None,
    src_ip: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 25,
) -> List[Dict[str, Any]]:
    """Query indexed authentication events (SSH, Kerberos, Windows Event 4624/4625)."""
    if not DB_PATH.exists():
        return []

    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT timestamp, user, host, src_ip, auth_service, status, failure_reason, dataset_source FROM auth_logs WHERE 1=1"
    params: List[Any] = []

    if user:
        query += " AND user = ?"
        params.append(user)
    if host:
        query += " AND host = ?"
        params.append(host)
    if src_ip:
        query += " AND src_ip = ?"
        params.append(src_ip)
    if status:
        query += " AND status = ?"
        params.append(status)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def query_endpoint_logs_db(
    host: Optional[str] = None,
    process_name: Optional[str] = None,
    sha256: Optional[str] = None,
    limit: int = 25,
) -> List[Dict[str, Any]]:
    """Query indexed endpoint telemetry (BETH / Sysmon / Process executions)."""
    if not DB_PATH.exists():
        return []

    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT timestamp, host, user, process_name, process_id, parent_process, command_line, sha256, action, dataset_source FROM endpoint_logs WHERE 1=1"
    params: List[Any] = []

    if host:
        query += " AND host = ?"
        params.append(host)
    if process_name:
        query += " AND process_name = ?"
        params.append(process_name)
    if sha256:
        query += " AND sha256 = ?"
        params.append(sha256)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows
