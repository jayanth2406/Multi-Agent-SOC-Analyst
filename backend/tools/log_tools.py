"""Tool definitions for the Log-Correlation Agent.

These tools query the indexed SOC telemetry database (soc_telemetry.db)
containing UNSW-NB15 network flows, LANL authentication events, and BETH endpoint logs.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from langchain_core.tools import tool

from backend.storage.db import (
    query_auth_logs_db,
    query_endpoint_logs_db,
    query_network_flows_db,
)


@tool
def query_network_flows_tool(
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
    limit: int = 15,
) -> str:
    """Query network flow records (from UNSW-NB15 / perimeter firewall).
    
    Args:
        src_ip: Source IPv4 address to filter by.
        dst_ip: Destination IPv4 address to filter by.
        dst_port: Target destination port (e.g. 80, 443, 22).
        limit: Maximum number of flow records to return.
    """
    rows = query_network_flows_db(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, limit=limit)
    if not rows:
        return f"No network flows found matching criteria (src_ip={src_ip}, dst_ip={dst_ip}, dst_port={dst_port})."
    return json.dumps(rows, indent=2)


@tool
def query_auth_logs_tool(
    user: Optional[str] = None,
    host: Optional[str] = None,
    src_ip: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 15,
) -> str:
    """Query authentication telemetry (SSH, Kerberos, Windows Event 4624/4625 logs).
    
    Args:
        user: Username to search for.
        host: Target machine/host name.
        src_ip: Remote originating IP address.
        status: Filter by LOGON_SUCCESS or LOGON_FAILURE.
        limit: Maximum records to return.
    """
    rows = query_auth_logs_db(user=user, host=host, src_ip=src_ip, status=status, limit=limit)
    if not rows:
        return f"No authentication records found matching criteria (user={user}, host={host}, src_ip={src_ip})."
    return json.dumps(rows, indent=2)


@tool
def query_endpoint_logs_tool(
    host: Optional[str] = None,
    process_name: Optional[str] = None,
    sha256: Optional[str] = None,
    limit: int = 15,
) -> str:
    """Query endpoint / EDR telemetry (from BETH dataset: process executions, parent processes, commands).
    
    Args:
        host: Target hostname.
        process_name: Name of executable (e.g. powershell.exe, cmd.exe).
        sha256: Hash of binary.
        limit: Maximum records to return.
    """
    rows = query_endpoint_logs_db(host=host, process_name=process_name, sha256=sha256, limit=limit)
    if not rows:
        return f"No endpoint events found matching criteria (host={host}, process_name={process_name}, sha256={sha256})."
    return json.dumps(rows, indent=2)
