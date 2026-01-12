"""Access database integration helpers with a SQLite fallback."""

from __future__ import annotations

from pathlib import Path
import os
import re
import sqlite3
from typing import Any

import win32com.client

from policywatch.core import config


class AccessDriverError(RuntimeError):
    """Raised when Access drivers or fallbacks are unavailable."""

    pass


def connect_access(db_path: str) -> Any:
    """Connect to an Access database using the ACE OLEDB provider."""

    return _open_ado_connection(db_path)


def preview_query(conn: Any, query: str, limit: int = 20) -> list[dict]:
    """Run a query against an Access connection and return up to ``limit`` rows."""

    recordset = win32com.client.Dispatch("ADODB.Recordset")
    recordset.Open(query, conn)
    columns = [recordset.Fields.Item(i).Name for i in range(recordset.Fields.Count)]
    rows: list[dict] = []
    while not recordset.EOF and len(rows) < limit:
        row = {columns[i]: recordset.Fields.Item(i).Value for i in range(len(columns))}
        rows.append(row)
        recordset.MoveNext()
    recordset.Close()
    return rows


def preview_query_from_path(
    db_path: str,
    query: str,
    limit: int = 20,
    table: str | None = None,
) -> list[dict]:
    """Preview a query from a DB path, falling back to a SQLite export."""

    conn = connect_access(db_path)
    try:
        return preview_query(conn, query, limit=limit)
    except AccessDriverError:
        return _preview_query_via_sqlite(db_path, query, limit=limit, table=table)
    finally:
        conn.Close()


def _preview_query_via_sqlite(
    db_path: str,
    query: str,
    limit: int,
    table: str | None,
) -> list[dict]:
    """Export the Access table to SQLite and run the query for previewing."""

    table_name = table or _extract_table_name(query)
    if not table_name:
        raise AccessDriverError("Unable to identify the Access table to export.")
    sqlite_path = _sqlite_cache_path(db_path)
    _export_table_to_sqlite(db_path, table_name, sqlite_path)
    with sqlite3.connect(sqlite_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(query)
        rows = cursor.fetchmany(limit)
        return [dict(row) for row in rows]


def _export_table_to_sqlite(db_path: str, table: str, sqlite_path: Path) -> None:
    """Export an Access table into a SQLite file for fallback queries."""

    columns, rows = _read_access_table(db_path, table)
    if not columns:
        raise AccessDriverError(f"No columns found for table '{table}'.")
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(sqlite_path) as conn:
        column_defs = ", ".join([f'"{name}" TEXT' for name in columns])
        column_names = ", ".join([f'"{name}"' for name in columns])
        placeholders = ", ".join(["?"] * len(columns))
        conn.execute(f'DROP TABLE IF EXISTS "{table}"')
        conn.execute(f'CREATE TABLE "{table}" ({column_defs})')
        if rows:
            conn.executemany(
                f'INSERT INTO "{table}" ({column_names}) VALUES ({placeholders})',
                rows,
            )
        conn.commit()


def _read_access_table(db_path: str, table: str) -> tuple[list[str], list[list]]:
    """Read an Access table via OLEDB and return columns and rows."""

    connection = _open_ado_connection(db_path)

    recordset = win32com.client.Dispatch("ADODB.Recordset")
    recordset.Open(f"SELECT * FROM [{table}]", connection)
    columns = [recordset.Fields.Item(i).Name for i in range(recordset.Fields.Count)]
    rows = []
    while not recordset.EOF:
        rows.append([recordset.Fields.Item(i).Value for i in range(recordset.Fields.Count)])
        recordset.MoveNext()
    recordset.Close()
    connection.Close()
    return columns, rows


def _extract_table_name(query: str) -> str:
    """Extract a table name from a SELECT query for fallback usage."""

    match = re.search(r"\\bFROM\\s+\\[([^\\]]+)\\]", query, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r"\\bFROM\\s+([\\w\\s]+)", query, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return ""


def _sqlite_cache_path(db_path: str) -> Path:
    """Return the cache path for the SQLite-exported Access data."""

    data_dir = config.get_paths().data_dir
    name = Path(db_path).stem or "access"
    return data_dir / f"{name}_cache.sqlite"


def _open_ado_connection(db_path: str) -> Any:
    """Open an ADODB connection using the newest available ACE provider."""

    provider_override = os.environ.get("POLICYWATCH_ACCESS_PROVIDER", "").strip()
    if provider_override:
        providers = [item.strip() for item in provider_override.split(",") if item.strip()]
    else:
        providers = ["Microsoft.ACE.OLEDB.16.0", "Microsoft.ACE.OLEDB.12.0"]
    last_error: Exception | None = None
    for provider in providers:
        try:
            connection = win32com.client.Dispatch("ADODB.Connection")
            connection.Open(f"Provider={provider};Data Source={db_path};")
            return connection
        except Exception as exc:
            last_error = exc
            continue
    raise AccessDriverError(
        "Access OLEDB provider not available. Office 2016 installs Microsoft.ACE.OLEDB.16.0; "
        "ensure the Access Runtime/Office bitness matches Python and that the ACE provider is "
        "installed. You can override providers with POLICYWATCH_ACCESS_PROVIDER "
        "(comma-separated)."
    ) from last_error
