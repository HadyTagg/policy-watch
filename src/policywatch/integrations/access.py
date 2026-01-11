from __future__ import annotations

from pathlib import Path
import re
import sqlite3

import pyodbc

from policywatch import config


class AccessDriverError(RuntimeError):
    pass


def connect_access(db_path: str) -> pyodbc.Connection:
    drivers = [driver for driver in pyodbc.drivers() if "Access" in driver]
    if not drivers:
        raise AccessDriverError("Microsoft Access Database Engine driver not found.")
    driver = drivers[-1]
    conn_str = f"DRIVER={{{driver}}};DBQ={db_path};"
    return pyodbc.connect(conn_str)


def preview_query(conn: pyodbc.Connection, query: str, limit: int = 20) -> list[dict]:
    cursor = conn.cursor()
    cursor.execute(query)
    columns = [col[0] for col in cursor.description]
    rows = cursor.fetchmany(limit)
    return [dict(zip(columns, row)) for row in rows]


def preview_query_from_path(
    db_path: str,
    query: str,
    limit: int = 20,
    table: str | None = None,
) -> list[dict]:
    try:
        conn = connect_access(db_path)
    except AccessDriverError:
        return _preview_query_via_sqlite(db_path, query, limit=limit, table=table)
    try:
        return preview_query(conn, query, limit=limit)
    finally:
        conn.close()


def _preview_query_via_sqlite(
    db_path: str,
    query: str,
    limit: int,
    table: str | None,
) -> list[dict]:
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
    try:
        import win32com.client  # type: ignore[import-untyped]
    except ImportError as exc:
        raise AccessDriverError("pywin32 is required for Access fallback.") from exc

    try:
        connection = win32com.client.Dispatch("ADODB.Connection")
        connection.Open(f"Provider=Microsoft.ACE.OLEDB.12.0;Data Source={db_path};")
    except Exception as exc:
        raise AccessDriverError(
            "Access OLEDB provider not available. Install Microsoft Access Database Engine or Access Runtime."
        ) from exc

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
    match = re.search(r"\\bFROM\\s+\\[([^\\]]+)\\]", query, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r"\\bFROM\\s+([\\w\\s]+)", query, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return ""


def _sqlite_cache_path(db_path: str) -> Path:
    data_dir = config.get_paths().data_dir
    name = Path(db_path).stem or "access"
    return data_dir / f"{name}_cache.sqlite"
