"""Access database integration helpers with a SQLite fallback."""

from __future__ import annotations

from pathlib import Path
import csv
import re
import sqlite3

from policywatch.core import config


class AccessDriverError(RuntimeError):
    """Raised when Access drivers or fallbacks are unavailable."""

    pass


def connect_access(db_path: str):
    """Connect to an Access database using ACE OLEDB via COM."""

    try:
        import win32com.client  # type: ignore[import-untyped]
    except ImportError as exc:
        raise AccessDriverError("pywin32 is required for Access ADO connections.") from exc

    try:
        connection = win32com.client.Dispatch("ADODB.Connection")
        connection.Open(f"Provider=Microsoft.ACE.OLEDB.12.0;Data Source={db_path};")
    except Exception as exc:
        raise AccessDriverError(
            "Access OLEDB provider not available. Install 32-bit Access Runtime/ACE and use a matching Python build."
        ) from exc
    return connection


def preview_query(conn, query: str, limit: int = 20) -> list[dict]:
    """Run a query against an Access connection and return up to ``limit`` rows."""

    columns, rows = _execute_ado_query(conn, query, limit=limit)
    return [dict(zip(columns, row)) for row in rows]


def preview_query_from_path(
    db_path: str,
    query: str,
    limit: int = 20,
    table: str | None = None,
) -> list[dict]:
    """Preview a query from a DB path, falling back to a SQLite export."""

    try:
        conn = connect_access(db_path)
    except AccessDriverError:
        return _preview_query_via_sqlite(db_path, query, limit=limit, table=table)
    try:
        return preview_query(conn, query, limit=limit)
    finally:
        _close_access_connection(conn)


def export_query_to_csv(db_path: str, query: str, destination: Path) -> Path:
    """Export an Access query result to a CSV file."""

    conn = connect_access(db_path)
    try:
        columns, rows = _execute_ado_query(conn, query)
    finally:
        _close_access_connection(conn)

    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        writer.writerows(rows)
    return destination


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

    conn = connect_access(db_path)
    try:
        return _execute_ado_query(conn, f"SELECT * FROM [{table}]")
    finally:
        _close_access_connection(conn)


def _execute_ado_query(conn, query: str, limit: int | None = None) -> tuple[list[str], list[list]]:
    """Execute a query via an existing ADO connection."""

    import win32com.client  # type: ignore[import-untyped]

    recordset = win32com.client.Dispatch("ADODB.Recordset")
    recordset.Open(query, conn)
    columns = [recordset.Fields.Item(i).Name for i in range(recordset.Fields.Count)]
    rows: list[list] = []
    while not recordset.EOF:
        rows.append([recordset.Fields.Item(i).Value for i in range(recordset.Fields.Count)])
        if limit is not None and len(rows) >= limit:
            break
        recordset.MoveNext()
    recordset.Close()
    return columns, rows


def _close_access_connection(conn) -> None:
    """Close an ADO connection safely."""

    if hasattr(conn, "Close"):
        conn.Close()


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
