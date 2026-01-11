from __future__ import annotations

from pathlib import Path
import re
import sqlite3
from typing import Iterable, Iterator

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


def ensure_sqlite_cache(
    db_path: str,
    query: str,
    table: str | None = None,
) -> Path:
    table_name = table or _extract_table_name(query)
    if not table_name:
        raise AccessDriverError("Unable to identify the Access table to export.")
    sqlite_path = _sqlite_cache_path(db_path)
    _ensure_table_cached(db_path, table_name, sqlite_path)
    return sqlite_path


def _preview_query_via_sqlite(
    db_path: str,
    query: str,
    limit: int,
    table: str | None,
) -> list[dict]:
    sqlite_path = ensure_sqlite_cache(db_path, query, table)
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
        return _read_access_table_with_access_parser(db_path, table)
    except Exception:
        return _read_access_table_with_pyaccdb(db_path, table)


def _read_access_table_with_access_parser(db_path: str, table: str) -> tuple[list[str], list[list]]:
    try:
        from access_parser import AccessParser  # type: ignore[import-untyped]
    except ImportError as exc:
        raise AccessDriverError("access-parser is required for Access fallback.") from exc

    parser = AccessParser(str(db_path))
    try:
        parser.parse_tables()
    except AttributeError:
        pass

    table_obj = _find_access_parser_table(parser, table)
    if table_obj is None:
        raise AccessDriverError(f"Table '{table}' not found in Access file.")

    records = _iter_access_parser_table(table_obj)
    return _records_to_columns(records)


def _read_access_table_with_pyaccdb(db_path: str, table: str) -> tuple[list[str], list[list]]:
    try:
        from pyaccdb import AccessDatabase  # type: ignore[import-untyped]
    except ImportError as exc:
        raise AccessDriverError(
            "pyaccdb is required for Access fallback. Vendor the pyaccdb package "
            "into the project (pyaccdb/__init__.py) to enable this fallback."
        ) from exc

    db = AccessDatabase(str(db_path))
    if hasattr(db, "table"):
        table_obj = db.table(table)  # type: ignore[attr-defined]
    else:
        table_obj = db[table]  # type: ignore[index]
    records = _iter_pyaccdb_table(table_obj)
    return _records_to_columns(records)


def _records_to_columns(records: Iterable[dict]) -> tuple[list[str], list[list]]:
    columns: list[str] = []
    rows: list[list] = []
    for record in records:
        record_keys = list(record.keys())
        new_columns = [key for key in record_keys if key not in columns]
        if new_columns:
            columns.extend(new_columns)
            for row in rows:
                row.extend([None] * len(new_columns))
        rows.append([record.get(col) for col in columns])
    return columns, rows


def _find_access_parser_table(parser: object, table: str) -> object | None:
    if hasattr(parser, "tables"):
        source = parser.tables  # type: ignore[attr-defined]
        if isinstance(source, dict):
            return source.get(table)
        for entry in source:
            name = getattr(entry, "name", None) or getattr(entry, "table_name", None)
            if name == table:
                return entry
        return None
    if hasattr(parser, "get_table"):
        return parser.get_table(table)  # type: ignore[attr-defined]
    return None


def _iter_access_parser_table(table: object) -> Iterator[dict]:
    if hasattr(table, "rows"):
        rows = table.rows  # type: ignore[attr-defined]
        if callable(rows):
            yield from rows()
        else:
            yield from rows
        return
    if hasattr(table, "iter_records"):
        yield from table.iter_records()  # type: ignore[attr-defined]
        return
    if hasattr(table, "records"):
        records = table.records  # type: ignore[attr-defined]
        if callable(records):
            yield from records()
        else:
            yield from records
        return
    raise AccessDriverError("Unsupported access-parser table API.")


def _iter_pyaccdb_table(table: object) -> Iterator[dict]:
    if hasattr(table, "records"):
        records = table.records  # type: ignore[attr-defined]
        if callable(records):
            yield from records()
        else:
            yield from records
        return
    if hasattr(table, "iter_records"):
        yield from table.iter_records()  # type: ignore[attr-defined]
        return
    if hasattr(table, "rows"):
        rows = table.rows  # type: ignore[attr-defined]
        if callable(rows):
            yield from rows()
        else:
            yield from rows
        return
    raise AccessDriverError("Unsupported pyaccdb table API.")


def _ensure_table_cached(db_path: str, table: str, sqlite_path: Path) -> None:
    accdb_mtime = Path(db_path).stat().st_mtime
    if sqlite_path.exists():
        sqlite_mtime = sqlite_path.stat().st_mtime
        if sqlite_mtime >= accdb_mtime and _sqlite_has_table(sqlite_path, table):
            return
    _export_table_to_sqlite(db_path, table, sqlite_path)


def _sqlite_has_table(sqlite_path: Path, table: str) -> bool:
    with sqlite3.connect(sqlite_path) as conn:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        )
        return cursor.fetchone() is not None


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
