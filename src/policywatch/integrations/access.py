from __future__ import annotations

import pyodbc


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
