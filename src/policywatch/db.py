from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable

def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def apply_schema(conn: sqlite3.Connection) -> None:
    with conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                disabled INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                slug TEXT NOT NULL,
                category TEXT NOT NULL,
                status TEXT NOT NULL,
                ratified INTEGER NOT NULL DEFAULT 0,
                ratified_at TEXT,
                ratified_by_user_id INTEGER,
                effective_date TEXT NOT NULL,
                review_due_date TEXT NOT NULL,
                expiry_date TEXT NOT NULL,
                owner TEXT,
                notes TEXT,
                current_version_id INTEGER,
                created_at TEXT NOT NULL,
                created_by_user_id INTEGER,
                FOREIGN KEY (ratified_by_user_id) REFERENCES users(id),
                FOREIGN KEY (created_by_user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS policy_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_id INTEGER NOT NULL,
                version_number INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                created_by_user_id INTEGER,
                file_path TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                file_size_bytes INTEGER NOT NULL,
                sha256_hash TEXT NOT NULL,
                ratified INTEGER NOT NULL DEFAULT 0,
                ratified_at TEXT,
                ratified_by_user_id INTEGER,
                FOREIGN KEY (policy_id) REFERENCES policies(id),
                FOREIGN KEY (created_by_user_id) REFERENCES users(id),
                FOREIGN KEY (ratified_by_user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS email_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sent_at TEXT NOT NULL,
                sender_windows_user TEXT NOT NULL,
                sender_mailbox TEXT,
                recipient_name TEXT NOT NULL,
                recipient_email TEXT NOT NULL,
                policy_id INTEGER NOT NULL,
                policy_title TEXT NOT NULL,
                policy_version_id INTEGER NOT NULL,
                version_number INTEGER NOT NULL,
                email_subject TEXT NOT NULL,
                email_part_index INTEGER NOT NULL,
                email_part_total INTEGER NOT NULL,
                total_attachment_bytes_for_part INTEGER NOT NULL,
                outlook_entry_id TEXT,
                status TEXT NOT NULL,
                error_text TEXT,
                prev_row_hash TEXT NOT NULL,
                row_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                actor TEXT,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id INTEGER,
                details TEXT,
                prev_row_hash TEXT NOT NULL,
                row_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_state (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                latest_row_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_event_state (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                latest_row_hash TEXT NOT NULL
            );

            CREATE TRIGGER IF NOT EXISTS email_log_no_update
            BEFORE UPDATE ON email_log
            BEGIN
                SELECT RAISE(ABORT, 'email_log is append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS email_log_no_delete
            BEFORE DELETE ON email_log
            BEGIN
                SELECT RAISE(ABORT, 'email_log is append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS audit_events_no_update
            BEFORE UPDATE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit_events is append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
            BEFORE DELETE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit_events is append-only');
            END;
            """
        )
    _ensure_policy_version_metadata(conn)
    _ensure_policy_metadata(conn)


def _ensure_policy_version_metadata(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(policy_versions)").fetchall()}
    additions = [
        ("status", "TEXT"),
        ("effective_date", "TEXT"),
        ("review_due_date", "TEXT"),
        ("review_frequency_months", "INTEGER"),
        ("expiry_date", "TEXT"),
        ("notes", "TEXT"),
    ]
    for name, column_type in additions:
        if name not in columns:
            conn.execute(f"ALTER TABLE policy_versions ADD COLUMN {name} {column_type}")


def _ensure_policy_metadata(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(policies)").fetchall()}
    if "review_frequency_months" not in columns:
        conn.execute("ALTER TABLE policies ADD COLUMN review_frequency_months INTEGER")


@contextmanager
def transactional(conn: sqlite3.Connection):
    try:
        conn.execute("BEGIN")
        yield
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def execute_with_retry(
    conn: sqlite3.Connection,
    statement: str,
    params: Iterable | None = None,
    retries: int = 3,
    delay: float = 0.1,
) -> sqlite3.Cursor:
    params = params or []
    for attempt in range(retries):
        try:
            return conn.execute(statement, params)
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == retries - 1:
                raise
            time.sleep(delay)
    return conn.execute(statement, params)
