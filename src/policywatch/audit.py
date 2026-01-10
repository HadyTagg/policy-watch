from __future__ import annotations

import hashlib
import sqlite3
from typing import Iterable

EMAIL_LOG_FIELDS = [
    "sent_at",
    "sender_windows_user",
    "sender_mailbox",
    "recipient_name",
    "recipient_email",
    "policy_id",
    "policy_title",
    "policy_version_id",
    "version_number",
    "email_subject",
    "email_part_index",
    "email_part_total",
    "total_attachment_bytes_for_part",
    "outlook_entry_id",
    "status",
    "error_text",
]


def _canonical_row_content(row: dict) -> str:
    parts = []
    for field in EMAIL_LOG_FIELDS:
        value = row.get(field, "")
        parts.append(str(value) if value is not None else "")
    return "|".join(parts)


def _hash_chain(prev_hash: str, row_content: str) -> str:
    payload = (prev_hash + row_content).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def get_latest_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT latest_row_hash FROM audit_state WHERE singleton_id = 1").fetchone()
    if row:
        return row["latest_row_hash"]
    return ""


def append_email_log(conn: sqlite3.Connection, row: dict) -> None:
    prev_hash = get_latest_hash(conn)
    row_content = _canonical_row_content(row)
    row_hash = _hash_chain(prev_hash, row_content)

    fields = EMAIL_LOG_FIELDS + ["prev_row_hash", "row_hash"]
    values = [row.get(field) for field in EMAIL_LOG_FIELDS] + [prev_hash, row_hash]

    placeholders = ", ".join(["?"] * len(fields))
    conn.execute(
        f"INSERT INTO email_log ({', '.join(fields)}) VALUES ({placeholders})",
        values,
    )
    conn.execute(
        "INSERT INTO audit_state (singleton_id, latest_row_hash) VALUES (1, ?) "
        "ON CONFLICT(singleton_id) DO UPDATE SET latest_row_hash = excluded.latest_row_hash",
        (row_hash,),
    )


def verify_audit_log(conn: sqlite3.Connection) -> tuple[bool, str]:
    rows = conn.execute(
        "SELECT * FROM email_log ORDER BY id"
    ).fetchall()
    prev_hash = ""
    for row in rows:
        row_dict = dict(row)
        row_content = _canonical_row_content(row_dict)
        expected_hash = _hash_chain(prev_hash, row_content)
        if row_dict["row_hash"] != expected_hash:
            return False, f"Hash mismatch at id {row_dict['id']}"
        prev_hash = row_dict["row_hash"]
    latest_hash = get_latest_hash(conn)
    if rows and latest_hash != rows[-1]["row_hash"]:
        return False, "Latest hash mismatch"
    return True, "Audit log verified"


def seed_email_logs(conn: sqlite3.Connection, rows: Iterable[dict]) -> None:
    for row in rows:
        append_email_log(conn, row)
