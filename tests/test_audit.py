import sqlite3

from policywatch import db
from policywatch.audit import append_email_log, verify_audit_log


def _sample_row():
    return {
        "sent_at": "2024-01-01T00:00:00",
        "sender_windows_user": "user",
        "sender_mailbox": "mailbox",
        "recipient_name": "Test User",
        "recipient_email": "test@example.com",
        "policy_id": 1,
        "policy_title": "Test Policy",
        "policy_version_id": 10,
        "version_number": 1,
        "email_subject": "Policy",
        "email_part_index": 1,
        "email_part_total": 1,
        "total_attachment_bytes_for_part": 100,
        "outlook_entry_id": "entry",
        "status": "SENT",
        "error_text": "",
    }


def test_audit_log_hash_chain():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    db.apply_schema(conn)

    append_email_log(conn, _sample_row())
    append_email_log(conn, _sample_row())

    ok, message = verify_audit_log(conn)
    assert ok
    assert message == "Audit log verified"
