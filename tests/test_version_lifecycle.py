import sqlite3
import sys
import unittest
from datetime import datetime
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from policywatch.data.db import apply_schema
from policywatch.services import (
    create_policy,
    set_version_current,
    set_version_ratified,
    set_version_status,
)


def _seed_policy(conn: sqlite3.Connection) -> int:
    cursor = conn.execute(
        """
        INSERT INTO policies (
            title,
            slug,
            category,
            status,
            ratified,
            effective_date,
            review_due_date,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Test Policy",
            "test-policy",
            "General",
            "Draft",
            0,
            "2024-01-01",
            "2024-12-31",
            datetime.utcnow().isoformat(),
        ),
    )
    return cursor.lastrowid


def _seed_version(conn: sqlite3.Connection, policy_id: int, status: str = "Draft") -> int:
    cursor = conn.execute(
        """
        INSERT INTO policy_versions (
            policy_id,
            version_number,
            created_at,
            file_path,
            original_filename,
            file_size_bytes,
            sha256_hash,
            status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            policy_id,
            1,
            datetime.utcnow().isoformat(),
            "test.pdf",
            "test.pdf",
            123,
            "deadbeef",
            status,
        ),
    )
    return cursor.lastrowid


class VersionLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        apply_schema(self.conn)

    def tearDown(self) -> None:
        self.conn.close()

    def test_happy_path_lifecycle(self) -> None:
        policy_id = _seed_policy(self.conn)
        version_id = _seed_version(self.conn, policy_id)

        set_version_status(self.conn, version_id, "Ratified")
        row = self.conn.execute(
            "SELECT status, ratified FROM policy_versions WHERE id = ?",
            (version_id,),
        ).fetchone()
        self.assertEqual(row["status"], "Ratified")
        self.assertEqual(row["ratified"], 1)

        set_version_status(self.conn, version_id, "Active")
        row = self.conn.execute(
            "SELECT status FROM policy_versions WHERE id = ?",
            (version_id,),
        ).fetchone()
        policy_row = self.conn.execute(
            "SELECT current_version_id FROM policies WHERE id = ?",
            (policy_id,),
        ).fetchone()
        self.assertEqual(row["status"], "Active")
        self.assertEqual(policy_row["current_version_id"], version_id)

        set_version_status(self.conn, version_id, "Withdrawn")
        row = self.conn.execute(
            "SELECT status FROM policy_versions WHERE id = ?",
            (version_id,),
        ).fetchone()
        policy_row = self.conn.execute(
            "SELECT current_version_id FROM policies WHERE id = ?",
            (policy_id,),
        ).fetchone()
        self.assertEqual(row["status"], "Withdrawn")
        self.assertIsNone(policy_row["current_version_id"])

        set_version_status(self.conn, version_id, "Archived")
        row = self.conn.execute(
            "SELECT status FROM policy_versions WHERE id = ?",
            (version_id,),
        ).fetchone()
        self.assertEqual(row["status"], "Archived")

    def test_invalid_current_for_draft(self) -> None:
        policy_id = _seed_policy(self.conn)
        version_id = _seed_version(self.conn, policy_id, status="Draft")

        with self.assertRaises(ValueError):
            set_version_current(self.conn, policy_id, version_id, True)

    def test_unratify_active_blocked(self) -> None:
        policy_id = _seed_policy(self.conn)
        version_id = _seed_version(self.conn, policy_id, status="Ratified")
        set_version_ratified(self.conn, version_id, True)
        set_version_status(self.conn, version_id, "Active")

        with self.assertRaises(ValueError):
            set_version_ratified(self.conn, version_id, False)

    def test_cannot_skip_draft_to_active(self) -> None:
        policy_id = _seed_policy(self.conn)
        version_id = _seed_version(self.conn, policy_id, status="Draft")

        with self.assertRaises(ValueError):
            set_version_status(self.conn, version_id, "Active")

    def test_new_policies_start_as_draft(self) -> None:
        with self.assertRaises(ValueError):
            create_policy(
                self.conn,
                title="New Policy",
                category="General",
                status="Active",
                review_due_date="",
                review_frequency_months=None,
                notes=None,
                created_by_user_id=None,
            )


if __name__ == "__main__":
    unittest.main()
