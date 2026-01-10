from __future__ import annotations

import datetime
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from policywatch import audit
from policywatch import config
from policywatch.policies import build_policy_path, next_version_number, slugify
from policywatch.traffic import traffic_light_status


def _resolve_london_tz() -> datetime.tzinfo:
    try:
        return ZoneInfo("Europe/London")
    except ZoneInfoNotFoundError:
        return datetime.datetime.now().astimezone().tzinfo or datetime.timezone.utc


LONDON_TZ = _resolve_london_tz()


def _resolve_actor() -> str | None:
    try:
        return os.getlogin()
    except OSError:
        return None


def _log_event(
    conn,
    action: str,
    entity_type: str,
    entity_id: int | None,
    details: str | None = None,
) -> None:
    audit.append_event_log(
        conn,
        {
            "occurred_at": datetime.datetime.utcnow().isoformat(),
            "actor": _resolve_actor(),
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "details": details,
        },
    )


@dataclass(frozen=True)
class PolicyRow:
    id: int
    title: str
    category: str
    status: str
    ratified: bool
    review_due_date: str
    expiry_date: str
    current_version_id: int | None
    current_version_number: int | None
    traffic_status: str
    traffic_reason: str


def _policy_root(conn) -> Path:
    root = config.get_setting(conn, "policy_root", "")
    if root:
        return Path(root)
    paths = config.get_paths()
    return paths.data_dir / "policies"


def list_policies(conn) -> list[PolicyRow]:
    rows = conn.execute(
        """
        SELECT p.id, p.title, p.category, p.status,
               COALESCE(v.ratified, 0) AS ratified,
               p.review_due_date, p.expiry_date, p.current_version_id,
               v.version_number AS current_version_number
        FROM policies p
        LEFT JOIN policy_versions v ON v.id = p.current_version_id
        ORDER BY p.created_at DESC
        """
    ).fetchall()

    policies: list[PolicyRow] = []
    today = datetime.datetime.now(LONDON_TZ).date()
    amber_months = int(config.get_setting(conn, "amber_months", 2) or 2)
    overdue_days = int(config.get_setting(conn, "overdue_grace_days", 0) or 0)

    for row in rows:
        review_due = datetime.date.fromisoformat(row["review_due_date"])
        expiry = datetime.date.fromisoformat(row["expiry_date"])
        traffic = traffic_light_status(today, review_due, expiry, amber_months, overdue_days)
        policies.append(
            PolicyRow(
                id=row["id"],
                title=row["title"],
                category=row["category"],
                status=row["status"],
                ratified=bool(row["ratified"]),
                review_due_date=row["review_due_date"],
                expiry_date=row["expiry_date"],
                current_version_id=row["current_version_id"],
                current_version_number=row["current_version_number"],
                traffic_status=traffic.status,
                traffic_reason=traffic.reason,
            )
        )
    return policies


def list_versions(conn, policy_id: int) -> list[dict]:
    rows = conn.execute(
        """
        SELECT id, version_number, created_at, sha256_hash, ratified,
               original_filename, file_size_bytes
        FROM policy_versions
        WHERE policy_id = ?
        ORDER BY version_number DESC
        """,
        (policy_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def create_policy(conn, title: str, category: str, status: str, effective: str, review_due: str, expiry: str,
                  notes: str | None, created_by_user_id: int | None) -> int:
    created_at = datetime.datetime.utcnow().isoformat()
    slug = slugify(title)
    cursor = conn.execute(
        """
        INSERT INTO policies (
            title, slug, category, status, ratified, ratified_at, ratified_by_user_id,
            effective_date, review_due_date, expiry_date, owner, notes,
            current_version_id, created_at, created_by_user_id
        ) VALUES (?, ?, ?, ?, 0, NULL, NULL, ?, ?, ?, ?, ?, NULL, ?, ?)
        """,
        (
            title,
            slug,
            category,
            status,
            effective,
            review_due,
            expiry,
            None,
            notes,
            created_at,
            created_by_user_id,
        ),
    )
    conn.commit()
    _log_event(conn, "create_policy", "policy", cursor.lastrowid, f"title={title}")
    return cursor.lastrowid


def add_policy_version(
    conn,
    policy_id: int,
    original_path: Path,
    created_by_user_id: int | None,
) -> int:
    existing = conn.execute(
        "SELECT version_number FROM policy_versions WHERE policy_id = ?",
        (policy_id,),
    ).fetchall()
    version_number = next_version_number([row["version_number"] for row in existing])

    policy_row = conn.execute(
        "SELECT title, category FROM policies WHERE id = ?",
        (policy_id,),
    ).fetchone()
    if not policy_row:
        raise ValueError("Policy not found")

    policy_root = _policy_root(conn)
    target_path = build_policy_path(
        policy_root,
        policy_row["category"],
        slugify(policy_row["title"]),
        version_number,
        original_path.name,
    )
    target_path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = target_path.with_suffix(target_path.suffix + ".tmp")
    with original_path.open("rb") as source, temp_path.open("wb") as dest:
        sha256 = hashlib.sha256()
        while True:
            chunk = source.read(8192)
            if not chunk:
                break
            dest.write(chunk)
            sha256.update(chunk)
    existing_hash = conn.execute(
        "SELECT 1 FROM policy_versions WHERE policy_id = ? AND sha256_hash = ? LIMIT 1",
        (policy_id, sha256.hexdigest()),
    ).fetchone()
    if existing_hash:
        temp_path.unlink(missing_ok=True)
        raise ValueError("No change detected. Policy document matches an existing version.")
    temp_path.replace(target_path)

    file_size = target_path.stat().st_size
    created_at = datetime.datetime.utcnow().isoformat()
    cursor = conn.execute(
        """
        INSERT INTO policy_versions (
            policy_id, version_number, created_at, created_by_user_id,
            file_path, original_filename, file_size_bytes, sha256_hash,
            ratified, ratified_at, ratified_by_user_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL)
        """,
        (
            policy_id,
            version_number,
            created_at,
            created_by_user_id,
            str(target_path),
            original_path.name,
            file_size,
            sha256.hexdigest(),
        ),
    )
    conn.commit()
    _log_event(
        conn,
        "add_policy_version",
        "policy_version",
        cursor.lastrowid,
        f"policy_id={policy_id} version={version_number}",
    )
    current_version_id = conn.execute(
        "SELECT current_version_id FROM policies WHERE id = ?",
        (policy_id,),
    ).fetchone()
    if current_version_id and not current_version_id["current_version_id"]:
        set_current_version(conn, policy_id, cursor.lastrowid)
    return cursor.lastrowid


def mark_version_ratified(conn, version_id: int, user_id: int | None) -> None:
    ratified_at = datetime.datetime.utcnow().isoformat()
    conn.execute(
        "UPDATE policy_versions SET ratified = 1, ratified_at = ?, ratified_by_user_id = ? WHERE id = ?",
        (ratified_at, user_id, version_id),
    )
    conn.commit()
    _log_event(conn, "ratify_version", "policy_version", version_id, None)


def set_current_version(conn, policy_id: int, version_id: int) -> None:
    conn.execute(
        "UPDATE policies SET current_version_id = ? WHERE id = ?",
        (version_id, policy_id),
    )
    conn.commit()
    _log_event(conn, "set_current_version", "policy", policy_id, f"version_id={version_id}")


def get_version_file(conn, version_id: int) -> str:
    row = conn.execute("SELECT file_path FROM policy_versions WHERE id = ?", (version_id,)).fetchone()
    if not row:
        raise ValueError("Version not found")
    return row["file_path"]


def list_categories(conn) -> list[str]:
    rows = conn.execute("SELECT name FROM categories ORDER BY name").fetchall()
    return [row["name"] for row in rows]


def create_category(conn, name: str) -> None:
    created_at = datetime.datetime.utcnow().isoformat()
    cursor = conn.execute("INSERT INTO categories (name, created_at) VALUES (?, ?)", (name, created_at))
    conn.commit()
    _log_event(conn, "create_category", "category", cursor.lastrowid, f"name={name}")


def delete_category(conn, category_id: int) -> None:
    conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
    conn.commit()
    _log_event(conn, "delete_category", "category", category_id, None)


def export_backup(conn, destination: Path, include_files: bool) -> None:
    data_dir = config.get_paths().data_dir
    destination.parent.mkdir(parents=True, exist_ok=True)
    import zipfile

    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        db_path = data_dir / "policywatch.db"
        if db_path.exists():
            archive.write(db_path, arcname="policywatch.db")
        if include_files:
            policies_root = _policy_root(conn)
            if policies_root.exists():
                for root, _, files in os.walk(policies_root):
                    for file in files:
                        file_path = Path(root) / file
                        arcname = file_path.relative_to(policies_root)
                        archive.write(file_path, arcname=Path("policies") / arcname)


def parse_mapping_json(mapping_text: str) -> dict:
    if not mapping_text:
        return {}
    import json

    try:
        return json.loads(mapping_text)
    except json.JSONDecodeError:
        return {}


def build_staff_query(mode: str, table: str, mapping: dict, custom_query: str) -> str:
    if mode == "query" and custom_query.strip():
        return custom_query

    fields = []
    for key in [
        "staff_id",
        "first_name",
        "last_name",
        "display_name",
        "email",
        "role_team",
        "active_flag",
    ]:
        field_name = mapping.get(key)
        if field_name:
            fields.append(f"[{field_name}]")
    if not table or not fields:
        return ""
    return f"SELECT {', '.join(fields)} FROM [{table}]"
