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
    status: str | None
    ratified: bool
    review_due_date: str | None
    expiry_date: str | None
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


def _cleanup_empty_dirs(path: Path, stop_at: Path) -> None:
    current = path
    stop_at = stop_at.resolve()
    while True:
        current = current.resolve()
        if current == stop_at or not current.exists():
            break
        if any(current.iterdir()):
            break
        current.rmdir()
        current = current.parent


def list_policies(conn) -> list[PolicyRow]:
    rows = conn.execute(
        """
        SELECT p.id, p.title, p.category,
               CASE WHEN p.current_version_id IS NULL THEN NULL ELSE v.status END AS status,
               CASE WHEN p.current_version_id IS NULL THEN 0 ELSE COALESCE(v.ratified, 0) END AS ratified,
               CASE WHEN p.current_version_id IS NULL THEN NULL ELSE v.review_due_date END AS review_due_date,
               CASE WHEN p.current_version_id IS NULL THEN NULL ELSE v.expiry_date END AS expiry_date,
               p.current_version_id,
               v.version_number AS current_version_number
        FROM policies p
        LEFT JOIN policy_versions v ON v.id = p.current_version_id
        ORDER BY p.created_at DESC
        """
    ).fetchall()

    policies: list[PolicyRow] = []
    today = datetime.datetime.now(LONDON_TZ).date()
    amber_months = int(config.get_setting(conn, "amber_months", 2) or 2)

    for row in rows:
        traffic_status = ""
        traffic_reason = ""
        if row["expiry_date"]:
            expiry = datetime.date.fromisoformat(row["expiry_date"])
            traffic = traffic_light_status(today, expiry, amber_months)
            traffic_status = traffic.status
            traffic_reason = traffic.reason
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
                traffic_status=traffic_status,
                traffic_reason=traffic_reason,
            )
        )
    return policies


def list_versions(conn, policy_id: int) -> list[dict]:
    rows = conn.execute(
        """
        SELECT id, version_number, created_at, sha256_hash, ratified,
               status, original_filename, file_size_bytes
        FROM policy_versions
        WHERE policy_id = ?
        ORDER BY version_number DESC
        """,
        (policy_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def create_policy(
    conn,
    title: str,
    category: str,
    status: str,
    expiry: str,
    notes: str | None,
    created_by_user_id: int | None,
) -> int:
    created_at = datetime.datetime.utcnow().isoformat()
    slug = slugify(title)
    effective_date = expiry or ""
    review_due_date = expiry or ""
    cursor = conn.execute(
        """
        INSERT INTO policies (
            title, slug, category, status, ratified, ratified_at, ratified_by_user_id,
            effective_date, review_due_date, review_frequency_months, expiry_date, owner, notes,
            current_version_id, created_at, created_by_user_id
        ) VALUES (?, ?, ?, ?, 0, NULL, NULL, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
        """,
        (
            title,
            slug,
            category,
            status,
            effective_date,
            review_due_date,
            None,
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
    metadata: dict | None = None,
) -> int:
    existing = conn.execute(
        "SELECT version_number FROM policy_versions WHERE policy_id = ?",
        (policy_id,),
    ).fetchall()
    version_number = next_version_number([row["version_number"] for row in existing])

    policy_row = conn.execute(
        """
        SELECT title, category, status, effective_date, review_due_date,
               review_frequency_months, expiry_date, notes
        FROM policies
        WHERE id = ?
        """,
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
    effective_date = policy_row["effective_date"]
    review_frequency = policy_row["review_frequency_months"]
    expiry_date = policy_row["expiry_date"]
    status = policy_row["status"]
    notes = policy_row["notes"]
    if metadata:
        if "expiry_date" in metadata:
            expiry_date = metadata["expiry_date"]
        if "status" in metadata:
            status = metadata["status"]
        if "notes" in metadata:
            notes = metadata["notes"]
    review_due_date = expiry_date or ""
    cursor = conn.execute(
        """
        INSERT INTO policy_versions (
            policy_id, version_number, created_at, created_by_user_id,
            file_path, original_filename, file_size_bytes, sha256_hash,
            ratified, ratified_at, ratified_by_user_id,
            status, effective_date, review_due_date, review_frequency_months, expiry_date, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?, ?, ?, ?, ?)
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
            status,
            effective_date,
            review_due_date,
            review_frequency,
            expiry_date,
            notes,
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
    return cursor.lastrowid


def mark_version_ratified(conn, version_id: int, user_id: int | None) -> None:
    ratified_at = datetime.datetime.utcnow().isoformat()
    version_row = conn.execute(
        "SELECT version_number FROM policy_versions WHERE id = ?",
        (version_id,),
    ).fetchone()
    conn.execute(
        "UPDATE policy_versions SET ratified = 1, ratified_at = ?, ratified_by_user_id = ? WHERE id = ?",
        (ratified_at, user_id, version_id),
    )
    conn.commit()
    details = f"version={version_row['version_number']}" if version_row else None
    _log_event(conn, "ratify_version", "policy_version", version_id, details)


def unmark_version_ratified(conn, version_id: int) -> None:
    version_row = conn.execute(
        "SELECT version_number FROM policy_versions WHERE id = ?",
        (version_id,),
    ).fetchone()
    conn.execute(
        "UPDATE policy_versions SET ratified = 0, ratified_at = NULL, ratified_by_user_id = NULL WHERE id = ?",
        (version_id,),
    )
    conn.commit()
    details = f"version={version_row['version_number']}" if version_row else None
    _log_event(conn, "unratify_version", "policy_version", version_id, details)


def set_current_version(conn, policy_id: int, version_id: int) -> None:
    conn.execute(
        "UPDATE policies SET current_version_id = ? WHERE id = ?",
        (version_id, policy_id),
    )
    conn.commit()
    _log_event(conn, "set_current_version", "policy", policy_id, f"version_id={version_id}")


def unset_current_version(conn, policy_id: int) -> None:
    conn.execute("UPDATE policies SET current_version_id = NULL WHERE id = ?", (policy_id,))
    conn.commit()
    _log_event(conn, "unset_current_version", "policy", policy_id, None)


def update_policy_title(conn, policy_id: int, title: str) -> None:
    policy_row = conn.execute(
        "SELECT title, category FROM policies WHERE id = ?",
        (policy_id,),
    ).fetchone()
    if not policy_row:
        raise ValueError("Policy not found")
    current_title = policy_row["title"]
    if current_title == title:
        return
    new_slug = slugify(title)
    policy_root = _policy_root(conn)
    versions = conn.execute(
        """
        SELECT id, version_number, original_filename, file_path
        FROM policy_versions
        WHERE policy_id = ?
        """,
        (policy_id,),
    ).fetchall()
    for version in versions:
        target_path = build_policy_path(
            policy_root,
            policy_row["category"],
            new_slug,
            version["version_number"],
            version["original_filename"],
        )
        target_path.parent.mkdir(parents=True, exist_ok=True)
        current_path = Path(version["file_path"])
        if current_path.exists() and current_path != target_path:
            current_path.rename(target_path)
            _cleanup_empty_dirs(current_path.parent, policy_root)
        conn.execute(
            "UPDATE policy_versions SET file_path = ? WHERE id = ?",
            (str(target_path), version["id"]),
        )
    conn.execute(
        "UPDATE policies SET title = ?, slug = ? WHERE id = ?",
        (title, new_slug, policy_id),
    )
    conn.commit()
    _log_event(
        conn,
        "update_policy_title",
        "policy",
        policy_id,
        f"title: {current_title} -> {title}",
    )


def update_policy_category(conn, policy_id: int, category: str) -> None:
    policy_row = conn.execute(
        "SELECT title, category FROM policies WHERE id = ?",
        (policy_id,),
    ).fetchone()
    if not policy_row:
        raise ValueError("Policy not found")
    current_category = policy_row["category"]
    if current_category == category:
        return
    policy_root = _policy_root(conn)
    slug = slugify(policy_row["title"])
    versions = conn.execute(
        """
        SELECT id, version_number, original_filename, file_path
        FROM policy_versions
        WHERE policy_id = ?
        """,
        (policy_id,),
    ).fetchall()
    for version in versions:
        target_path = build_policy_path(
            policy_root,
            category,
            slug,
            version["version_number"],
            version["original_filename"],
        )
        target_path.parent.mkdir(parents=True, exist_ok=True)
        current_path = Path(version["file_path"])
        if current_path.exists() and current_path != target_path:
            current_path.rename(target_path)
            _cleanup_empty_dirs(current_path.parent, policy_root)
        conn.execute(
            "UPDATE policy_versions SET file_path = ? WHERE id = ?",
            (str(target_path), version["id"]),
        )
    conn.execute(
        "UPDATE policies SET category = ? WHERE id = ?",
        (category, policy_id),
    )
    conn.commit()
    _log_event(
        conn,
        "update_policy_category",
        "policy",
        policy_id,
        f"category: {current_category} -> {category}",
    )


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
