"""Service-layer operations for policies, categories, and exports."""

from __future__ import annotations

import datetime
import hashlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from policywatch.core import audit, config
from policywatch.services.policies import build_policy_path, next_version_number, slugify
from policywatch.services.traffic import traffic_light_status


def _resolve_london_tz() -> datetime.tzinfo:
    """Resolve the London time zone, falling back gracefully when unavailable."""

    try:
        return ZoneInfo("Europe/London")
    except ZoneInfoNotFoundError:
        return datetime.datetime.now().astimezone().tzinfo or datetime.timezone.utc


LONDON_TZ = _resolve_london_tz()


def _resolve_actor() -> str | None:
    """Resolve the current OS login name if available."""

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
    """Write an audit event for service-layer actions."""

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
    """Presentation model for policy listing rows."""

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
    """Return the policy root directory, using config defaults when missing."""

    root = config.get_setting(conn, "policy_root", "")
    if root:
        return Path(root)
    paths = config.get_paths()
    return paths.data_dir / "policies"


def _cleanup_empty_dirs(path: Path, stop_at: Path) -> None:
    """Remove empty directories up to the configured root."""

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
    """Return policies with derived traffic status information."""

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
    """Return policy version rows for a policy."""

    rows = conn.execute(
        """
        SELECT id, version_number, created_at, sha256_hash, ratified,
               status, original_filename, file_path, file_size_bytes
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
    """Create a policy and return its database ID."""

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
    """Store a new policy version and return its database ID."""

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
    """Mark a policy version as ratified and log the event."""

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
    """Clear the ratified status for a policy version."""

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
    """Set the current version for a policy and log the change."""

    version_number = None
    version_row = conn.execute(
        "SELECT version_number FROM policy_versions WHERE id = ?",
        (version_id,),
    ).fetchone()
    if version_row:
        version_number = version_row["version_number"]
    conn.execute(
        "UPDATE policies SET current_version_id = ? WHERE id = ?",
        (version_id, policy_id),
    )
    conn.commit()
    details = f"version_id={version_id}"
    if version_number is not None:
        details = f"{details} (v{version_number})"
    _log_event(conn, "set_current_version", "policy", policy_id, details)


def unset_current_version(conn, policy_id: int) -> None:
    """Clear the current version for a policy."""

    policy_row = conn.execute(
        "SELECT current_version_id FROM policies WHERE id = ?",
        (policy_id,),
    ).fetchone()
    current_version_id = policy_row["current_version_id"] if policy_row else None
    version_number = None
    if current_version_id:
        version_row = conn.execute(
            "SELECT version_number FROM policy_versions WHERE id = ?",
            (current_version_id,),
        ).fetchone()
        if version_row:
            version_number = version_row["version_number"]
    conn.execute("UPDATE policies SET current_version_id = NULL WHERE id = ?", (policy_id,))
    conn.commit()
    details = None
    if current_version_id:
        if version_number is not None:
            details = f"version_id={current_version_id} (v{version_number})"
        else:
            details = f"version_id={current_version_id}"
    _log_event(conn, "unset_current_version", "policy", policy_id, details)


def update_policy_title(conn, policy_id: int, title: str) -> None:
    """Rename a policy and move stored files to the new slug path."""

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
    """Move policy versions to a new category folder."""

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
    """Return the stored file path for a policy version."""

    row = conn.execute("SELECT file_path FROM policy_versions WHERE id = ?", (version_id,)).fetchone()
    if not row:
        raise ValueError("Version not found")
    return row["file_path"]


def resolve_version_file_path(conn, version_id: int, stored_path: str) -> Path | None:
    """Resolve a version file path, repairing stale locations if needed."""

    path = Path(stored_path)
    if path.exists():
        return path

    policy_root = _policy_root(conn)
    if path.is_absolute():
        parts = [part.lower() for part in path.parts]
        if "policies" in parts:
            index = parts.index("policies")
            relative = Path(*path.parts[index + 1 :])
            candidate = policy_root / relative
            if candidate.exists():
                conn.execute(
                    "UPDATE policy_versions SET file_path = ? WHERE id = ?",
                    (str(candidate), version_id),
                )
                conn.commit()
                return candidate
        return None

    candidate = policy_root / path
    if candidate.exists():
        conn.execute(
            "UPDATE policy_versions SET file_path = ? WHERE id = ?",
            (str(candidate), version_id),
        )
        conn.commit()
        return candidate
    return None


def _hash_file(path: Path) -> str:
    """Return the SHA-256 hash for a file on disk."""

    sha256 = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(8192)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def scan_policy_file_integrity(conn) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Repair stored paths and detect missing or altered policy files."""

    rows = conn.execute(
        """
        SELECT v.id AS version_id,
               v.file_path,
               v.sha256_hash,
               v.version_number,
               p.id AS policy_id,
               p.title AS policy_title
        FROM policy_versions v
        JOIN policies p ON p.id = v.policy_id
        ORDER BY p.title, v.version_number
        """
    ).fetchall()
    missing: list[dict[str, str]] = []
    altered: list[dict[str, str]] = []
    for row in rows:
        resolved = resolve_version_file_path(conn, row["version_id"], row["file_path"])
        if not resolved:
            details = (
                f"title={row['policy_title']} "
                f"version={row['version_number']} "
                f"path={row['file_path']}"
            )
            _log_event(conn, "policy_file_missing", "policy_version", row["version_id"], details)
            missing.append(
                {
                    "version_id": str(row["version_id"]),
                    "title": row["policy_title"],
                    "version": str(row["version_number"]),
                    "path": row["file_path"],
                    "expected_hash": row["sha256_hash"],
                }
            )
            continue
        current_hash = _hash_file(resolved)
        if current_hash != row["sha256_hash"]:
            details = (
                f"title={row['policy_title']} "
                f"version={row['version_number']} "
                f"path={resolved} "
                f"expected_hash={row['sha256_hash']} "
                f"actual_hash={current_hash}"
            )
            _log_event(conn, "policy_file_integrity_mismatch", "policy_version", row["version_id"], details)
            altered.append(
                {
                    "version_id": str(row["version_id"]),
                    "policy_id": str(row["policy_id"]),
                    "title": row["policy_title"],
                    "version": str(row["version_number"]),
                    "path": str(resolved),
                    "expected_hash": row["sha256_hash"],
                    "actual_hash": current_hash,
                }
            )
    if missing or altered:
        conn.commit()
    return missing, altered


def restore_policy_version_file(conn, version_id: int, source_path: Path) -> None:
    """Replace a policy version file with a selected source file and update metadata."""

    row = conn.execute(
        "SELECT file_path, sha256_hash, version_number FROM policy_versions WHERE id = ?",
        (version_id,),
    ).fetchone()
    if not row:
        raise ValueError("Version not found")
    target_path = Path(row["file_path"])
    if source_path.resolve() == target_path.resolve():
        raise ValueError("Selected file matches the stored policy file.")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, target_path)
    new_hash = _hash_file(target_path)
    file_size = target_path.stat().st_size
    conn.execute(
        "UPDATE policy_versions SET sha256_hash = ?, file_size_bytes = ? WHERE id = ?",
        (new_hash, file_size, version_id),
    )
    _log_event(
        conn,
        "policy_file_integrity_restored",
        "policy_version",
        version_id,
        f"version={row['version_number']} path={target_path} new_hash={new_hash}",
    )
    conn.commit()


def restore_missing_policy_file(conn, version_id: int, source_path: Path) -> None:
    """Restore a missing policy file if it matches the stored checksum."""

    row = conn.execute(
        "SELECT file_path, sha256_hash, version_number FROM policy_versions WHERE id = ?",
        (version_id,),
    ).fetchone()
    if not row:
        raise ValueError("Version not found")
    source_hash = _hash_file(source_path)
    if source_hash != row["sha256_hash"]:
        raise ValueError("Selected file does not match the stored checksum.")
    target_path = Path(row["file_path"])
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, target_path)
    file_size = target_path.stat().st_size
    conn.execute(
        "UPDATE policy_versions SET file_size_bytes = ? WHERE id = ?",
        (file_size, version_id),
    )
    _log_event(
        conn,
        "policy_file_missing_restored",
        "policy_version",
        version_id,
        f"version={row['version_number']} path={target_path}",
    )
    conn.commit()


def mark_policy_version_missing(
    conn,
    version_id: int,
    details: str,
    replacement_version_number: int | None = None,
) -> None:
    """Record that a policy version file is missing or replaced."""

    row = conn.execute(
        """
        SELECT p.current_version_id,
               v.policy_id,
               v.version_number,
               v.notes
        FROM policy_versions v
        JOIN policies p ON p.id = v.policy_id
        WHERE v.id = ?
        """,
        (version_id,),
    ).fetchone()
    if not row:
        raise ValueError("Version not found")
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    replacement_text = "Replacement version unknown"
    if replacement_version_number is not None:
        replacement_text = f"Replacement version v{replacement_version_number}"
    note_line = (
        f"{replacement_text} accepted on {timestamp} after integrity mismatch."
    )
    existing_notes = (row["notes"] or "").rstrip()
    updated_notes = f"{existing_notes}\n{note_line}".strip()
    conn.execute(
        "UPDATE policy_versions SET status = ?, notes = ? WHERE id = ?",
        ("Withdrawn", updated_notes, version_id),
    )
    if row["current_version_id"] == version_id:
        conn.execute(
            "UPDATE policies SET current_version_id = NULL WHERE id = ?",
            (row["policy_id"],),
        )
    _log_event(conn, "policy_version_marked_missing", "policy_version", version_id, details)
    conn.commit()


def list_categories(conn) -> list[str]:
    """Return available category names."""

    rows = conn.execute("SELECT name FROM categories ORDER BY name").fetchall()
    return [row["name"] for row in rows]


def create_category(conn, name: str) -> None:
    """Create a category record and log the event."""

    created_at = datetime.datetime.utcnow().isoformat()
    cursor = conn.execute("INSERT INTO categories (name, created_at) VALUES (?, ?)", (name, created_at))
    conn.commit()
    _log_event(conn, "create_category", "category", cursor.lastrowid, f"name={name}")


def delete_category(conn, category_id: int) -> None:
    """Delete a category record and log the event."""

    conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
    conn.commit()
    _log_event(conn, "delete_category", "category", category_id, None)


def export_backup(conn, destination: Path, include_files: bool) -> None:
    """Export the database and optionally policy files to a zip archive."""

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
