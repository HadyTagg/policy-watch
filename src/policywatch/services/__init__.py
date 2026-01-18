"""Service-layer operations for policies, categories, and exports."""

from __future__ import annotations

import contextvars
import datetime
import hashlib
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from policywatch.core import audit, config, security
from policywatch.services.policies import build_policy_path, next_version_number, slugify
from policywatch.services.traffic import traffic_light_status


def _resolve_london_tz() -> datetime.tzinfo:
    """Resolve the London time zone, falling back gracefully when unavailable."""

    try:
        return ZoneInfo("Europe/London")
    except ZoneInfoNotFoundError:
        return datetime.datetime.now().astimezone().tzinfo or datetime.timezone.utc


LONDON_TZ = _resolve_london_tz()


_AUDIT_ACTOR = contextvars.ContextVar("policywatch_audit_actor", default=None)


def _add_months(source: datetime.date, months: int) -> datetime.date:
    """Add months to a date while keeping the day within month bounds."""

    month = source.month - 1 + months
    year = source.year + month // 12
    month = month % 12 + 1
    day = min(
        source.day,
        [
            31,
            29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28,
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ][month - 1],
    )
    return datetime.date(year, month, day)


def set_audit_actor(actor: str | None) -> None:
    """Set the current audit actor for service-layer logging."""

    _AUDIT_ACTOR.set(actor)


def get_audit_actor() -> str | None:
    """Return the current audit actor for service-layer logging."""

    return _AUDIT_ACTOR.get()


def _resolve_actor() -> str | None:
    """Resolve the current app or OS login name if available."""

    actor = get_audit_actor()
    if actor:
        return actor
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
    conn.commit()


@dataclass(frozen=True)
class PolicyRow:
    """Presentation model for policy listing rows."""

    id: int
    title: str
    category: str
    status: str | None
    ratified: bool
    review_due_date: str | None
    review_frequency_months: int | None
    owner: str | None
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


def _policy_backup_root(conn) -> Path:
    """Return the hidden backup directory for policy files."""

    paths = config.get_paths()
    return paths.data_dir / ".policy_backups"


def _unique_destination(destination: Path) -> Path:
    """Return a unique destination path by appending a counter when needed."""

    if not destination.exists():
        return destination
    stem = destination.stem
    suffix = destination.suffix
    for index in range(1, 1000):
        candidate = destination.with_name(f"{stem}-{index}{suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Unable to find unique destination for {destination}")


def evacuate_untracked_policy_files(conn) -> list[Path]:
    """Move unexpected policy files into the Evacuated Files folder."""

    policy_rows = conn.execute(
        "SELECT id, policy_id, original_filename, file_path FROM policy_versions"
    ).fetchall()
    policy_root = _policy_root(conn)
    backup_root = _policy_backup_root(conn)
    expected_policy_files: set[Path] = set()
    expected_backup_files: set[Path] = set()

    for row in policy_rows:
        stored_path = Path(row["file_path"])
        if stored_path.is_absolute():
            expected_policy_files.add(stored_path.resolve())
        else:
            expected_policy_files.add((policy_root / stored_path).resolve())
        expected_backup_files.add(
            _policy_backup_path(conn, row["policy_id"], row["id"], row["original_filename"]).resolve()
        )

    evac_root = config.get_paths().data_dir / "Evacuated Files"
    evacuated: list[Path] = []

    def _expected_directories(root: Path, expected_files: set[Path]) -> set[Path]:
        expected_dirs = {root.resolve()}
        root_resolved = root.resolve()
        for file_path in expected_files:
            resolved_file = file_path.resolve()
            if root_resolved not in resolved_file.parents:
                continue
            current = resolved_file.parent
            while True:
                expected_dirs.add(current)
                if current == root_resolved:
                    break
                current = current.parent
        return expected_dirs

    def _evacuate_unknown_items(root: Path, expected_files: set[Path], label: str) -> None:
        if not root.exists():
            return
        expected_dirs = _expected_directories(root, expected_files)
        for current_root, _, files in os.walk(root):
            for filename in files:
                file_path = Path(current_root) / filename
                resolved_path = file_path.resolve()
                if resolved_path in expected_files:
                    continue
                relative = file_path.relative_to(root)
                target = evac_root / label / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                destination = _unique_destination(target)
                shutil.move(str(file_path), str(destination))
                evacuated.append(destination)

    def _evacuate_unknown_dirs(root: Path, expected_dirs: set[Path], label: str) -> None:
        if not root.exists():
            return
        for current_root, dirs, _ in os.walk(root):
            for directory in list(dirs):
                dir_path = Path(current_root) / directory
                resolved_dir = dir_path.resolve()
                if resolved_dir in expected_dirs:
                    continue
                relative = dir_path.relative_to(root)
                target = evac_root / label / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                destination = _unique_destination(target)
                shutil.move(str(dir_path), str(destination))
                evacuated.append(destination)
                dirs.remove(directory)

    policy_expected_dirs = _expected_directories(policy_root, expected_policy_files)
    backup_expected_dirs = _expected_directories(backup_root, expected_backup_files)
    _evacuate_unknown_dirs(policy_root, policy_expected_dirs, "policies")
    _evacuate_unknown_dirs(backup_root, backup_expected_dirs, ".policy_backups")
    _evacuate_unknown_items(policy_root, expected_policy_files, "policies")
    _evacuate_unknown_items(backup_root, expected_backup_files, ".policy_backups")

    return evacuated


def _policy_backup_path(
    conn,
    policy_id: int,
    version_id: int,
    original_filename: str,
) -> Path:
    """Build the backup path for a specific policy version."""

    suffix = Path(original_filename).suffix
    return _policy_backup_root(conn) / f"policy_{policy_id}" / f"version_{version_id}{suffix}"


def _ensure_backup_read_only(path: Path, backup_root: Path) -> None:
    """Mark a backup file as read-only when possible."""

    try:
        resolved_path = path.resolve()
        resolved_root = backup_root.resolve()
        if resolved_root not in resolved_path.parents and resolved_path != resolved_root:
            return
        resolved_path.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        return


def _ensure_policy_read_only(path: Path) -> None:
    """Mark a policy version file as read-only when possible."""

    try:
        path.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        return


def _store_policy_backup(
    conn,
    policy_id: int,
    version_id: int,
    original_filename: str,
    source_path: Path,
    expected_hash: str,
) -> Path:
    """Store a read-only backup for a policy version if one does not exist."""

    backup_path = _policy_backup_path(conn, policy_id, version_id, original_filename)
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    if backup_path.exists():
        if _hash_file(backup_path) != expected_hash:
            raise ValueError("Existing backup checksum does not match expected hash.")
        return backup_path
    temp_path = backup_path.with_suffix(backup_path.suffix + ".tmp")
    shutil.copy2(source_path, temp_path)
    backup_hash = _hash_file(temp_path)
    if backup_hash != expected_hash:
        temp_path.unlink(missing_ok=True)
        raise ValueError("Backup checksum did not match expected hash.")
    temp_path.replace(backup_path)
    _ensure_backup_read_only(backup_path, _policy_backup_root(conn))
    return backup_path


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


def _build_policy_rows(conn, rows) -> list[PolicyRow]:
    """Build PolicyRow entries with derived traffic status information."""

    policies: list[PolicyRow] = []
    today = datetime.datetime.now(LONDON_TZ).date()
    amber_months = int(config.get_setting(conn, "amber_months", 2) or 2)

    for row in rows:
        traffic_status = ""
        traffic_reason = ""
        review_due = None
        if row["review_due_date"]:
            review_due = datetime.date.fromisoformat(row["review_due_date"])
        if review_due:
            traffic = traffic_light_status(today, review_due, amber_months)
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
                review_frequency_months=row["review_frequency_months"],
                owner=row["owner"],
                current_version_id=row["current_version_id"],
                current_version_number=row["current_version_number"],
                traffic_status=traffic_status,
                traffic_reason=traffic_reason,
            )
        )
    return policies


def list_policies(conn) -> list[PolicyRow]:
    """Return policies with derived traffic status information."""

    rows = conn.execute(
        """
        SELECT p.id, p.title, p.category,
               CASE WHEN p.current_version_id IS NULL THEN NULL ELSE v.status END AS status,
               CASE WHEN p.current_version_id IS NULL THEN 0 ELSE COALESCE(v.ratified, 0) END AS ratified,
               CASE WHEN p.current_version_id IS NULL THEN NULL ELSE v.review_due_date END AS review_due_date,
               CASE WHEN p.current_version_id IS NULL THEN NULL ELSE v.review_frequency_months END AS review_frequency_months,
               CASE WHEN p.current_version_id IS NULL THEN NULL ELSE v.owner END AS owner,
               p.current_version_id,
               v.version_number AS current_version_number
        FROM policies p
        LEFT JOIN policy_versions v ON v.id = p.current_version_id
        ORDER BY p.created_at DESC
        """
    ).fetchall()

    return _build_policy_rows(conn, rows)


def list_drafts_awaiting_ratification(conn) -> list[PolicyRow]:
    """Return draft policies awaiting ratification, even without a current version."""

    rows = conn.execute(
        """
        SELECT p.id,
               p.title,
               p.category,
               v.status,
               COALESCE(v.ratified, 0) AS ratified,
               v.review_due_date,
               v.review_frequency_months,
               v.owner AS owner,
               v.id AS current_version_id,
               v.version_number AS current_version_number
        FROM policies p
        JOIN policy_versions v
          ON v.id = (
              SELECT pv.id
              FROM policy_versions pv
              WHERE pv.policy_id = p.id
                AND LOWER(pv.status) = 'draft'
                AND COALESCE(pv.ratified, 0) = 0
              ORDER BY pv.version_number DESC, pv.created_at DESC, pv.id DESC
              LIMIT 1
          )
        WHERE LOWER(p.status) NOT IN ('archived', 'withdrawn')
        ORDER BY p.created_at DESC
        """
    ).fetchall()

    return _build_policy_rows(conn, rows)


def count_drafts_awaiting_ratification(conn) -> int:
    """Return the number of draft policies awaiting ratification."""

    row = conn.execute(
        """
        SELECT COUNT(DISTINCT p.id) AS draft_count
        FROM policies p
        JOIN policy_versions v
          ON v.policy_id = p.id
        WHERE LOWER(p.status) NOT IN ('archived', 'withdrawn')
          AND LOWER(v.status) = 'draft'
          AND COALESCE(v.ratified, 0) = 0
        """
    ).fetchone()
    return int(row["draft_count"] or 0)


def list_versions(conn, policy_id: int) -> list[dict]:
    """Return policy version rows for a policy."""

    rows = conn.execute(
        """
        SELECT v.id,
               v.version_number,
               v.created_at,
               v.sha256_hash,
               v.ratified,
               v.status,
               v.review_due_date,
               v.review_frequency_months,
               v.original_filename,
               v.file_path,
               v.file_size_bytes,
               v.owner,
               p.category,
               p.title,
               pr.last_reviewed
        FROM policy_versions v
        JOIN policies p ON p.id = v.policy_id
        LEFT JOIN (
            SELECT version_id, MAX(reviewed_at) AS last_reviewed
            FROM (
                SELECT policy_version_id AS version_id, reviewed_at
                FROM policy_reviews
                UNION ALL
                SELECT pc.replacement_version_id AS version_id, pr.reviewed_at
                FROM policy_review_carryovers pc
                JOIN policy_reviews pr ON pr.policy_version_id = pc.source_version_id
            )
            GROUP BY version_id
        ) pr ON pr.version_id = v.id
        WHERE v.policy_id = ?
        ORDER BY v.version_number DESC
        """,
        (policy_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def list_policy_reviews(conn, policy_version_id: int) -> list[dict]:
    """Return review records for a policy version."""

    rows = conn.execute(
        """
        SELECT pr.id,
               pr.reviewed_at,
               pr.notes,
               pr.no_change,
               v.version_number,
               u.username AS reviewed_by
        FROM policy_reviews pr
        LEFT JOIN policy_versions v ON v.id = pr.policy_version_id
        LEFT JOIN users u ON u.id = pr.reviewed_by_user_id
        WHERE pr.policy_version_id = ?
           OR pr.policy_version_id IN (
                SELECT source_version_id
                FROM policy_review_carryovers
                WHERE replacement_version_id = ?
           )
        ORDER BY pr.reviewed_at DESC, pr.id DESC
        """,
        (policy_version_id, policy_version_id),
    ).fetchall()
    return [dict(row) for row in rows]


def add_policy_review(
    conn,
    policy_version_id: int,
    reviewed_by_user_id: int | None,
    reviewed_at: str,
    notes: str | None,
    no_change: bool = True,
) -> int:
    """Record a policy review that did not create a new version."""

    policy_row = conn.execute(
        """
        SELECT policy_id, version_number, review_frequency_months, review_due_date
        FROM policy_versions
        WHERE id = ?
        """,
        (policy_version_id,),
    ).fetchone()
    if not policy_row:
        raise ValueError("Policy version not found")
    policy_id = policy_row["policy_id"]
    next_review_due = reviewed_at
    review_frequency = policy_row["review_frequency_months"]
    if review_frequency:
        reviewed_date = datetime.date.fromisoformat(reviewed_at)
        next_review_due = _add_months(reviewed_date, int(review_frequency)).isoformat()
    cursor = conn.execute(
        """
        INSERT INTO policy_reviews (
            policy_id, policy_version_id, reviewed_at, reviewed_by_user_id, notes, no_change
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            policy_id,
            policy_version_id,
            reviewed_at,
            reviewed_by_user_id,
            notes,
            1 if no_change else 0,
        ),
    )
    conn.execute(
        "UPDATE policy_versions SET review_due_date = ? WHERE id = ?",
        (next_review_due, policy_version_id),
    )
    current_row = conn.execute(
        "SELECT current_version_id FROM policies WHERE id = ?",
        (policy_id,),
    ).fetchone()
    if current_row and current_row["current_version_id"] == policy_version_id:
        conn.execute(
            "UPDATE policies SET review_due_date = ? WHERE id = ?",
            (next_review_due, policy_id),
        )
    conn.commit()
    details = f"reviewed_at={reviewed_at}"
    details = f"{details} version=v{policy_row['version_number']}"
    details = f"{details} next_review_due={next_review_due}"
    if no_change:
        details = f"{details} no_change=true"
    _log_event(conn, "record_policy_review", "policy", policy_id, details)
    return cursor.lastrowid


def create_policy(
    conn,
    title: str,
    category: str,
    status: str,
    review_due_date: str,
    review_frequency_months: int | None,
    notes: str | None,
    created_by_user_id: int | None,
) -> int:
    """Create a policy and return its database ID."""

    created_at = datetime.datetime.utcnow().isoformat()
    slug = slugify(title)
    effective_date = ""
    review_due_date = review_due_date or ""
    cursor = conn.execute(
        """
        INSERT INTO policies (
            title, slug, category, status, ratified, ratified_at, ratified_by_user_id,
            effective_date, review_due_date, review_frequency_months, notes,
            current_version_id, created_at, created_by_user_id
        ) VALUES (?, ?, ?, ?, 0, NULL, NULL, ?, ?, ?, ?, NULL, ?, ?)
        """,
        (
            title,
            slug,
            category,
            status,
            effective_date,
            review_due_date,
            review_frequency_months,
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
    allow_active_version_id: int | None = None,
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
               review_frequency_months, notes
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
    _ensure_policy_read_only(target_path)

    file_size = target_path.stat().st_size
    created_at = datetime.datetime.utcnow().isoformat()
    effective_date = policy_row["effective_date"]
    review_due_date = policy_row["review_due_date"]
    review_frequency = policy_row["review_frequency_months"]
    status = policy_row["status"]
    notes = policy_row["notes"]
    owner = policy_row["owner"] if "owner" in policy_row.keys() else None
    if metadata:
        if "review_due_date" in metadata:
            review_due_date = metadata["review_due_date"]
        if "status" in metadata:
            status = metadata["status"]
        if "review_frequency_months" in metadata:
            review_frequency = metadata["review_frequency_months"]
        if "owner" in metadata:
            owner = metadata["owner"]
        if "notes" in metadata:
            notes = metadata["notes"]
    if not review_due_date:
        review_due_date = ""
    normalized_status = _normalize_version_status(status)
    status = normalized_status
    if normalized_status == "Active":
        raise ValueError("You must ratify before activating.")
    ratified_flag = 0
    ratified_at = None
    if normalized_status == "Ratified":
        ratified_flag = 1
        ratified_at = datetime.datetime.utcnow().isoformat()
    if (status or "").lower() == "active":
        active_row = conn.execute(
            """
            SELECT id
            FROM policy_versions
            WHERE policy_id = ?
              AND LOWER(status) = 'active'
            LIMIT 1
            """,
            (policy_id,),
        ).fetchone()
        if active_row and active_row["id"] != allow_active_version_id:
            raise ValueError("Only one active version is allowed for a policy.")
    cursor = conn.execute(
        """
        INSERT INTO policy_versions (
            policy_id, version_number, created_at, created_by_user_id,
            file_path, original_filename, file_size_bytes, sha256_hash,
            ratified, ratified_at, ratified_by_user_id,
            status, effective_date, review_due_date, review_frequency_months, notes, owner
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?)
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
            ratified_flag,
            ratified_at,
            status,
            effective_date,
            review_due_date,
            review_frequency,
            notes,
            owner,
        ),
    )
    version_id = cursor.lastrowid
    try:
        _store_policy_backup(
            conn,
            policy_id,
            version_id,
            original_path.name,
            target_path,
            sha256.hexdigest(),
        )
    except Exception:
        conn.rollback()
        target_path.unlink(missing_ok=True)
        raise
    conn.commit()
    _log_event(
        conn,
        "add_policy_version",
        "policy_version",
        version_id,
        f"policy_id={policy_id} version={version_number}",
    )
    return version_id


def mark_version_ratified(conn, version_id: int, user_id: int | None) -> None:
    """Mark a policy version as ratified and log the event."""
    set_version_ratified(conn, version_id, True, user_id=user_id)


def unmark_version_ratified(conn, version_id: int) -> None:
    """Clear the ratified status for a policy version."""
    set_version_ratified(conn, version_id, False)


def set_current_version(conn, policy_id: int, version_id: int) -> None:
    """Set the current version for a policy and log the change."""
    set_version_current(conn, policy_id, version_id, True)


def unset_current_version(conn, policy_id: int) -> None:
    """Clear the current version for a policy."""
    if not policy_id:
        return
    policy_row = conn.execute(
        "SELECT current_version_id FROM policies WHERE id = ?",
        (policy_id,),
    ).fetchone()
    current_version_id = policy_row["current_version_id"] if policy_row else None
    if current_version_id:
        set_version_current(conn, policy_id, current_version_id, False)


def _normalize_version_status(status: str | None) -> str:
    """Return a canonical status label for comparisons."""

    if not status:
        return "Draft"
    normalized = status.strip().lower()
    mapping = {
        "draft": "Draft",
        "ratified": "Ratified",
        "active": "Active",
        "withdrawn": "Withdrawn",
        "archived": "Archived",
        "missing": "Missing",
    }
    return mapping.get(normalized, status)


def _load_version_row(conn, version_id: int):
    """Return a policy version row or raise if missing."""

    row = conn.execute(
        """
        SELECT id, policy_id, version_number, status, ratified
        FROM policy_versions
        WHERE id = ?
        """,
        (version_id,),
    ).fetchone()
    if not row:
        raise ValueError("Version not found")
    return row


def set_version_ratified(
    conn,
    version_id: int,
    is_ratified: bool,
    *,
    user_id: int | None = None,
) -> None:
    """Set the ratified flag for a policy version while enforcing lifecycle rules."""

    version_row = _load_version_row(conn, version_id)
    current_status = _normalize_version_status(version_row["status"])
    if current_status == "Archived":
        raise ValueError("Archived versions are locked and cannot be modified.")
    if current_status == "Active" and not is_ratified:
        raise ValueError("You cannot unratify an Active version.")
    if current_status == "Ratified" and not is_ratified:
        raise ValueError("Ratified versions cannot be unratified.")
    if is_ratified:
        ratified_at = datetime.datetime.utcnow().isoformat()
        conn.execute(
            """
            UPDATE policy_versions
            SET ratified = 1, ratified_at = ?, ratified_by_user_id = ?
            WHERE id = ?
            """,
            (ratified_at, user_id, version_id),
        )
        action = "ratify_version"
    else:
        conn.execute(
            """
            UPDATE policy_versions
            SET ratified = 0, ratified_at = NULL, ratified_by_user_id = NULL
            WHERE id = ?
            """,
            (version_id,),
        )
        action = "unratify_version"
    conn.commit()
    details = f"version={version_row['version_number']}" if version_row else None
    _log_event(conn, action, "policy_version", version_id, details)


def set_version_current(conn, policy_id: int, version_id: int, is_current: bool) -> None:
    """Set or unset a policy version as current with lifecycle validation."""

    version_row = _load_version_row(conn, version_id)
    current_status = _normalize_version_status(version_row["status"])
    if current_status == "Archived":
        raise ValueError("Archived versions are locked and cannot be modified.")
    if current_status == "Missing":
        raise ValueError("Missing versions are locked and cannot be modified.")
    if version_row["policy_id"] != policy_id:
        raise ValueError("Version does not belong to the selected policy.")
    policy_row = conn.execute(
        "SELECT current_version_id FROM policies WHERE id = ?",
        (policy_id,),
    ).fetchone()
    current_version_id = policy_row["current_version_id"] if policy_row else None
    if not is_current:
        if current_version_id != version_id:
            return
        conn.execute("UPDATE policies SET current_version_id = NULL WHERE id = ?", (policy_id,))
        if current_status == "Active":
            conn.execute(
                "UPDATE policy_versions SET status = ? WHERE id = ?",
                ("Withdrawn", version_id),
            )
        conn.commit()
        _log_event(
            conn,
            "unset_current_version",
            "policy",
            policy_id,
            f"version_id={version_id}",
        )
        return
    if current_status == "Draft":
        raise ValueError("Draft versions cannot be set as Current.")
    if current_status in {"Withdrawn", "Archived"}:
        raise ValueError("Withdrawn/Archived versions cannot be set as Current.")
    if not version_row["ratified"]:
        raise ValueError("You must ratify before activating.")
    if current_version_id and current_version_id != version_id:
        previous_status_row = conn.execute(
            "SELECT status FROM policy_versions WHERE id = ?",
            (current_version_id,),
        ).fetchone()
        if previous_status_row:
            previous_status = _normalize_version_status(previous_status_row["status"])
            if previous_status != "Archived":
                conn.execute(
                    "UPDATE policy_versions SET status = ? WHERE id = ?",
                    ("Withdrawn", current_version_id),
                )
    conn.execute(
        "UPDATE policy_versions SET status = ? WHERE id = ?",
        ("Active", version_id),
    )
    conn.execute(
        "UPDATE policies SET current_version_id = ? WHERE id = ?",
        (version_id, policy_id),
    )
    conn.commit()
    _log_event(
        conn,
        "set_current_version",
        "policy",
        policy_id,
        f"version_id={version_id}",
    )


def set_version_status(conn, version_id: int, new_status: str) -> None:
    """Update a policy version status using lifecycle rules."""

    version_row = _load_version_row(conn, version_id)
    current_status = _normalize_version_status(version_row["status"])
    requested_status = _normalize_version_status(new_status)
    if current_status == "Archived":
        raise ValueError("Archived versions are locked and cannot be modified.")
    if current_status == "Missing":
        raise ValueError("Missing versions are locked and cannot be modified.")
    if requested_status == current_status:
        return
    allowed_transitions = {
        ("Draft", "Ratified"),
        ("Ratified", "Active"),
        ("Active", "Withdrawn"),
        ("Withdrawn", "Archived"),
    }
    if (current_status, requested_status) not in allowed_transitions:
        if current_status == "Draft" and requested_status == "Active":
            raise ValueError("You must ratify before activating.")
        if current_status == "Active" and requested_status == "Draft":
            raise ValueError("Active versions cannot be moved back to Draft.")
        if current_status == "Active" and requested_status == "Ratified":
            raise ValueError("Active versions cannot be moved back to Ratified.")
        raise ValueError("Invalid status transition.")
    if requested_status == "Ratified":
        ratified_at = datetime.datetime.utcnow().isoformat()
        conn.execute(
            """
            UPDATE policy_versions
            SET status = ?, ratified = 1, ratified_at = ?, ratified_by_user_id = NULL
            WHERE id = ?
            """,
            ("Ratified", ratified_at, version_id),
        )
    elif requested_status == "Active":
        if not version_row["ratified"]:
            raise ValueError("You must ratify before activating.")
        policy_row = conn.execute(
            "SELECT current_version_id FROM policies WHERE id = ?",
            (version_row["policy_id"],),
        ).fetchone()
        current_version_id = policy_row["current_version_id"] if policy_row else None
        if current_version_id and current_version_id != version_id:
            previous_status_row = conn.execute(
                "SELECT status FROM policy_versions WHERE id = ?",
                (current_version_id,),
            ).fetchone()
            if previous_status_row:
                previous_status = _normalize_version_status(previous_status_row["status"])
                if previous_status != "Archived":
                    conn.execute(
                        "UPDATE policy_versions SET status = ? WHERE id = ?",
                        ("Withdrawn", current_version_id),
                    )
        conn.execute(
            "UPDATE policies SET current_version_id = ? WHERE id = ?",
            (version_id, version_row["policy_id"]),
        )
        conn.execute(
            "UPDATE policy_versions SET status = ? WHERE id = ?",
            ("Active", version_id),
        )
    elif requested_status == "Withdrawn":
        conn.execute(
            "UPDATE policy_versions SET status = ? WHERE id = ?",
            ("Withdrawn", version_id),
        )
        conn.execute(
            "UPDATE policies SET current_version_id = NULL WHERE id = ? AND current_version_id = ?",
            (version_row["policy_id"], version_id),
        )
    elif requested_status == "Archived":
        conn.execute(
            "UPDATE policy_versions SET status = ? WHERE id = ?",
            ("Archived", version_id),
        )
        conn.execute(
            "UPDATE policies SET current_version_id = NULL WHERE id = ? AND current_version_id = ?",
            (version_row["policy_id"], version_id),
        )
    conn.commit()
    details = f"{current_status} -> {requested_status}"
    _log_event(conn, "policy_version_status_updated", "policy_version", version_id, details)


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


def file_sha256(path: Path) -> str:
    """Return a SHA-256 hash for a file path."""

    return _hash_file(path)


def format_replacement_note(
    replaced_version_number: int,
    replacement_version_number: int | None,
    timestamp: str,
    reason: str,
) -> str:
    """Format a consistent replacement note for policy versions."""

    replacement_label = "unknown"
    if replacement_version_number is not None:
        replacement_label = f"v{replacement_version_number}"
    return (
        "Replacement accepted: replaced v"
        f"{replaced_version_number} with {replacement_label} on {timestamp} "
        f"(reason: {reason})."
    )


def policy_backup_available(conn, version_id: int) -> bool:
    """Return True when a backup exists for the policy version."""

    row = conn.execute(
        "SELECT policy_id, original_filename, sha256_hash FROM policy_versions WHERE id = ?",
        (version_id,),
    ).fetchone()
    if not row:
        return False
    backup_path = _policy_backup_path(conn, row["policy_id"], version_id, row["original_filename"])
    return backup_path.exists()


def restore_policy_from_backup(conn, version_id: int, reason: str) -> None:
    """Restore a policy file from its backup after verifying the checksum."""

    row = conn.execute(
        """
        SELECT policy_id, file_path, sha256_hash, version_number, original_filename
        FROM policy_versions
        WHERE id = ?
        """,
        (version_id,),
    ).fetchone()
    if not row:
        raise ValueError("Version not found")
    backup_path = _policy_backup_path(conn, row["policy_id"], version_id, row["original_filename"])
    if not backup_path.exists():
        raise ValueError("Backup file not found.")
    backup_hash = _hash_file(backup_path)
    if backup_hash != row["sha256_hash"]:
        raise ValueError("Backup checksum does not match the stored hash.")
    target_path = Path(row["file_path"])
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(backup_path, target_path)
    _ensure_policy_read_only(target_path)
    restored_hash = _hash_file(target_path)
    if restored_hash != row["sha256_hash"]:
        raise ValueError("Restored file failed checksum verification.")
    file_size = target_path.stat().st_size
    conn.execute(
        "UPDATE policy_versions SET file_size_bytes = ? WHERE id = ?",
        (file_size, version_id),
    )
    _log_event(
        conn,
        "policy_backup_restored",
        "policy_version",
        version_id,
        f"reason={reason} path={target_path}",
    )
    conn.commit()


def scan_policy_file_integrity(conn) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Repair stored paths and detect missing or altered policy files."""

    rows = conn.execute(
        """
        SELECT v.id AS version_id,
               v.file_path,
               v.sha256_hash,
               v.status,
               v.notes,
               v.replacement_accepted,
               v.original_filename,
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
        if row["status"] == "Missing" and row["replacement_accepted"]:
            continue
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
        """
        SELECT policy_id, file_path, sha256_hash, version_number, original_filename
        FROM policy_versions
        WHERE id = ?
        """,
        (version_id,),
    ).fetchone()
    if not row:
        raise ValueError("Version not found")
    target_path = Path(row["file_path"])
    if source_path.resolve() == target_path.resolve():
        raise ValueError("Selected file matches the stored policy file.")
    source_hash = _hash_file(source_path)
    if source_hash != row["sha256_hash"]:
        raise ValueError("Selected file does not match the stored checksum.")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, target_path)
    _ensure_policy_read_only(target_path)
    new_hash = _hash_file(target_path)
    file_size = target_path.stat().st_size
    _store_policy_backup(
        conn,
        row["policy_id"],
        version_id,
        row["original_filename"],
        target_path,
        new_hash,
    )
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
        """
        SELECT policy_id, file_path, sha256_hash, version_number, original_filename
        FROM policy_versions
        WHERE id = ?
        """,
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
    _ensure_policy_read_only(target_path)
    file_size = target_path.stat().st_size
    _store_policy_backup(
        conn,
        row["policy_id"],
        version_id,
        row["original_filename"],
        target_path,
        row["sha256_hash"],
    )
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


def update_policy_version_notes(conn, version_id: int, notes: str) -> None:
    """Update notes for a policy version and log the change."""

    conn.execute(
        "UPDATE policy_versions SET notes = ? WHERE id = ?",
        (notes, version_id),
    )
    _log_event(
        conn,
        "policy_version_notes_updated",
        "policy_version",
        version_id,
        "replacement_notes_applied",
    )
    conn.commit()


def mark_policy_version_missing(
    conn,
    version_id: int,
    details: str,
    replacement_version_number: int | None = None,
    replacement_note: str | None = None,
    replacement_version_id: int | None = None,
) -> None:
    """Record that a policy version file is missing or replaced."""

    row = conn.execute(
        """
        SELECT p.current_version_id,
               v.policy_id,
               v.version_number,
               v.status,
               v.notes,
               v.owner
        FROM policy_versions v
        JOIN policies p ON p.id = v.policy_id
        WHERE v.id = ?
        """,
        (version_id,),
    ).fetchone()
    if not row:
        raise ValueError("Version not found")
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    note_line = replacement_note or format_replacement_note(
        row["version_number"],
        replacement_version_number,
        timestamp,
        "policy integrity mismatch",
    )
    existing_notes = (row["notes"] or "").rstrip()
    updated_notes = f"{existing_notes}\n{note_line}".strip()
    conn.execute(
        "UPDATE policy_versions SET status = ?, notes = ?, replacement_accepted = 1 WHERE id = ?",
        ("Missing", updated_notes, version_id),
    )
    _log_event(
        conn,
        "policy_version_notes_updated",
        "policy_version",
        version_id,
        "replacement_notes_applied",
    )
    if replacement_version_id is not None:
        new_version_number = replacement_version_number
        if new_version_number is None:
            replacement_row = conn.execute(
                "SELECT version_number FROM policy_versions WHERE id = ?",
                (replacement_version_id,),
            ).fetchone()
            if replacement_row:
                new_version_number = replacement_row["version_number"]
        existing_carryover = conn.execute(
            """
            SELECT 1
            FROM policy_review_carryovers
            WHERE source_version_id = ? AND replacement_version_id = ?
            """,
            (version_id, replacement_version_id),
        ).fetchone()
        if not existing_carryover:
            conn.execute(
                """
                INSERT INTO policy_review_carryovers (
                    source_version_id, replacement_version_id, carried_at
                ) VALUES (?, ?, ?)
                """,
                (version_id, replacement_version_id, datetime.datetime.utcnow().isoformat()),
            )
            _log_event(
                conn,
                "policy_review_carryover_added",
                "policy_version",
                replacement_version_id,
                f"carried_reviews_from_version={row['version_number']}",
            )
    if row["current_version_id"] == version_id:
        if replacement_version_id is not None:
            conn.execute(
                "UPDATE policy_versions SET owner = ? WHERE id = ?",
                (row["owner"], replacement_version_id),
            )
            _log_event(
                conn,
                "policy_owner_copied",
                "policy_version",
                replacement_version_id,
                f"owner={row['owner'] or 'Unassigned'} copied_from_version={row['version_number']}",
            )
            conn.execute(
                "UPDATE policies SET current_version_id = ? WHERE id = ?",
                (replacement_version_id, row["policy_id"]),
            )
            _log_event(
                conn,
                "current_version_replaced",
                "policy",
                row["policy_id"],
                (
                    "current_status_copied"
                    f" status={row['status']}"
                    f" from_version={row['version_number']}"
                    f" to_version={new_version_number}"
                ),
            )
        else:
            conn.execute(
                "UPDATE policies SET current_version_id = NULL WHERE id = ?",
                (row["policy_id"],),
            )
            _log_event(
                conn,
                "current_version_cleared",
                "policy",
                row["policy_id"],
                f"previous_version_id={version_id}",
            )
    _log_event(conn, "policy_version_marked_missing", "policy_version", version_id, details)
    conn.commit()


def list_categories(conn) -> list[str]:
    """Return available category names."""

    rows = conn.execute("SELECT name FROM categories ORDER BY name").fetchall()
    return [row["name"] for row in rows]


def list_users(conn, include_disabled: bool = False) -> list[str]:
    """Return usernames for existing users."""

    query = "SELECT username FROM users"
    params: tuple = ()
    if not include_disabled:
        query += " WHERE disabled = 0"
    query += " ORDER BY username"
    rows = conn.execute(query, params).fetchall()
    return [row["username"] for row in rows]


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


def update_policy_version_owner(conn, version_id: int, owner: str | None) -> None:
    """Update the policy version owner and log the change."""

    row = conn.execute(
        "SELECT owner, version_number FROM policy_versions WHERE id = ?",
        (version_id,),
    ).fetchone()
    if not row:
        return
    current_owner = row["owner"] or ""
    new_owner = owner or ""
    if current_owner == new_owner:
        return
    conn.execute(
        "UPDATE policy_versions SET owner = ? WHERE id = ?",
        (owner, version_id),
    )
    conn.commit()
    previous_label = current_owner or "Unassigned"
    new_label = new_owner or "Unassigned"
    details = f"version={row['version_number']} owner={new_label} previous_owner={previous_label}"
    _log_event(
        conn,
        "update_policy_owner",
        "policy_version",
        version_id,
        details,
    )


def create_user(
    conn,
    username: str,
    password: str,
    role: str,
    created_by_user_id: int | None,
) -> int:
    """Create a user account and log the event."""

    created_at = datetime.datetime.utcnow().isoformat()
    pwd_hash, salt = security.hash_password(password)
    created_by_username = None
    if created_by_user_id is not None:
        row = conn.execute(
            "SELECT username FROM users WHERE id = ?",
            (created_by_user_id,),
        ).fetchone()
        if row:
            created_by_username = row["username"]
    cursor = conn.execute(
        """
        INSERT INTO users (username, password_hash, salt, role, created_at, disabled)
        VALUES (?, ?, ?, ?, ?, 0)
        """,
        (username, pwd_hash, salt, role, created_at),
    )
    conn.commit()
    _log_event(
        conn,
        "create_user",
        "user",
        cursor.lastrowid,
        f"username={username} role={role} created_by={created_by_username}",
    )
    return cursor.lastrowid


def update_user_password(conn, user_id: int, password: str) -> None:
    """Update a user password and log the event."""

    pwd_hash, salt = security.hash_password(password)
    conn.execute(
        "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
        (pwd_hash, salt, user_id),
    )
    conn.commit()
    _log_event(conn, "update_user_password", "user", user_id, None)


def get_user_theme(conn, user_id: int) -> str:
    """Return the stored theme for a user, defaulting to light."""

    row = conn.execute(
        "SELECT theme FROM user_settings WHERE user_id = ?",
        (str(user_id),),
    ).fetchone()
    if row:
        return row["theme"]
    theme_value = "light"
    updated_at = datetime.datetime.utcnow().isoformat()
    conn.execute(
        "INSERT OR IGNORE INTO user_settings (user_id, theme, updated_at) VALUES (?, ?, ?)",
        (str(user_id), theme_value, updated_at),
    )
    conn.commit()
    return theme_value


def set_user_theme(conn, user_id: int, theme_value: str) -> None:
    """Persist the user's theme preference."""

    if theme_value not in {"light", "dark"}:
        raise ValueError("theme must be 'light' or 'dark'")
    updated_at = datetime.datetime.utcnow().isoformat()
    conn.execute(
        """
        INSERT INTO user_settings (user_id, theme, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id)
        DO UPDATE SET theme = excluded.theme, updated_at = excluded.updated_at
        """,
        (str(user_id), theme_value, updated_at),
    )
    conn.commit()


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
