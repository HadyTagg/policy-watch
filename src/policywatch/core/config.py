"""Configuration helpers and defaults for Policy Watch."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Default configuration values stored in the settings table.
DEFAULT_SETTINGS = {
    "policy_root": "",
    "amber_months": 2,
    "overdue_grace_days": 0,
    "max_attachment_mb": 0,
    "access_db_path": "N:\\",
    "access_query": "",
    "access_table": "",
    "access_mode": "table",
    "access_fields": json.dumps({}),
}


@dataclass(frozen=True)
class AppPaths:
    """Resolved filesystem locations used by the application."""

    data_dir: Path
    db_path: Path


def resolve_data_dir() -> Path:
    """Resolve the data directory, honoring environment overrides and frozen builds."""

    env_override = os.environ.get("POLICYWATCH_DATA_DIR")
    if env_override:
        return Path(env_override).expanduser().resolve()

    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent

    return Path.cwd()


def get_paths() -> AppPaths:
    """Create and return the canonical data directory and database path."""

    data_dir = resolve_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    return AppPaths(data_dir=data_dir, db_path=data_dir / "policywatch.db")


def ensure_defaults(conn) -> None:
    """Seed the config table with defaults if values are missing."""

    for key, value in DEFAULT_SETTINGS.items():
        conn.execute(
            "INSERT INTO config (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO NOTHING",
            (key, json.dumps(value) if isinstance(value, (dict, list)) else str(value)),
        )
    conn.commit()


def get_setting(conn, key: str, default: Any | None = None) -> str:
    """Fetch a config value, returning a string (or stringified default)."""

    row = conn.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
    if row:
        return row["value"]
    return str(default) if default is not None else ""


def set_setting(conn, key: str, value: Any) -> None:
    """Upsert a config value, serializing complex values to JSON."""

    stored = json.dumps(value) if isinstance(value, (dict, list)) else str(value)
    conn.execute(
        "INSERT INTO config (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, stored),
    )
    conn.commit()
