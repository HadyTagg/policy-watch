from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

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
    data_dir: Path
    db_path: Path


def resolve_data_dir() -> Path:
    env_override = os.environ.get("POLICYWATCH_DATA_DIR")
    if env_override:
        return Path(env_override).expanduser().resolve()

    program_data = os.environ.get("PROGRAMDATA")
    if program_data:
        return Path(program_data) / "PolicyWatch"

    return Path.cwd() / "policywatch_data"


def get_paths() -> AppPaths:
    data_dir = resolve_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    return AppPaths(data_dir=data_dir, db_path=data_dir / "policywatch.db")
