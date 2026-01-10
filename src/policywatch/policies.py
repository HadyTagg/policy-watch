from __future__ import annotations

import re
from pathlib import Path


def slugify(title: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", title.strip().lower())
    slug = slug.strip("-")
    return slug or "policy"


def next_version_number(existing_versions: list[int]) -> int:
    if not existing_versions:
        return 1
    return max(existing_versions) + 1


def build_policy_path(
    policy_root: Path,
    category: str,
    policy_slug: str,
    version_number: int,
    original_filename: str,
) -> Path:
    safe_category = slugify(category)
    safe_slug = slugify(policy_slug)
    safe_filename = Path(original_filename).name
    return policy_root / safe_category / safe_slug / f"v{version_number}" / safe_filename
