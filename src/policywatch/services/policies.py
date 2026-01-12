"""Policy-specific helper functions."""

from __future__ import annotations

import re
from pathlib import Path


def slugify(title: str) -> str:
    """Convert a policy title into a URL-friendly slug."""

    slug = re.sub(r"[^a-zA-Z0-9]+", "-", title.strip().lower())
    slug = slug.strip("-")
    return slug or "policy"


def next_version_number(existing_versions: list[int]) -> int:
    """Return the next version number for a policy."""

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
    """Build a deterministic filesystem path for a stored policy version."""

    safe_category = slugify(category)
    safe_slug = slugify(policy_slug)
    original_path = Path(original_filename)
    suffix = "".join(original_path.suffixes)
    safe_filename = f"{safe_slug}-v{version_number}{suffix}"
    return policy_root / safe_category / safe_slug / f"v{version_number}" / safe_filename
