"""Thin wrapper to run Policy Watch from the repository root."""

from __future__ import annotations

import sys
from pathlib import Path


# Ensure the local src/ directory is on the import path when running from the repo root.
ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from policywatch.__main__ import main


if __name__ == "__main__":
    main()
