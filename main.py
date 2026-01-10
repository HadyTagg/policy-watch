import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import os

qt_platform = os.environ.get("POLICYWATCH_QT_PLATFORM")
if qt_platform and "QT_QPA_PLATFORM" not in os.environ:
    os.environ["QT_QPA_PLATFORM"] = qt_platform

from policywatch.app import main


if __name__ == "__main__":
    main()
