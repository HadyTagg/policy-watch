"""Application entry point for Policy Watch."""

from __future__ import annotations

import datetime
import os
import sys
from pathlib import Path

qt_platform = os.environ.get("POLICYWATCH_QT_PLATFORM")
if qt_platform and "QT_QPA_PLATFORM" not in os.environ:
    os.environ["QT_QPA_PLATFORM"] = qt_platform

from PyQt5 import QtGui, QtWidgets

from policywatch.core import config, security
from policywatch.data import db
from policywatch.services import evacuate_untracked_policy_files, get_user_theme
from policywatch.ui import theme
from policywatch.ui.login import LoginWindow
from policywatch.ui.main import MainWindow


class PolicyWatchApp:
    """Main application wrapper for initialization and authentication."""

    def __init__(self) -> None:
        """Prepare application state, database connections, and styles."""

        self.paths = config.get_paths()
        self.conn = db.connect(self.paths.db_path)
        db.apply_schema(self.conn)
        config.ensure_defaults(self.conn)
        evacuate_untracked_policy_files(self.conn)
        self._app: QtWidgets.QApplication | None = None

    def _apply_base_theme(self, app: QtWidgets.QApplication) -> None:
        """Apply the Policy Watch base theme tokens and stylesheet."""

        theme.apply_base_theme(app)

    def _resolve_icon_path(self) -> Path | None:
        """Resolve the application icon path for local and frozen builds."""

        repo_icon = Path(__file__).resolve().parents[2] / "policywatch.ico"
        candidates = [repo_icon]
        if getattr(sys, "frozen", False):
            candidates.append(Path(sys.executable).resolve().parent / "policywatch.ico")
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None

    def _load_app_icon(self) -> QtGui.QIcon | None:
        """Load the application icon if available."""

        icon_path = self._resolve_icon_path()
        if not icon_path:
            return None
        return QtGui.QIcon(str(icon_path))

    def _ensure_admin(self) -> None:
        """Ensure a default admin user exists on first run."""

        row = self.conn.execute("SELECT COUNT(*) as count FROM users").fetchone()
        if row["count"] > 0:
            return
        password, ok = QtWidgets.QInputDialog.getText(
            None,
            "Create Admin",
            "Set password for default admin user:",
            QtWidgets.QLineEdit.Password,
        )
        if not ok or not password:
            raise SystemExit("Admin password is required.")
        pwd_hash, salt = security.hash_password(password)
        with self.conn:
            self.conn.execute(
                "INSERT INTO users (username, password_hash, salt, role, created_at, disabled) "
                "VALUES (?, ?, ?, ?, ?, 0)",
                ("admin", pwd_hash, salt, "Admin", datetime.datetime.utcnow().isoformat()),
            )

    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate a user against stored credentials."""

        row = self.conn.execute(
            "SELECT password_hash, salt, disabled FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row or row["disabled"]:
            return False
        return security.verify_password(password, row["password_hash"], row["salt"])

    def run(self) -> None:
        """Run the Qt application loop with login gating."""

        app = QtWidgets.QApplication([])
        self._app = app
        self._apply_base_theme(app)
        icon = self._load_app_icon()
        if icon and not icon.isNull():
            app.setWindowIcon(icon)
        self._ensure_admin()
        login = LoginWindow(self.authenticate, icon=icon)
        if login.exec() == QtWidgets.QDialog.Accepted:
            username = login.username_input.text()
            row = self.conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if row:
                theme.apply_theme(get_user_theme(self.conn, row["id"]))
            main = MainWindow(username, self.conn, icon=icon)
            main.resize(800, 600)
            main.show()
            app.exec()


def main() -> None:
    """Launch the Policy Watch application."""

    PolicyWatchApp().run()


if __name__ == "__main__":
    main()
