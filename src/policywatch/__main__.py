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
        self._app: QtWidgets.QApplication | None = None
        self._dark_stylesheet = """
            QWidget {
                background-color: #2b2b2b;
                color: #f0f0f0;
            }
            QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox, QDateEdit, QComboBox {
                background-color: #3a3a3a;
                border: 1px solid #555;
                padding: 4px;
                selection-background-color: #5a5a5a;
            }
            QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus,
            QDoubleSpinBox:focus, QDateEdit:focus, QComboBox:focus {
                border: 1px solid #6aa9ff;
            }
            QPushButton {
                background-color: #3d3d3d;
                border: 1px solid #555;
                padding: 6px 10px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
            QPushButton:pressed {
                background-color: #2f2f2f;
            }
            QGroupBox {
                border: 1px solid #555;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
            }
            QHeaderView::section {
                background-color: #3a3a3a;
                padding: 4px;
                border: 1px solid #555;
            }
            QTableWidget, QTableView {
                gridline-color: #555;
                selection-background-color: #4a4a4a;
                selection-color: #ffffff;
            }
            QTabBar::tab {
                background: #3a3a3a;
                padding: 6px 12px;
                border: 1px solid #555;
            }
            QTabBar::tab:selected {
                background: #2b2b2b;
                border-bottom-color: #2b2b2b;
            }
            QMenuBar {
                background-color: #2b2b2b;
            }
            QMenuBar::item:selected {
                background-color: #3a3a3a;
            }
            QMenu {
                background-color: #2b2b2b;
                border: 1px solid #555;
            }
            QMenu::item:selected {
                background-color: #3a3a3a;
            }
        """

    def _apply_dark_mode(self, app: QtWidgets.QApplication) -> None:
        """Apply the dark theme palette and stylesheet."""

        app.setStyle("Fusion")
        palette = app.palette()
        palette.setColor(palette.Window, QtGui.QColor("#2b2b2b"))
        palette.setColor(palette.WindowText, QtGui.QColor("#f0f0f0"))
        palette.setColor(palette.Base, QtGui.QColor("#3a3a3a"))
        palette.setColor(palette.AlternateBase, QtGui.QColor("#2f2f2f"))
        palette.setColor(palette.Text, QtGui.QColor("#f0f0f0"))
        palette.setColor(palette.Button, QtGui.QColor("#3d3d3d"))
        palette.setColor(palette.ButtonText, QtGui.QColor("#f0f0f0"))
        palette.setColor(palette.Highlight, QtGui.QColor("#6aa9ff"))
        palette.setColor(palette.HighlightedText, QtGui.QColor("#1a1a1a"))
        app.setPalette(palette)
        app.setStyleSheet(self._dark_stylesheet)

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
        self._apply_dark_mode(app)
        icon = self._load_app_icon()
        if icon and not icon.isNull():
            app.setWindowIcon(icon)
        self._ensure_admin()
        login = LoginWindow(self.authenticate, icon=icon)
        if login.exec() == QtWidgets.QDialog.Accepted:
            main = MainWindow(login.username_input.text(), self.conn, icon=icon)
            main.resize(800, 600)
            main.show()
            app.exec()


def main() -> None:
    """Launch the Policy Watch application."""

    PolicyWatchApp().run()


if __name__ == "__main__":
    main()
