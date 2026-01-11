from __future__ import annotations

import datetime

from PyQt5 import QtGui, QtWidgets

from policywatch import config, db, security
from policywatch.ui.login import LoginWindow
from policywatch.ui.main import MainWindow


class PolicyWatchApp:
    def __init__(self) -> None:
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

    def _ensure_admin(self) -> None:
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
        row = self.conn.execute(
            "SELECT password_hash, salt, disabled FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row or row["disabled"]:
            return False
        return security.verify_password(password, row["password_hash"], row["salt"])

    def run(self) -> None:
        app = QtWidgets.QApplication([])
        self._app = app
        self._apply_dark_mode(app)
        self._ensure_admin()
        login = LoginWindow(self.authenticate)
        if login.exec() == QtWidgets.QDialog.Accepted:
            main = MainWindow(login.username_input.text(), self.conn)
            main.resize(800, 600)
            main.show()
            app.exec()


def main() -> None:
    PolicyWatchApp().run()


if __name__ == "__main__":
    main()
