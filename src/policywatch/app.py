from __future__ import annotations

import datetime

from PyQt5 import QtWidgets

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
