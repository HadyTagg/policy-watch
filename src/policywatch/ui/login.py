"""Login dialog for Policy Watch."""

from __future__ import annotations

from PyQt5 import QtCore, QtGui, QtWidgets


class LoginWindow(QtWidgets.QDialog):
    """Simple login dialog with username/password inputs."""

    authenticated = QtCore.pyqtSignal(str)

    def __init__(self, on_authenticate, parent=None, icon: QtGui.QIcon | None = None):
        """Initialize the login dialog layout and handlers."""

        super().__init__(parent)
        self._on_authenticate = on_authenticate
        self.setWindowTitle("Policy Watch - Login")
        self.setModal(True)
        if icon and not icon.isNull():
            self.setWindowIcon(icon)

        self.username_input = QtWidgets.QLineEdit()
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.message_label = QtWidgets.QLabel()
        self.message_label.setStyleSheet("color: #b00020")

        form = QtWidgets.QFormLayout()
        form.addRow("Username", self.username_input)
        form.addRow("Password", self.password_input)

        button = QtWidgets.QPushButton("Login")
        button.clicked.connect(self._handle_login)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(button)
        layout.addWidget(self.message_label)

        self.adjustSize()
        self.setMinimumWidth(self.sizeHint().width() + 40)

    def _handle_login(self):
        """Validate credentials and emit the authenticated signal."""

        username = self.username_input.text().strip()
        password = self.password_input.text()
        if not username or not password:
            self.message_label.setText("Enter username and password.")
            return
        if self._on_authenticate(username, password):
            self.accept()
            self.authenticated.emit(username)
        else:
            self.message_label.setText("Invalid credentials.")
