from __future__ import annotations

from PySide6 import QtCore, QtWidgets


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, username: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Policy Watch")
        label = QtWidgets.QLabel(f"Welcome, {username}.")
        label.setAlignment(QtCore.Qt.AlignCenter)
        container = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(container)
        layout.addWidget(label)
        self.setCentralWidget(container)
