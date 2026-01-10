from __future__ import annotations

from PySide6 import QtCore, QtWidgets


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, username: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Policy Watch")

        header = QtWidgets.QLabel(f"Welcome, {username}.")
        header.setStyleSheet("font-size: 16px; font-weight: 600;")

        search_input = QtWidgets.QLineEdit()
        search_input.setPlaceholderText("Search policies...")

        category_filter = QtWidgets.QComboBox()
        category_filter.addItems(["All Categories"])

        traffic_filter = QtWidgets.QComboBox()
        traffic_filter.addItems(["All Traffic Lights", "Green", "Amber", "Red"])

        status_filter = QtWidgets.QComboBox()
        status_filter.addItems(["All Statuses", "Draft", "Active", "Withdrawn", "Archived"])

        ratified_filter = QtWidgets.QComboBox()
        ratified_filter.addItems(["All", "Ratified", "Not Ratified"])

        show_expired = QtWidgets.QCheckBox("Show expired")

        filter_row = QtWidgets.QHBoxLayout()
        filter_row.addWidget(search_input, 2)
        filter_row.addWidget(category_filter, 1)
        filter_row.addWidget(traffic_filter, 1)
        filter_row.addWidget(status_filter, 1)
        filter_row.addWidget(ratified_filter, 1)
        filter_row.addWidget(show_expired)

        table = QtWidgets.QTableWidget(0, 9)
        table.setHorizontalHeaderLabels(
            [
                "Traffic Light",
                "Title",
                "Category",
                "Status",
                "Ratified",
                "Current Version",
                "Review Due",
                "Expiry",
                "Owner",
            ]
        )
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        empty_state = QtWidgets.QLabel(
            "No policies yet. Use the toolbar to add policies and upload versions."
        )
        empty_state.setAlignment(QtCore.Qt.AlignCenter)
        empty_state.setStyleSheet("color: #666; padding: 12px;")

        table_stack = QtWidgets.QStackedWidget()
        table_stack.addWidget(empty_state)
        table_stack.addWidget(table)
        table_stack.setCurrentIndex(0)

        content = QtWidgets.QVBoxLayout()
        content.addWidget(header)
        content.addLayout(filter_row)
        content.addWidget(table_stack)

        container = QtWidgets.QWidget()
        container.setLayout(content)
        self.setCentralWidget(container)
