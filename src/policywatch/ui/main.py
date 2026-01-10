from __future__ import annotations

import sqlite3

from PySide6 import QtCore, QtWidgets

from policywatch.ui.dialogs import CategoryManagerDialog, PolicyDialog


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, username: str, conn: sqlite3.Connection, parent=None):
        super().__init__(parent)
        self.conn = conn
        self.setWindowTitle("Policy Watch")

        toolbar = self.addToolBar("Main")
        toolbar.setMovable(False)

        new_policy_action = QtWidgets.QAction("New Policy", self)
        new_policy_action.triggered.connect(self._open_new_policy)
        toolbar.addAction(new_policy_action)

        manage_categories_action = QtWidgets.QAction("Manage Categories", self)
        manage_categories_action.triggered.connect(self._open_categories)
        toolbar.addAction(manage_categories_action)

        header = QtWidgets.QLabel(f"Welcome, {username}.")
        header.setStyleSheet("font-size: 16px; font-weight: 600;")

        self.search_input = QtWidgets.QLineEdit()
        self.search_input.setPlaceholderText("Search policies...")

        self.category_filter = QtWidgets.QComboBox()
        self.category_filter.setMinimumWidth(160)

        self.traffic_filter = QtWidgets.QComboBox()
        self.traffic_filter.addItems(["All Traffic Lights", "Green", "Amber", "Red"])

        self.status_filter = QtWidgets.QComboBox()
        self.status_filter.addItems(["All Statuses", "Draft", "Active", "Withdrawn", "Archived"])

        self.ratified_filter = QtWidgets.QComboBox()
        self.ratified_filter.addItems(["All", "Ratified", "Not Ratified"])

        self.show_expired = QtWidgets.QCheckBox("Show expired")

        filter_row = QtWidgets.QHBoxLayout()
        filter_row.addWidget(self.search_input, 2)
        filter_row.addWidget(self.category_filter, 1)
        filter_row.addWidget(self.traffic_filter, 1)
        filter_row.addWidget(self.status_filter, 1)
        filter_row.addWidget(self.ratified_filter, 1)
        filter_row.addWidget(self.show_expired)

        self.table = QtWidgets.QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(
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
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        self.empty_state = QtWidgets.QLabel(
            "No policies yet. Use the toolbar to add policies and upload versions."
        )
        self.empty_state.setAlignment(QtCore.Qt.AlignCenter)
        self.empty_state.setStyleSheet("color: #666; padding: 12px;")

        self.table_stack = QtWidgets.QStackedWidget()
        self.table_stack.addWidget(self.empty_state)
        self.table_stack.addWidget(self.table)
        self.table_stack.setCurrentIndex(0)

        dashboard = QtWidgets.QWidget()
        dashboard_layout = QtWidgets.QVBoxLayout(dashboard)
        dashboard_layout.addWidget(header)
        dashboard_layout.addLayout(filter_row)
        dashboard_layout.addWidget(self.table_stack)

        policy_detail = self._build_policy_detail()
        email_compose = self._build_email_compose()
        audit_log = self._build_audit_log()
        settings = self._build_settings()

        self.tabs = QtWidgets.QTabWidget()
        self.tabs.addTab(dashboard, "Dashboard")
        self.tabs.addTab(policy_detail, "Policy Detail")
        self.tabs.addTab(email_compose, "Compose Email")
        self.tabs.addTab(audit_log, "Audit Log")
        self.tabs.addTab(settings, "Settings")

        container = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(container)
        layout.addWidget(self.tabs)
        self.setCentralWidget(container)

        self._refresh_categories()
        self._refresh_policies()

    def _refresh_categories(self) -> None:
        rows = self.conn.execute("SELECT name FROM categories ORDER BY name").fetchall()
        categories = ["All Categories"] + [row["name"] for row in rows]
        self.category_filter.clear()
        self.category_filter.addItems(categories)

    def _refresh_policies(self) -> None:
        rows = self.conn.execute(
            "SELECT title, category, status, ratified, review_due_date, expiry_date, owner "
            "FROM policies ORDER BY created_at DESC"
        ).fetchall()
        self.table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            self.table.setItem(row_index, 0, QtWidgets.QTableWidgetItem(""))
            self.table.setItem(row_index, 1, QtWidgets.QTableWidgetItem(row["title"]))
            self.table.setItem(row_index, 2, QtWidgets.QTableWidgetItem(row["category"]))
            self.table.setItem(row_index, 3, QtWidgets.QTableWidgetItem(row["status"]))
            self.table.setItem(row_index, 4, QtWidgets.QTableWidgetItem("Yes" if row["ratified"] else "No"))
            self.table.setItem(row_index, 5, QtWidgets.QTableWidgetItem(""))
            self.table.setItem(row_index, 6, QtWidgets.QTableWidgetItem(row["review_due_date"]))
            self.table.setItem(row_index, 7, QtWidgets.QTableWidgetItem(row["expiry_date"]))
            self.table.setItem(row_index, 8, QtWidgets.QTableWidgetItem(row["owner"] or ""))

        self.table_stack.setCurrentIndex(1 if rows else 0)

    def _open_categories(self) -> None:
        dialog = CategoryManagerDialog(self.conn, self._refresh_categories, self)
        dialog.exec()

    def _open_new_policy(self) -> None:
        dialog = PolicyDialog(self.conn, self._refresh_policies, self)
        dialog.exec()

    def _build_policy_detail(self) -> QtWidgets.QWidget:
        wrapper = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(wrapper)

        summary = QtWidgets.QGroupBox("Policy Metadata")
        form = QtWidgets.QFormLayout(summary)
        form.addRow("Title", QtWidgets.QLineEdit())
        form.addRow("Category", QtWidgets.QLineEdit())
        form.addRow("Status", QtWidgets.QComboBox())
        form.addRow("Ratified", QtWidgets.QCheckBox("Yes"))
        form.addRow("Effective Date", QtWidgets.QDateEdit())
        form.addRow("Review Due", QtWidgets.QDateEdit())
        form.addRow("Expiry", QtWidgets.QDateEdit())
        form.addRow("Owner", QtWidgets.QLineEdit())
        form.addRow("Notes", QtWidgets.QPlainTextEdit())

        versions = QtWidgets.QGroupBox("Version History")
        versions_layout = QtWidgets.QVBoxLayout(versions)
        version_table = QtWidgets.QTableWidget(0, 6)
        version_table.setHorizontalHeaderLabels(
            ["Version", "Created", "Hash", "Ratified", "File Name", "Size"]
        )
        version_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        versions_layout.addWidget(version_table)

        button_row = QtWidgets.QHBoxLayout()
        button_row.addWidget(QtWidgets.QPushButton("Upload New Version"))
        button_row.addWidget(QtWidgets.QPushButton("Mark Ratified"))
        button_row.addWidget(QtWidgets.QPushButton("Set Current"))
        button_row.addWidget(QtWidgets.QPushButton("Open File Location"))
        button_row.addStretch(1)

        layout.addWidget(summary)
        layout.addWidget(versions)
        layout.addLayout(button_row)
        return wrapper

    def _build_email_compose(self) -> QtWidgets.QWidget:
        wrapper = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(wrapper)

        policy_group = QtWidgets.QGroupBox("Policies to Send")
        policy_layout = QtWidgets.QVBoxLayout(policy_group)
        policy_table = QtWidgets.QTableWidget(0, 4)
        policy_table.setHorizontalHeaderLabels(["Title", "Version", "Category", "Size"])
        policy_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        policy_layout.addWidget(policy_table)

        recipient_group = QtWidgets.QGroupBox("Recipients")
        recipient_layout = QtWidgets.QVBoxLayout(recipient_group)
        recipient_layout.addWidget(QtWidgets.QLineEdit("Search staff..."))
        recipient_table = QtWidgets.QTableWidget(0, 3)
        recipient_table.setHorizontalHeaderLabels(["Name", "Email", "Team"])
        recipient_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        recipient_layout.addWidget(recipient_table)
        recipient_layout.addWidget(QtWidgets.QLineEdit("Manual emails (comma separated)"))

        send_group = QtWidgets.QGroupBox("Send")
        send_layout = QtWidgets.QFormLayout(send_group)
        send_layout.addRow("Total attachment size", QtWidgets.QLabel("0 MB"))
        send_layout.addRow("Split plan", QtWidgets.QLabel("Single email"))
        send_button = QtWidgets.QPushButton("Send")
        send_layout.addRow("", send_button)

        layout.addWidget(policy_group)
        layout.addWidget(recipient_group)
        layout.addWidget(send_group)
        return wrapper

    def _build_audit_log(self) -> QtWidgets.QWidget:
        wrapper = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(wrapper)

        filters = QtWidgets.QHBoxLayout()
        filters.addWidget(QtWidgets.QDateEdit())
        filters.addWidget(QtWidgets.QDateEdit())
        filters.addWidget(QtWidgets.QLineEdit("Recipient"))
        filters.addWidget(QtWidgets.QLineEdit("Policy"))
        filters.addWidget(QtWidgets.QComboBox())

        table = QtWidgets.QTableWidget(0, 6)
        table.setHorizontalHeaderLabels(
            ["Sent At", "Recipient", "Policy", "Version", "Status", "Mailbox"]
        )
        table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)

        button_row = QtWidgets.QHBoxLayout()
        button_row.addWidget(QtWidgets.QPushButton("Export CSV"))
        button_row.addWidget(QtWidgets.QPushButton("Verify Integrity"))
        button_row.addStretch(1)

        layout.addLayout(filters)
        layout.addWidget(table)
        layout.addLayout(button_row)
        return wrapper

    def _build_settings(self) -> QtWidgets.QWidget:
        wrapper = QtWidgets.QWidget()
        layout = QtWidgets.QFormLayout(wrapper)

        layout.addRow("Policy root folder", QtWidgets.QLineEdit())
        layout.addRow("Amber months", QtWidgets.QSpinBox())
        layout.addRow("Overdue grace days", QtWidgets.QSpinBox())
        layout.addRow("Max attachment MB", QtWidgets.QSpinBox())

        access_group = QtWidgets.QGroupBox("Staff Data Source")
        access_layout = QtWidgets.QFormLayout(access_group)
        access_layout.addRow("Access .accdb path", QtWidgets.QLineEdit())
        access_layout.addRow("Mode", QtWidgets.QComboBox())
        access_layout.addRow("Table", QtWidgets.QLineEdit())
        access_layout.addRow("Query", QtWidgets.QPlainTextEdit())
        access_layout.addRow("Test", QtWidgets.QPushButton("Test Connection"))

        layout.addRow(access_group)

        backup_row = QtWidgets.QHBoxLayout()
        backup_row.addWidget(QtWidgets.QPushButton("Open data folder"))
        backup_row.addWidget(QtWidgets.QPushButton("Backup/Export"))
        backup_row.addStretch(1)

        wrapper_layout = QtWidgets.QVBoxLayout()
        wrapper_layout.addLayout(layout)
        wrapper_layout.addLayout(backup_row)
        wrapper_container = QtWidgets.QWidget()
        wrapper_container.setLayout(wrapper_layout)
        return wrapper_container
