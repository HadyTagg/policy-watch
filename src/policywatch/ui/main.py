from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from pathlib import Path

from PySide6 import QtCore, QtGui, QtWidgets

from policywatch import audit, config
from policywatch.integrations import access, outlook
from policywatch.services import (
    add_policy_version,
    build_staff_query,
    export_backup,
    get_version_file,
    list_categories,
    list_policies,
    list_versions,
    parse_mapping_json,
    set_current_version,
)
from policywatch.ui.dialogs import CategoryManagerDialog, PolicyDialog


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, username: str, conn: sqlite3.Connection, parent=None):
        super().__init__(parent)
        self.conn = conn
        self.current_policy_id: int | None = None

        self.setWindowTitle("Policy Watch")

        toolbar = self.addToolBar("Main")
        toolbar.setMovable(False)

        new_policy_action = QtGui.QAction("New Policy", self)
        new_policy_action.triggered.connect(self._open_new_policy)
        toolbar.addAction(new_policy_action)

        manage_categories_action = QtGui.QAction("Manage Categories", self)
        manage_categories_action.triggered.connect(self._open_categories)
        toolbar.addAction(manage_categories_action)

        header = QtWidgets.QLabel(f"Welcome, {username}.")
        header.setStyleSheet("font-size: 16px; font-weight: 600;")

        self.search_input = QtWidgets.QLineEdit()
        self.search_input.setPlaceholderText("Search policies...")
        self.search_input.textChanged.connect(self._refresh_policies)

        self.category_filter = QtWidgets.QComboBox()
        self.category_filter.setMinimumWidth(160)
        self.category_filter.currentIndexChanged.connect(self._refresh_policies)

        self.traffic_filter = QtWidgets.QComboBox()
        self.traffic_filter.addItems(["All Traffic Lights", "Green", "Amber", "Red"])
        self.traffic_filter.currentIndexChanged.connect(self._refresh_policies)

        self.status_filter = QtWidgets.QComboBox()
        self.status_filter.addItems(["All Statuses", "Draft", "Active", "Withdrawn", "Archived"])
        self.status_filter.currentIndexChanged.connect(self._refresh_policies)

        self.ratified_filter = QtWidgets.QComboBox()
        self.ratified_filter.addItems(["All", "Ratified", "Not Ratified"])
        self.ratified_filter.currentIndexChanged.connect(self._refresh_policies)

        self.show_expired = QtWidgets.QCheckBox("Show expired")
        self.show_expired.stateChanged.connect(self._refresh_policies)

        filter_row = QtWidgets.QHBoxLayout()
        filter_row.addWidget(self.search_input, 2)
        filter_row.addWidget(self.category_filter, 1)
        filter_row.addWidget(self.traffic_filter, 1)
        filter_row.addWidget(self.status_filter, 1)
        filter_row.addWidget(self.ratified_filter, 1)
        filter_row.addWidget(self.show_expired)

        self.table = QtWidgets.QTableWidget(0, 8)
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
            ]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._on_policy_selected)

        self.empty_state = QtWidgets.QLabel(
            "No policies yet. Use the toolbar to add policies, then upload versions from Policy Detail."
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
        self._load_settings()
        self._load_audit_log()

    def _refresh_categories(self) -> None:
        categories = ["All Categories"] + list_categories(self.conn)
        self.category_filter.blockSignals(True)
        self.category_filter.clear()
        self.category_filter.addItems(categories)
        self.category_filter.blockSignals(False)

    def _refresh_policies(self) -> None:
        policies = list_policies(self.conn)
        filtered = []
        search_text = self.search_input.text().strip().lower()
        category = self.category_filter.currentText()
        traffic = self.traffic_filter.currentText()
        status = self.status_filter.currentText()
        ratified_filter = self.ratified_filter.currentText()
        show_expired = self.show_expired.isChecked()

        for policy in policies:
            if search_text and search_text not in policy.title.lower():
                continue
            if category != "All Categories" and policy.category != category:
                continue
            if traffic != "All Traffic Lights" and policy.traffic_status != traffic:
                continue
            if status != "All Statuses" and policy.status != status:
                continue
            if ratified_filter == "Ratified" and not policy.ratified:
                continue
            if ratified_filter == "Not Ratified" and policy.ratified:
                continue
            if not show_expired and policy.traffic_reason == "Expired":
                continue
            filtered.append(policy)

        self.table.setRowCount(len(filtered))
        for row_index, policy in enumerate(filtered):
            traffic_item = QtWidgets.QTableWidgetItem(policy.traffic_status)
            traffic_item.setToolTip(policy.traffic_reason)
            self.table.setItem(row_index, 0, traffic_item)
            self.table.setItem(row_index, 1, QtWidgets.QTableWidgetItem(policy.title))
            self.table.setItem(row_index, 2, QtWidgets.QTableWidgetItem(policy.category))
            self.table.setItem(row_index, 3, QtWidgets.QTableWidgetItem(policy.status))
            self.table.setItem(row_index, 4, QtWidgets.QTableWidgetItem("Yes" if policy.ratified else "No"))
            self.table.setItem(
                row_index,
                5,
                QtWidgets.QTableWidgetItem(
                    str(policy.current_version_number) if policy.current_version_number else ""
                ),
            )
            self.table.setItem(row_index, 6, QtWidgets.QTableWidgetItem(policy.review_due_date))
            self.table.setItem(row_index, 7, QtWidgets.QTableWidgetItem(policy.expiry_date))
            self.table.item(row_index, 0).setData(QtCore.Qt.UserRole, policy.id)

        self.table_stack.setCurrentIndex(1 if filtered else 0)

    def _on_policy_selected(self) -> None:
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            return
        policy_id = self.table.item(selected[0].row(), 0).data(QtCore.Qt.UserRole)
        self.current_policy_id = policy_id
        self._load_policy_detail(policy_id)

    def _open_categories(self) -> None:
        dialog = CategoryManagerDialog(self.conn, self._refresh_categories, self)
        dialog.exec()
        self._refresh_policies()

    def _open_new_policy(self) -> None:
        if not list_categories(self.conn):
            QtWidgets.QMessageBox.warning(
                self,
                "Missing Categories",
                "Create at least one category before adding policies.",
            )
            return
        dialog = PolicyDialog(self.conn, self._refresh_policies, self)
        dialog.exec()
        self._load_send_policies()

    def _load_policy_detail(self, policy_id: int) -> None:
        policy = self.conn.execute(
            "SELECT * FROM policies WHERE id = ?",
            (policy_id,),
        ).fetchone()
        if not policy:
            return
        self.detail_status.blockSignals(True)
        self.detail_effective.blockSignals(True)
        self.detail_review_due.blockSignals(True)
        self.detail_expiry.blockSignals(True)
        self.detail_title.setText(policy["title"])
        self.detail_category.setText(policy["category"])
        self.detail_status.setCurrentText(policy["status"])
        self.detail_effective.setDate(QtCore.QDate.fromString(policy["effective_date"], "yyyy-MM-dd"))
        self.detail_review_due.setDate(QtCore.QDate.fromString(policy["review_due_date"], "yyyy-MM-dd"))
        self.detail_expiry.setDate(QtCore.QDate.fromString(policy["expiry_date"], "yyyy-MM-dd"))
        self.detail_notes.setPlainText(policy["notes"] or "")
        self.detail_status.blockSignals(False)
        self.detail_effective.blockSignals(False)
        self.detail_review_due.blockSignals(False)
        self.detail_expiry.blockSignals(False)

        versions = list_versions(self.conn, policy_id)
        self.version_table.setRowCount(len(versions))
        for row_index, version in enumerate(versions):
            self.version_table.setItem(
                row_index, 0, QtWidgets.QTableWidgetItem(str(version["version_number"]))
            )
            self.version_table.setItem(row_index, 1, QtWidgets.QTableWidgetItem(version["created_at"]))
            self.version_table.setItem(row_index, 2, QtWidgets.QTableWidgetItem(version["sha256_hash"]))
            self.version_table.setItem(
                row_index, 3, QtWidgets.QTableWidgetItem("Yes" if version["ratified"] else "No")
            )
            self.version_table.setItem(
                row_index, 4, QtWidgets.QTableWidgetItem(version["original_filename"])
            )
            self.version_table.setItem(
                row_index, 5, QtWidgets.QTableWidgetItem(str(version["file_size_bytes"]))
            )
            self.version_table.item(row_index, 0).setData(QtCore.Qt.UserRole, version["id"])

    def _upload_version(self) -> None:
        if not self.current_policy_id:
            QtWidgets.QMessageBox.warning(self, "Select Policy", "Select a policy first.")
            return
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Policy File")
        if not file_path:
            return
        try:
            add_policy_version(self.conn, self.current_policy_id, Path(file_path), None)
        except ValueError as exc:
            QtWidgets.QMessageBox.warning(self, "No Change", str(exc))
            return
        self._load_policy_detail(self.current_policy_id)
        self._refresh_policies()

    def _mark_ratified(self) -> None:
        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
            return
        version_id = self.version_table.item(selection[0].row(), 0).data(QtCore.Qt.UserRole)
        self.conn.execute(
            "UPDATE policy_versions SET ratified = 1, ratified_at = ?, ratified_by_user_id = NULL WHERE id = ?",
            (datetime.utcnow().isoformat(), version_id),
        )
        self.conn.commit()
        if self.current_policy_id:
            self._load_policy_detail(self.current_policy_id)
            self._refresh_policies()

    def _set_current(self) -> None:
        if not self.current_policy_id:
            return
        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
            return
        version_id = self.version_table.item(selection[0].row(), 0).data(QtCore.Qt.UserRole)
        ratified = self.conn.execute(
            "SELECT ratified FROM policy_versions WHERE id = ?",
            (version_id,),
        ).fetchone()
        if not ratified or not ratified["ratified"]:
            QtWidgets.QMessageBox.warning(self, "Not Ratified", "Version must be ratified first.")
            return
        set_current_version(self.conn, self.current_policy_id, version_id)
        self._refresh_policies()

    def _open_file_location(self) -> None:
        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
            return
        version_id = self.version_table.item(selection[0].row(), 0).data(QtCore.Qt.UserRole)
        file_path = get_version_file(self.conn, version_id)
        QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(file_path))

    def _update_policy_field(self, field: str, value: str) -> None:
        if not self.current_policy_id:
            return
        self.conn.execute(
            f"UPDATE policies SET {field} = ? WHERE id = ?",
            (value, self.current_policy_id),
        )
        self.conn.commit()
        self._refresh_policies()

    def _on_status_changed(self, status: str) -> None:
        self._update_policy_field("status", status)

    def _on_effective_changed(self, value: QtCore.QDate) -> None:
        self._update_policy_field("effective_date", value.toString("yyyy-MM-dd"))

    def _on_review_due_changed(self, value: QtCore.QDate) -> None:
        self._update_policy_field("review_due_date", value.toString("yyyy-MM-dd"))

    def _on_expiry_changed(self, value: QtCore.QDate) -> None:
        self._update_policy_field("expiry_date", value.toString("yyyy-MM-dd"))

    def _build_policy_detail(self) -> QtWidgets.QWidget:
        wrapper = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(wrapper)

        summary = QtWidgets.QGroupBox("Policy Metadata")
        form = QtWidgets.QFormLayout(summary)
        self.detail_title = QtWidgets.QLineEdit()
        self.detail_title.setReadOnly(True)
        self.detail_category = QtWidgets.QLineEdit()
        self.detail_category.setReadOnly(True)
        self.detail_status = QtWidgets.QComboBox()
        self.detail_status.addItems(["Draft", "Active", "Withdrawn", "Archived"])
        self.detail_status.currentTextChanged.connect(self._on_status_changed)
        self.detail_effective = QtWidgets.QDateEdit()
        self.detail_effective.setCalendarPopup(True)
        self.detail_effective.dateChanged.connect(self._on_effective_changed)
        self.detail_review_due = QtWidgets.QDateEdit()
        self.detail_review_due.setCalendarPopup(True)
        self.detail_review_due.dateChanged.connect(self._on_review_due_changed)
        self.detail_expiry = QtWidgets.QDateEdit()
        self.detail_expiry.setCalendarPopup(True)
        self.detail_expiry.dateChanged.connect(self._on_expiry_changed)
        self.detail_notes = QtWidgets.QPlainTextEdit()
        self.detail_notes.setReadOnly(True)

        form.addRow("Title", self.detail_title)
        form.addRow("Category", self.detail_category)
        form.addRow("Status", self.detail_status)
        form.addRow("Effective Date", self.detail_effective)
        form.addRow("Review Due", self.detail_review_due)
        form.addRow("Expiry", self.detail_expiry)
        form.addRow("Notes", self.detail_notes)

        versions = QtWidgets.QGroupBox("Version History")
        versions_layout = QtWidgets.QVBoxLayout(versions)
        self.version_table = QtWidgets.QTableWidget(0, 6)
        self.version_table.setHorizontalHeaderLabels(
            ["Version", "Created", "Hash", "Ratified", "File Name", "Size"]
        )
        self.version_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.version_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.version_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        versions_layout.addWidget(self.version_table)

        button_row = QtWidgets.QHBoxLayout()
        ratify_button = QtWidgets.QPushButton("Mark Ratified")
        ratify_button.clicked.connect(self._mark_ratified)
        set_current_button = QtWidgets.QPushButton("Set Current")
        set_current_button.clicked.connect(self._set_current)
        open_location_button = QtWidgets.QPushButton("Open File Location")
        open_location_button.clicked.connect(self._open_file_location)
        button_row.addWidget(QtWidgets.QPushButton("Upload New Version", clicked=self._upload_version))
        button_row.addWidget(ratify_button)
        button_row.addWidget(set_current_button)
        button_row.addWidget(open_location_button)
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
        self.policy_send_table = QtWidgets.QTableWidget(0, 5)
        self.policy_send_table.setHorizontalHeaderLabels(
            ["Select", "Title", "Version", "Category", "Size"]
        )
        self.policy_send_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.policy_send_table.itemChanged.connect(self._recalculate_attachments)
        policy_layout.addWidget(self.policy_send_table)
        reload_policies = QtWidgets.QPushButton("Reload Policies")
        reload_policies.clicked.connect(self._load_send_policies)
        policy_layout.addWidget(reload_policies)

        recipient_group = QtWidgets.QGroupBox("Recipients")
        recipient_layout = QtWidgets.QVBoxLayout(recipient_group)
        staff_search = QtWidgets.QLineEdit()
        staff_search.setPlaceholderText("Search staff...")
        staff_search.textChanged.connect(self._filter_staff)
        recipient_layout.addWidget(staff_search)
        self.staff_table = QtWidgets.QTableWidget(0, 4)
        self.staff_table.setHorizontalHeaderLabels(["Select", "Name", "Email", "Team"])
        self.staff_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        recipient_layout.addWidget(self.staff_table)
        load_staff_button = QtWidgets.QPushButton("Load Staff")
        load_staff_button.clicked.connect(self._load_staff)
        recipient_layout.addWidget(load_staff_button)
        self.manual_emails = QtWidgets.QLineEdit()
        self.manual_emails.setPlaceholderText("Manual emails (comma separated)")
        recipient_layout.addWidget(self.manual_emails)

        send_group = QtWidgets.QGroupBox("Send")
        send_layout = QtWidgets.QFormLayout(send_group)
        self.total_attachment_label = QtWidgets.QLabel("0 MB")
        self.split_plan_label = QtWidgets.QLabel("Single email")
        send_layout.addRow("Total attachment size", self.total_attachment_label)
        send_layout.addRow("Split plan", self.split_plan_label)
        send_button = QtWidgets.QPushButton("Send")
        send_button.clicked.connect(self._send_email)
        send_layout.addRow("", send_button)

        layout.addWidget(policy_group)
        layout.addWidget(recipient_group)
        layout.addWidget(send_group)

        self._load_send_policies()
        return wrapper

    def _load_send_policies(self) -> None:
        rows = self.conn.execute(
            """
            SELECT p.title, p.category, v.id AS version_id, v.version_number, v.file_size_bytes
            FROM policy_versions v
            JOIN policies p ON p.id = v.policy_id
            ORDER BY p.title, v.version_number DESC
            """
        ).fetchall()
        self.policy_send_table.blockSignals(True)
        self.policy_send_table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            checkbox = QtWidgets.QTableWidgetItem()
            checkbox.setCheckState(QtCore.Qt.Unchecked)
            self.policy_send_table.setItem(row_index, 0, checkbox)
            self.policy_send_table.setItem(row_index, 1, QtWidgets.QTableWidgetItem(row["title"]))
            self.policy_send_table.setItem(row_index, 2, QtWidgets.QTableWidgetItem(str(row["version_number"])))
            self.policy_send_table.setItem(row_index, 3, QtWidgets.QTableWidgetItem(row["category"]))
            self.policy_send_table.setItem(row_index, 4, QtWidgets.QTableWidgetItem(str(row["file_size_bytes"])))
            self.policy_send_table.item(row_index, 0).setData(QtCore.Qt.UserRole, row["version_id"])
        self.policy_send_table.blockSignals(False)
        self._recalculate_attachments()

    def _load_staff(self) -> None:
        access_path = config.get_setting(self.conn, "access_db_path", "N:\\")
        mode = config.get_setting(self.conn, "access_mode", "table")
        table = config.get_setting(self.conn, "access_table", "")
        mapping = parse_mapping_json(config.get_setting(self.conn, "access_fields", "{}"))
        query = config.get_setting(self.conn, "access_query", "")
        staff_query = build_staff_query(mode, table, mapping, query)
        if not staff_query:
            QtWidgets.QMessageBox.warning(self, "Configure", "Configure staff data source first.")
            return
        try:
            conn = access.connect_access(access_path)
        except access.AccessDriverError as exc:
            QtWidgets.QMessageBox.warning(self, "Driver Missing", str(exc))
            return
        rows = access.preview_query(conn, staff_query, limit=200)
        conn.close()
        self.staff_table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            checkbox = QtWidgets.QTableWidgetItem()
            checkbox.setCheckState(QtCore.Qt.Unchecked)
            name = row.get(mapping.get("display_name")) if mapping.get("display_name") else None
            if not name:
                first = row.get(mapping.get("first_name"), "")
                last = row.get(mapping.get("last_name"), "")
                name = f"{first} {last}".strip()
            email = row.get(mapping.get("email"), "")
            team = row.get(mapping.get("role_team"), "")
            self.staff_table.setItem(row_index, 0, checkbox)
            self.staff_table.setItem(row_index, 1, QtWidgets.QTableWidgetItem(name or ""))
            self.staff_table.setItem(row_index, 2, QtWidgets.QTableWidgetItem(email or ""))
            self.staff_table.setItem(row_index, 3, QtWidgets.QTableWidgetItem(team or ""))
        self.staff_table.resizeColumnsToContents()

    def _filter_staff(self, text: str) -> None:
        text = text.lower().strip()
        for row in range(self.staff_table.rowCount()):
            name = self.staff_table.item(row, 1).text().lower()
            email = self.staff_table.item(row, 2).text().lower()
            match = text in name or text in email
            self.staff_table.setRowHidden(row, not match if text else False)

    def _recalculate_attachments(self) -> None:
        total_bytes = 0
        for row in range(self.policy_send_table.rowCount()):
            item = self.policy_send_table.item(row, 0)
            if item.checkState() == QtCore.Qt.Checked:
                size = int(self.policy_send_table.item(row, 4).text())
                total_bytes += size
        total_mb = total_bytes / (1024 * 1024)
        self.total_attachment_label.setText(f"{total_mb:.2f} MB")

        max_mb = float(config.get_setting(self.conn, "max_attachment_mb", 0) or 0)
        if max_mb and total_mb > max_mb:
            parts = int(total_mb // max_mb) + 1
            self.split_plan_label.setText(f"Split into {parts} emails")
        else:
            self.split_plan_label.setText("Single email")

    def _send_email(self) -> None:
        selected_versions: list[int] = []
        for row in range(self.policy_send_table.rowCount()):
            item = self.policy_send_table.item(row, 0)
            if item.checkState() == QtCore.Qt.Checked:
                selected_versions.append(item.data(QtCore.Qt.UserRole))

        recipients: list[tuple[str, str]] = []
        for row in range(self.staff_table.rowCount()):
            item = self.staff_table.item(row, 0)
            if item and item.checkState() == QtCore.Qt.Checked:
                recipients.append(
                    (self.staff_table.item(row, 2).text(), self.staff_table.item(row, 1).text())
                )
        manual = [email.strip() for email in self.manual_emails.text().split(",") if email.strip()]
        recipients.extend([(email, email) for email in manual])

        if not selected_versions or not recipients:
            QtWidgets.QMessageBox.warning(self, "Missing", "Select policies and recipients.")
            return

        max_mb = float(config.get_setting(self.conn, "max_attachment_mb", 0) or 0)
        attachments: list[tuple[str, int]] = []
        policy_rows = []
        total_bytes = 0
        for version_id in selected_versions:
            row = self.conn.execute(
                """
                SELECT p.id AS policy_id, p.title, v.id AS version_id, v.version_number,
                       v.file_size_bytes, v.file_path
                FROM policy_versions v
                JOIN policies p ON p.id = v.policy_id
                WHERE v.id = ?
                """,
                (version_id,),
            ).fetchone()
            if not row:
                continue
            attachments.append((row["file_path"], row["file_size_bytes"]))
            policy_rows.append(row)
            total_bytes += row["file_size_bytes"]

        total_mb = total_bytes / (1024 * 1024)
        parts = 1
        if max_mb and total_mb > max_mb:
            parts = int(total_mb // max_mb) + 1

        subject_base = "Policy/Policies"
        body_lines = [
            "Please find the following policy/policies attached. Please ensure you read the policy. "
            "If you have any questions, please contact us.",
            "",
        ]
        for row in policy_rows:
            body_lines.append(f"- {row['title']} (v{row['version_number']})")
        body = "\n".join(body_lines)

        max_bytes = int(max_mb * 1024 * 1024) if max_mb else 0
        attachment_chunks: list[list[tuple[str, int]]] = [[]]
        current_bytes = 0
        for path, size in attachments:
            if max_bytes and current_bytes + size > max_bytes and attachment_chunks[-1]:
                attachment_chunks.append([])
                current_bytes = 0
            attachment_chunks[-1].append((path, size))
            current_bytes += size

        parts = len(attachment_chunks)
        sender_user = os.getlogin()
        for part_index, chunk in enumerate(attachment_chunks, start=1):
            subject = subject_base
            if parts > 1:
                subject = f"{subject_base} (Part {part_index} of {parts})"
            try:
                entry_id = outlook.send_email(
                    subject, body, [email for email, _ in recipients], [path for path, _ in chunk]
                )
                status = "SENT"
                error_text = ""
            except outlook.OutlookError as exc:
                entry_id = ""
                status = "FAILED"
                error_text = str(exc)

            for row in policy_rows:
                for recipient_email, recipient_name in recipients:
                    audit.append_email_log(
                        self.conn,
                        {
                            "sent_at": datetime.utcnow().isoformat(),
                            "sender_windows_user": sender_user,
                            "sender_mailbox": "",
                            "recipient_name": recipient_name or recipient_email,
                            "recipient_email": recipient_email,
                            "policy_id": row["policy_id"],
                            "policy_title": row["title"],
                            "policy_version_id": row["version_id"],
                            "version_number": row["version_number"],
                            "email_subject": subject,
                            "email_part_index": part_index,
                            "email_part_total": parts,
                            "total_attachment_bytes_for_part": sum(size for _, size in chunk),
                            "outlook_entry_id": entry_id,
                            "status": status,
                            "error_text": error_text,
                        },
                    )

        QtWidgets.QMessageBox.information(self, "Sent", "Email processing completed.")

    def _build_audit_log(self) -> QtWidgets.QWidget:
        wrapper = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(wrapper)

        filters = QtWidgets.QHBoxLayout()
        self.audit_start = QtWidgets.QDateEdit()
        self.audit_end = QtWidgets.QDateEdit()
        self.audit_recipient = QtWidgets.QLineEdit()
        self.audit_policy = QtWidgets.QLineEdit()
        self.audit_status = QtWidgets.QComboBox()
        self.audit_status.addItems(["All", "SENT", "FAILED"])
        filters.addWidget(self.audit_start)
        filters.addWidget(self.audit_end)
        filters.addWidget(self.audit_recipient)
        filters.addWidget(self.audit_policy)
        filters.addWidget(self.audit_status)

        self.audit_table = QtWidgets.QTableWidget(0, 6)
        self.audit_table.setHorizontalHeaderLabels(
            ["Sent At", "Recipient", "Policy", "Version", "Status", "Mailbox"]
        )
        self.audit_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)

        button_row = QtWidgets.QHBoxLayout()
        export_button = QtWidgets.QPushButton("Export CSV")
        export_button.clicked.connect(self._export_audit_csv)
        verify_button = QtWidgets.QPushButton("Verify Integrity")
        verify_button.clicked.connect(self._verify_audit)
        refresh_button = QtWidgets.QPushButton("Refresh")
        refresh_button.clicked.connect(self._load_audit_log)
        button_row.addWidget(export_button)
        button_row.addWidget(verify_button)
        button_row.addWidget(refresh_button)
        button_row.addStretch(1)

        layout.addLayout(filters)
        layout.addWidget(self.audit_table)
        layout.addLayout(button_row)
        return wrapper

    def _load_audit_log(self) -> None:
        rows = self.conn.execute(
            "SELECT sent_at, recipient_email, policy_title, version_number, status, sender_mailbox "
            "FROM email_log ORDER BY sent_at DESC"
        ).fetchall()
        self.audit_table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            self.audit_table.setItem(row_index, 0, QtWidgets.QTableWidgetItem(row["sent_at"]))
            self.audit_table.setItem(row_index, 1, QtWidgets.QTableWidgetItem(row["recipient_email"]))
            self.audit_table.setItem(row_index, 2, QtWidgets.QTableWidgetItem(row["policy_title"]))
            self.audit_table.setItem(row_index, 3, QtWidgets.QTableWidgetItem(str(row["version_number"])))
            self.audit_table.setItem(row_index, 4, QtWidgets.QTableWidgetItem(row["status"]))
            self.audit_table.setItem(row_index, 5, QtWidgets.QTableWidgetItem(row["sender_mailbox"] or ""))

    def _export_audit_csv(self) -> None:
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export CSV", "audit_log.csv")
        if not path:
            return
        rows = self.conn.execute("SELECT * FROM email_log ORDER BY sent_at DESC").fetchall()
        import csv

        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            if rows:
                writer.writerow(rows[0].keys())
            for row in rows:
                writer.writerow(list(row))

    def _verify_audit(self) -> None:
        ok, message = audit.verify_audit_log(self.conn)
        QtWidgets.QMessageBox.information(self, "Audit Log", message)

    def _build_settings(self) -> QtWidgets.QWidget:
        wrapper = QtWidgets.QWidget()
        wrapper_layout = QtWidgets.QVBoxLayout(wrapper)

        form_container = QtWidgets.QWidget(wrapper)
        self.settings_form = QtWidgets.QFormLayout(form_container)

        self.policy_root_input = QtWidgets.QLineEdit(form_container)
        browse_root = QtWidgets.QPushButton("Browse", form_container)
        browse_root.clicked.connect(self._browse_policy_root)
        policy_root_row = QtWidgets.QHBoxLayout()
        policy_root_row.addWidget(self.policy_root_input)
        policy_root_row.addWidget(browse_root)
        policy_root_container = QtWidgets.QWidget(form_container)
        policy_root_container.setLayout(policy_root_row)

        self.amber_months_input = QtWidgets.QSpinBox(form_container)
        self.amber_months_input.setRange(0, 24)
        self.overdue_days_input = QtWidgets.QSpinBox(form_container)
        self.overdue_days_input.setRange(0, 365)
        self.max_attachment_input = QtWidgets.QSpinBox(form_container)
        self.max_attachment_input.setRange(0, 500)

        self.settings_form.addRow("Policy root folder", policy_root_container)
        self.settings_form.addRow("Amber months", self.amber_months_input)
        self.settings_form.addRow("Overdue grace days", self.overdue_days_input)
        self.settings_form.addRow("Max attachment MB", self.max_attachment_input)

        access_group = QtWidgets.QGroupBox("Staff Data Source", form_container)
        access_layout = QtWidgets.QFormLayout(access_group)
        self.access_path = QtWidgets.QLineEdit(access_group)
        self.access_mode = QtWidgets.QComboBox(access_group)
        self.access_mode.addItems(["table", "query"])
        self.access_table = QtWidgets.QLineEdit(access_group)
        self.access_query = QtWidgets.QPlainTextEdit(access_group)
        self.access_fields = QtWidgets.QPlainTextEdit(access_group)
        self.access_fields.setPlaceholderText(
            '{"staff_id": "ID", "first_name": "FirstName", "last_name": "LastName", "email": "Email"}'
        )
        test_button = QtWidgets.QPushButton("Test Connection", access_group)
        test_button.clicked.connect(self._test_access)

        access_layout.addRow("Access .accdb path", self.access_path)
        access_layout.addRow("Mode", self.access_mode)
        access_layout.addRow("Table", self.access_table)
        access_layout.addRow("Query", self.access_query)
        access_layout.addRow("Field mapping (JSON)", self.access_fields)
        access_layout.addRow("", test_button)

        self.settings_form.addRow(access_group)

        save_button = QtWidgets.QPushButton("Save Settings", wrapper)
        save_button.clicked.connect(self._save_settings)

        backup_row = QtWidgets.QHBoxLayout()
        open_data = QtWidgets.QPushButton("Open data folder", wrapper)
        open_data.clicked.connect(self._open_data_folder)
        backup = QtWidgets.QPushButton("Backup/Export", wrapper)
        backup.clicked.connect(self._backup_export)
        backup_row.addWidget(open_data)
        backup_row.addWidget(backup)
        backup_row.addStretch(1)

        wrapper_layout.addWidget(form_container)
        wrapper_layout.addWidget(save_button)
        wrapper_layout.addLayout(backup_row)
        return wrapper

    def _browse_policy_root(self) -> None:
        directory = QtWidgets.QFileDialog.getExistingDirectory(self, "Policy Root")
        if directory:
            self.policy_root_input.setText(directory)

    def _save_settings(self) -> None:
        config.set_setting(self.conn, "policy_root", self.policy_root_input.text().strip())
        config.set_setting(self.conn, "amber_months", self.amber_months_input.value())
        config.set_setting(self.conn, "overdue_grace_days", self.overdue_days_input.value())
        config.set_setting(self.conn, "max_attachment_mb", self.max_attachment_input.value())
        config.set_setting(self.conn, "access_db_path", self.access_path.text().strip())
        config.set_setting(self.conn, "access_mode", self.access_mode.currentText())
        config.set_setting(self.conn, "access_table", self.access_table.text().strip())
        config.set_setting(self.conn, "access_query", self.access_query.toPlainText().strip())
        config.set_setting(self.conn, "access_fields", self.access_fields.toPlainText().strip())
        QtWidgets.QMessageBox.information(self, "Saved", "Settings updated.")

    def _load_settings(self) -> None:
        self.policy_root_input.setText(config.get_setting(self.conn, "policy_root", ""))
        self.amber_months_input.setValue(int(config.get_setting(self.conn, "amber_months", 2) or 2))
        self.overdue_days_input.setValue(int(config.get_setting(self.conn, "overdue_grace_days", 0) or 0))
        self.max_attachment_input.setValue(int(config.get_setting(self.conn, "max_attachment_mb", 0) or 0))
        self.access_path.setText(config.get_setting(self.conn, "access_db_path", "N:\\"))
        self.access_mode.setCurrentText(config.get_setting(self.conn, "access_mode", "table"))
        self.access_table.setText(config.get_setting(self.conn, "access_table", ""))
        self.access_query.setPlainText(config.get_setting(self.conn, "access_query", ""))
        self.access_fields.setPlainText(config.get_setting(self.conn, "access_fields", "{}"))

    def _test_access(self) -> None:
        access_path = self.access_path.text().strip()
        mapping = parse_mapping_json(self.access_fields.toPlainText().strip())
        query = self.access_query.toPlainText().strip()
        table = self.access_table.text().strip()
        mode = self.access_mode.currentText()
        staff_query = build_staff_query(mode, table, mapping, query)
        if not staff_query:
            QtWidgets.QMessageBox.warning(self, "Invalid", "Provide a table and field mapping or query.")
            return
        try:
            conn = access.connect_access(access_path)
        except access.AccessDriverError as exc:
            QtWidgets.QMessageBox.warning(self, "Driver Missing", str(exc))
            return
        rows = access.preview_query(conn, staff_query, limit=20)
        conn.close()
        preview = "\n".join([str(row) for row in rows])
        QtWidgets.QMessageBox.information(self, "Preview", preview or "No rows returned.")

    def _open_data_folder(self) -> None:
        data_dir = config.get_paths().data_dir
        QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(data_dir)))

    def _backup_export(self) -> None:
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Backup", "policywatch_backup.zip")
        if not path:
            return
        include_files = QtWidgets.QMessageBox.question(
            self,
            "Include Files",
            "Include policy files in the backup?",
        )
        export_backup(self.conn, Path(path), include_files == QtWidgets.QMessageBox.Yes)
        QtWidgets.QMessageBox.information(self, "Backup", "Backup complete.")
