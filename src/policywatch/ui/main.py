"""Main window and UI logic for Policy Watch."""

from __future__ import annotations

import csv
import os
import re
import sqlite3
import shutil
import subprocess
import sys
import time
from datetime import date, datetime
from email.utils import parseaddr
from pathlib import Path

from PyQt5 import QtCore, QtGui, QtWidgets

from policywatch.core import audit, config, security
from policywatch.integrations import outlook
from policywatch.services import (
    add_policy_version,
    add_policy_review,
    export_backup,
    get_version_file,
    mark_policy_version_missing,
    format_replacement_note,
    file_sha256,
    policy_backup_available,
    resolve_version_file_path,
    restore_policy_from_backup,
    restore_policy_version_file,
    restore_missing_policy_file,
    update_policy_version_notes,
    scan_policy_file_integrity,
    list_categories,
    list_users,
    list_policies,
    list_policy_reviews,
    list_versions,
    mark_version_ratified,
    unmark_version_ratified,
    set_current_version,
    unset_current_version,
    update_policy_category,
    update_policy_version_owner,
    update_policy_title,
    set_audit_actor,
)
from policywatch.ui.dialogs import AccountCreationDialog, CategoryManagerDialog, PasswordChangeDialog, PolicyDialog


class BoldTableItemDelegate(QtWidgets.QStyledItemDelegate):
    """Force bold text for table items."""

    def initStyleOption(self, option: QtWidgets.QStyleOptionViewItem, index: QtCore.QModelIndex) -> None:
        """Initialize style options with a bold font."""

        super().initStyleOption(option, index)
        option.font.setBold(True)


class MainWindow(QtWidgets.QMainWindow):
    """Main application window coordinating dashboard and workflow tabs."""

    def __init__(
        self,
        username: str,
        conn: sqlite3.Connection,
        parent=None,
        icon: QtGui.QIcon | None = None,
    ):
        """Initialize the main window and build all primary UI sections."""

        super().__init__(parent)
        self.conn = conn
        self.username = username
        self.user_id: int | None = None
        self.user_role: str | None = None
        self.current_policy_id: int | None = None
        self._notes_dirty = False
        self._title_dirty = False
        self._current_policy_title = ""
        self._current_policy_category = ""
        self._latest_reviewed_at: str | None = None
        self._staff_records: list[dict[str, str]] = []
        self._owner_refreshing = False

        set_audit_actor(username)
        self._load_user_context()
        self.setWindowTitle("Policy Watch - Developed by Hady Tagg")
        if icon and not icon.isNull():
            self.setWindowIcon(icon)

        toolbar = self.addToolBar("Main")
        toolbar.setMovable(False)

        new_policy_action = QtWidgets.QAction("New Policy", self)
        new_policy_action.triggered.connect(self._open_new_policy)
        toolbar.addAction(new_policy_action)

        manage_categories_action = QtWidgets.QAction("Manage Categories", self)
        manage_categories_action.triggered.connect(self._open_categories)
        toolbar.addAction(manage_categories_action)

        create_account_action = QtWidgets.QAction("Create Account", self)
        create_account_action.triggered.connect(self._open_account_creation)
        create_account_action.setEnabled(self._is_admin())
        toolbar.addAction(create_account_action)

        change_password_action = QtWidgets.QAction("Change Password", self)
        change_password_action.triggered.connect(self._open_change_password)
        toolbar.addAction(change_password_action)

        toolbar.addSeparator()
        spacer = QtWidgets.QWidget()
        spacer.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        toolbar.addWidget(spacer)
        audit_log_action = QtWidgets.QAction("Audit Log", self)
        audit_log_action.triggered.connect(self._open_audit_log)
        toolbar.addAction(audit_log_action)
        settings_action = QtWidgets.QAction("Settings", self)
        settings_action.triggered.connect(self._open_settings)
        toolbar.addAction(settings_action)

        header = QtWidgets.QLabel(f"Welcome, {username}.")
        header.setStyleSheet("font-size: 16px; font-weight: 600;")

        self.search_input = QtWidgets.QLineEdit()
        self.search_input.setPlaceholderText("Search policies...")
        self.search_input.textChanged.connect(self._refresh_policies)

        self.category_filter = QtWidgets.QComboBox()
        self.category_filter.setMinimumWidth(160)
        self.category_filter.currentIndexChanged.connect(self._refresh_policies)

        self.traffic_filter = QtWidgets.QComboBox()
        self.traffic_filter.addItems(["All", "In Date", "Review Due", "Past Review Date"])
        self.traffic_filter.currentIndexChanged.connect(self._refresh_policies)

        self.status_filter = QtWidgets.QComboBox()
        self.status_filter.addItems(["All Statuses", "Draft", "Active", "Withdrawn", "Missing", "Archived"])
        self.status_filter.currentIndexChanged.connect(self._refresh_policies)

        self.ratified_filter = QtWidgets.QComboBox()
        self.ratified_filter.addItems(["All", "Ratified", "Not Ratified"])
        self.ratified_filter.currentIndexChanged.connect(self._refresh_policies)

        filter_row = QtWidgets.QHBoxLayout()
        filter_row.addWidget(self.search_input, 2)
        filter_row.addWidget(self.category_filter, 1)
        filter_row.addWidget(self.traffic_filter, 1)
        filter_row.addWidget(self.status_filter, 1)
        filter_row.addWidget(self.ratified_filter, 1)

        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            [
                "Category",
                "Title",
                "Status",
                "Current Version",
                "Review Due",
                "Days Remaining",
                "Ratified",
            ]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table_font = self.table.font()
        table_font.setPointSize(9)
        table_font.setBold(True)
        self.table.setFont(table_font)
        self.table.setStyleSheet(
            "QTableWidget::item { color: black;}"
            "QTableWidget::item:selected { background-color: blue; color: white;}"
        )


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
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.addTab(dashboard, "Dashboard")
        self.policy_detail_index = self.tabs.addTab(policy_detail, "Policy Detail")
        self.policy_distributor_index = self.tabs.addTab(email_compose, "Policy Distributor")
        self.tabs.currentChanged.connect(self._on_tab_changed)

        self.audit_dialog = self._build_audit_dialog()
        self.settings_dialog = self._build_settings_dialog()

        container = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(container)
        layout.addWidget(self.tabs)
        self.setCentralWidget(container)

        self._refresh_categories()
        self._refresh_policies()
        self._load_settings()
        self._load_audit_log()
        self._run_startup_policy_checks()

    def _run_startup_policy_checks(self) -> None:
        """Repair paths and flag missing or altered policy files on launch."""

        missing, altered = scan_policy_file_integrity(self.conn)
        if not missing and not altered:
            return
        message_lines = [
            "Policy file checks found issues. See the audit log for details.",
            "",
        ]
        if missing:
            message_lines.append("Missing policy files:")
            message_lines.extend(
                f"- {item['title']} (v{item['version']}): {item['path']}" for item in missing
            )
            message_lines.append("")
        if altered:
            message_lines.append("Modified policy files detected (hash mismatch):")
            message_lines.extend(
                f"- {item['title']} (v{item['version']}): {item['path']}" for item in altered
            )
        QtWidgets.QMessageBox.warning(self, "Policy File Issues", "\n".join(message_lines))
        for item in missing:
            dialog = QtWidgets.QMessageBox(self)
            dialog.setWindowTitle("Policy File Missing")
            dialog.setText(
                "A policy file could not be found.\n\n"
                f"{item['title']} (v{item['version']})\n"
                f"Stored path: {item['path']}\n\n"
                "Locate the original file to restore it and verify the checksum."
            )
            backup_button = None
            if policy_backup_available(self.conn, int(item["version_id"])):
                backup_button = dialog.addButton(
                    "Restore from Backup",
                    QtWidgets.QMessageBox.ActionRole,
                )
            locate_button = dialog.addButton("Locate Missing File", QtWidgets.QMessageBox.AcceptRole)
            skip_button = dialog.addButton("Skip", QtWidgets.QMessageBox.RejectRole)
            dialog.exec()
            clicked = dialog.clickedButton()
            if backup_button and clicked == backup_button:
                try:
                    restore_policy_from_backup(self.conn, int(item["version_id"]), "missing")
                except ValueError as exc:
                    QtWidgets.QMessageBox.warning(self, "Restore Failed", str(exc))
            elif clicked == locate_button:
                file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
                    self,
                    "Select Missing Policy File",
                )
                if file_path:
                    try:
                        restore_missing_policy_file(
                            self.conn,
                            int(item["version_id"]),
                            Path(file_path),
                        )
                    except ValueError as exc:
                        QtWidgets.QMessageBox.warning(self, "Restore Failed", str(exc))
            elif clicked == skip_button:
                continue
        for item in altered:
            dialog = QtWidgets.QMessageBox(self)
            dialog.setWindowTitle("Policy Integrity Mismatch")
            dialog.setText(
                "A policy file has changed since it was recorded.\n\n"
                f"{item['title']} (v{item['version']})\n"
                f"Stored path: {item['path']}\n\n"
                "Choose how to resolve this mismatch."
            )
            backup_button = None
            if policy_backup_available(self.conn, int(item["version_id"])):
                backup_button = dialog.addButton(
                    "Restore from Backup",
                    QtWidgets.QMessageBox.ActionRole,
                )
            locate_button = dialog.addButton("Locate Original File", QtWidgets.QMessageBox.AcceptRole)
            replace_button = dialog.addButton(
                "Create Replacement Version", QtWidgets.QMessageBox.DestructiveRole
            )
            skip_button = dialog.addButton("Skip", QtWidgets.QMessageBox.RejectRole)
            dialog.exec()
            clicked = dialog.clickedButton()
            if backup_button and clicked == backup_button:
                try:
                    restore_policy_from_backup(self.conn, int(item["version_id"]), "hash_mismatch")
                except ValueError as exc:
                    QtWidgets.QMessageBox.warning(self, "Restore Failed", str(exc))
            elif clicked == locate_button:
                file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
                    self,
                    "Select Original Policy File",
                )
                if file_path:
                    try:
                        restore_policy_version_file(
                            self.conn,
                            int(item["version_id"]),
                            Path(file_path),
                        )
                    except ValueError as exc:
                        QtWidgets.QMessageBox.warning(self, "Restore Failed", str(exc))
            elif clicked == replace_button:
                response = QtWidgets.QMessageBox.question(
                    self,
                    "Create Replacement Version",
                    "This will mark the original version as missing and create a new version "
                    "from the current file on disk. Continue?",
                )
                if response != QtWidgets.QMessageBox.Yes:
                    continue
                self._append_audit_event(
                    "policy_file_replacement_accepted",
                    "policy_version",
                    int(item["version_id"]),
                    f"title={item['title']} version={item['version']}",
                )
                replacement_path = Path(item["path"])
                if not replacement_path.exists():
                    file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
                        self,
                        "Select Replacement Policy File",
                    )
                    if not file_path:
                        continue
                    replacement_path = Path(file_path)
                try:
                    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
                    original_status_row = self.conn.execute(
                        """
                        SELECT status, ratified, ratified_at, ratified_by_user_id
                        FROM policy_versions
                        WHERE id = ?
                        """,
                        (int(item["version_id"]),),
                    ).fetchone()
                    original_status = (original_status_row["status"] if original_status_row else None) or "Draft"
                    new_version_id = add_policy_version(
                        self.conn,
                        int(item["policy_id"]),
                        replacement_path,
                        None,
                        {"notes": "", "status": original_status},
                    )
                    self._append_audit_event(
                        "policy_version_status_copied",
                        "policy_version",
                        new_version_id,
                        f"copied_from_version={item['version_id']} status={original_status}",
                    )
                    if original_status_row and original_status_row["ratified"]:
                        self.conn.execute(
                            """
                            UPDATE policy_versions
                            SET ratified = 1, ratified_at = ?, ratified_by_user_id = ?
                            WHERE id = ?
                            """,
                            (
                                original_status_row["ratified_at"],
                                original_status_row["ratified_by_user_id"],
                                new_version_id,
                            ),
                        )
                        self.conn.commit()
                        audit.append_event_log(
                            self.conn,
                            {
                                "occurred_at": datetime.utcnow().isoformat(),
                                "actor": self._resolve_audit_actor(),
                                "action": "policy_version_ratification_copied",
                                "entity_type": "policy_version",
                                "entity_id": new_version_id,
                                "details": (
                                    f"copied_from_version={item['version_id']} "
                                    f"ratified_at={original_status_row['ratified_at']} "
                                    f"ratified_by_user_id={original_status_row['ratified_by_user_id']}"
                                ),
                            },
                        )
                    new_version_row = self.conn.execute(
                        "SELECT version_number FROM policy_versions WHERE id = ?",
                        (new_version_id,),
                    ).fetchone()
                    replacement_number = (
                        int(new_version_row["version_number"]) if new_version_row else None
                    )
                    replacement_note = format_replacement_note(
                        int(item["version"]),
                        replacement_number,
                        timestamp,
                        "policy integrity mismatch",
                    )
                    update_policy_version_notes(self.conn, new_version_id, replacement_note)
                    details = (
                        f"title={item['title']} "
                        f"version={item['version']} "
                        f"path={item['path']}"
                    )
                    mark_policy_version_missing(
                        self.conn,
                        int(item["version_id"]),
                        details,
                        replacement_version_number=replacement_number,
                        replacement_note=replacement_note,
                        replacement_version_id=new_version_id,
                    )
                    self._refresh_policies(clear_selection=False)
                except ValueError as exc:
                    QtWidgets.QMessageBox.warning(self, "Replacement Failed", str(exc))
            elif clicked == skip_button:
                continue
        self._load_audit_log()

    def _refresh_categories(self) -> None:
        """Refresh category filter options from the database."""

        categories = ["All Categories"] + list_categories(self.conn)
        self.category_filter.blockSignals(True)
        self.category_filter.clear()
        self.category_filter.addItems(categories)
        self.category_filter.blockSignals(False)

    def _refresh_policies(self, clear_selection: bool = True) -> None:
        """Refresh the policy table using the current filter settings."""

        policies = list_policies(self.conn)
        filtered = []
        search_text = self.search_input.text().strip().lower()
        category = self.category_filter.currentText()
        traffic = self.traffic_filter.currentText()
        status = self.status_filter.currentText()
        ratified_filter = self.ratified_filter.currentText()
        selected_policy_id = self.current_policy_id

        for policy in policies:
            if search_text and search_text not in policy.title.lower():
                continue
            if category != "All Categories" and policy.category != category:
                continue
            if traffic != "All":
                if traffic == "In Date" and policy.traffic_status != "Green":
                    continue
                if traffic == "Review Due" and policy.traffic_status != "Amber":
                    continue
                if traffic == "Past Review Date" and policy.traffic_status != "Red":
                    continue
            if status != "All Statuses" and policy.status != status:
                continue
            if ratified_filter == "Ratified" and not policy.ratified:
                continue
            if ratified_filter == "Not Ratified" and policy.ratified:
                continue
            filtered.append(policy)

        self.table.setRowCount(len(filtered))
        for row_index, policy in enumerate(filtered):
            category_item = QtWidgets.QTableWidgetItem(policy.category)
            title_item = QtWidgets.QTableWidgetItem(policy.title)
            if policy.current_version_id:
                status_item = QtWidgets.QTableWidgetItem(policy.status or "")
                current_version_item = QtWidgets.QTableWidgetItem(
                    str(policy.current_version_number) if policy.current_version_number else ""
                )
                is_draft = (policy.status or "").lower() == "draft"
                review_due_item = QtWidgets.QTableWidgetItem(
                    "" if is_draft else self._format_date_display(policy.review_due_date)
                )
                days_remaining_item = QtWidgets.QTableWidgetItem(
                    "" if is_draft else self._format_days_remaining(policy.review_due_date)
                )
                ratified_item = QtWidgets.QTableWidgetItem("Yes" if policy.ratified else "No")
            else:
                status_item = QtWidgets.QTableWidgetItem("")
                current_version_item = QtWidgets.QTableWidgetItem("")
                review_due_item = QtWidgets.QTableWidgetItem("")
                days_remaining_item = QtWidgets.QTableWidgetItem("")
                ratified_item = QtWidgets.QTableWidgetItem("")
            items = [
                category_item,
                title_item,
                status_item,
                current_version_item,
                review_due_item,
                days_remaining_item,
                ratified_item,
            ]
            for column, item in enumerate(items):
                self.table.setItem(row_index, column, item)
            if policy.current_version_id:
                self._apply_traffic_row_color(row_index, policy.traffic_status, policy.traffic_reason)
            else:
                self._apply_no_current_row_color(row_index)
            self.table.item(row_index, 0).setData(QtCore.Qt.UserRole, policy.id)

        self.table_stack.setCurrentIndex(1 if filtered else 0)
        if clear_selection:
            self.table.clearSelection()
            self.current_policy_id = None
        elif selected_policy_id:
            if not self._select_policy_row_by_id(selected_policy_id):
                self.table.clearSelection()
                self.current_policy_id = None

    def _on_policy_selected(self) -> None:
        """Load the policy detail panel when the table selection changes."""

        selected = self.table.selectionModel().selectedRows()
        if not selected:
            return
        policy_id = self.table.item(selected[0].row(), 0).data(QtCore.Qt.UserRole)
        self.current_policy_id = policy_id
        self._load_policy_detail(policy_id)

    def _open_settings(self) -> None:
        """Open the settings dialog."""

        self._load_settings()
        self.settings_dialog.show()
        self.settings_dialog.raise_()
        self.settings_dialog.activateWindow()

    def _open_audit_log(self) -> None:
        """Open the audit log dialog."""

        self._load_audit_log()
        self.audit_dialog.show()
        self.audit_dialog.raise_()
        self.audit_dialog.activateWindow()

    def _select_version_row_by_id(self, version_id: int) -> bool:
        """Select a version row based on the version ID."""

        for row_index in range(self.version_table.rowCount()):
            row_version_id = self.version_table.item(row_index, 0).data(QtCore.Qt.UserRole)
            if row_version_id == version_id:
                self.version_table.selectRow(row_index)
                return True
        return False

    def _select_policy_row_by_id(self, policy_id: int) -> bool:
        """Select a policy row based on the policy ID."""

        for row_index in range(self.table.rowCount()):
            row_policy_id = self.table.item(row_index, 0).data(QtCore.Qt.UserRole)
            if row_policy_id == policy_id:
                self.table.selectRow(row_index)
                return True
        return False

    def _on_tab_changed(self, index: int) -> None:
        """React to tab changes to enforce selection rules."""

        if index == self.policy_detail_index:
            selection = self.table.selectionModel().selectedRows()
            if not selection:
                self._block_policy_detail_tab()
                return
            if not self.current_policy_id:
                self._block_policy_detail_tab()
                return
        if index == self.policy_distributor_index:
            self._load_send_policies()

    def _block_policy_detail_tab(self) -> None:
        """Return to the dashboard when a policy is not selected."""

        self.tabs.blockSignals(True)
        self.tabs.setCurrentIndex(0)
        self.tabs.blockSignals(False)
        QtWidgets.QMessageBox.warning(self, "Select Policy", "Select a policy first.")

    def _load_user_context(self) -> None:
        """Load the current user's metadata for role-aware actions."""

        row = self.conn.execute(
            "SELECT id, role FROM users WHERE username = ?",
            (self.username,),
        ).fetchone()
        if row:
            self.user_id = row["id"]
            self.user_role = row["role"]

    def _is_admin(self) -> bool:
        """Return True if the current user is an admin."""

        return (self.user_role or "").lower() == "admin"

    def _open_account_creation(self) -> None:
        """Open the account creation dialog for admins."""

        if not self._is_admin():
            QtWidgets.QMessageBox.warning(self, "Restricted", "Only admins can create accounts.")
            return
        dialog = AccountCreationDialog(self.conn, self.user_id, self)
        dialog.exec()

    def _open_change_password(self) -> None:
        """Open the change password dialog for the current user."""

        if self.user_id is None:
            QtWidgets.QMessageBox.warning(self, "Unavailable", "User account not found.")
            return
        dialog = PasswordChangeDialog(self.conn, self.user_id, self.username, self)
        dialog.exec()

    def _open_categories(self) -> None:
        """Open the category management dialog and refresh data."""

        def _refresh_categories_and_audit() -> None:
            self._refresh_categories()
            self._load_audit_log()

        dialog = CategoryManagerDialog(self.conn, _refresh_categories_and_audit, self)
        dialog.exec()
        self._refresh_policies(clear_selection=False)
        self._load_policy_detail(self.current_policy_id)
        self._load_audit_log()

    def _open_new_policy(self) -> None:
        """Open the new policy dialog and refresh data."""

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
        self._load_audit_log()

    def _load_policy_detail(self, policy_id: int) -> None:
        """Load policy details and version history for the selected policy."""

        selected_version_id = None
        selection = self.version_table.selectionModel().selectedRows()
        if selection:
            selected_version_id = self.version_table.item(selection[0].row(), 0).data(QtCore.Qt.UserRole)

        policy = self.conn.execute(
            "SELECT * FROM policies WHERE id = ?",
            (policy_id,),
        ).fetchone()
        if not policy:
            return
        self._current_policy_title = policy["title"] or ""
        self._current_policy_category = policy["category"] or ""
        self.detail_status.blockSignals(True)
        self.detail_review_due.blockSignals(True)
        self.detail_review_frequency.blockSignals(True)
        self.detail_notes.blockSignals(True)
        self.detail_title.blockSignals(True)
        self.detail_category.blockSignals(True)
        self.detail_owner.blockSignals(True)
        self._populate_category_options(self._current_policy_category)
        self._clear_policy_metadata_fields()
        self._populate_owner_options(None)
        self.detail_status.blockSignals(False)
        self.detail_review_due.blockSignals(False)
        self.detail_review_frequency.blockSignals(False)
        self.detail_notes.blockSignals(False)
        self.detail_category.blockSignals(False)
        self.detail_title.blockSignals(False)
        self.detail_owner.blockSignals(False)
        self._notes_dirty = False
        self._title_dirty = False

        versions = list_versions(self.conn, policy_id)
        headers = ["Created", "Version", "Current", "Ratified", "Status", "File Name", "Size", "Hash"]
        self.version_table.clearContents()
        self.version_table.setColumnCount(len(headers))
        self.version_table.setHorizontalHeaderLabels(headers)
        self.version_table.setRowCount(len(versions))
        for row_index, version in enumerate(versions):
            integrity_issue = False
            issue_reason = ""
            if version.get("file_path"):
                resolved_path = resolve_version_file_path(
                    self.conn,
                    version["id"],
                    version["file_path"],
                )
                if not resolved_path:
                    integrity_issue = True
                    issue_reason = "Missing file"
                else:
                    current_hash = file_sha256(resolved_path)
                    if current_hash != version["sha256_hash"]:
                        integrity_issue = True
                        issue_reason = "Hash mismatch"
            is_current = policy["current_version_id"] == version["id"]
            created_item = QtWidgets.QTableWidgetItem(
                self._format_datetime_display(version["created_at"])
            )
            version_item = QtWidgets.QTableWidgetItem(str(version["version_number"]))
            current_item = QtWidgets.QTableWidgetItem("Current" if is_current else "Not Current")
            ratified_value = "Yes" if int(version["ratified"] or 0) else "No"
            ratified_item = QtWidgets.QTableWidgetItem(ratified_value)
            status_item = QtWidgets.QTableWidgetItem(version["status"] or "")
            stored_filename = ""
            if version.get("file_path"):
                stored_filename = Path(version["file_path"]).name
            filename_item = QtWidgets.QTableWidgetItem(
                stored_filename or version["original_filename"] or ""
            )
            size_item = QtWidgets.QTableWidgetItem(
                self._format_file_size(version["file_size_bytes"])
            )
            hash_item = QtWidgets.QTableWidgetItem(version["sha256_hash"])
            items = [
                created_item,
                version_item,
                current_item,
                ratified_item,
                status_item,
                filename_item,
                size_item,
                hash_item,
            ]
            for column, item in enumerate(items):
                self.version_table.setItem(row_index, column, item)
                if integrity_issue:
                    item.setForeground(QtGui.QColor("#9ca3af"))
                    item.setToolTip(f"Integrity issue: {issue_reason}")
            self.version_table.item(row_index, 0).setData(QtCore.Qt.UserRole, version["id"])
            self.version_table.item(row_index, 0).setData(QtCore.Qt.UserRole + 1, issue_reason)
        selected = False
        if selected_version_id:
            selected = self._select_version_row_by_id(selected_version_id)
        if not selected and policy["current_version_id"]:
            selected = self._select_version_row_by_id(policy["current_version_id"])
        if selected:
            version_id = self.version_table.item(self.version_table.currentRow(), 0).data(QtCore.Qt.UserRole)
            self._load_policy_reviews(version_id)
        else:
            self._clear_policy_reviews()

    def _load_policy_reviews(self, policy_version_id: int) -> None:
        """Load review history for the selected policy version."""

        reviews = list_policy_reviews(self.conn, policy_version_id)
        self._latest_reviewed_at = reviews[0]["reviewed_at"] if reviews else None
        self.detail_last_reviewed.setText(
            self._format_review_date_display(self._latest_reviewed_at or "")
        )
        self.review_table.setRowCount(len(reviews))
        for row_index, review in enumerate(reviews):
            reviewed_at = self._format_review_date_display(review["reviewed_at"] or "")
            reviewed_by = review.get("reviewed_by") or ""
            version_number = review.get("version_number")
            version_label = f"v{version_number}" if version_number is not None else ""
            notes = review.get("notes") or ""
            self.review_table.setItem(row_index, 0, QtWidgets.QTableWidgetItem(reviewed_at))
            self.review_table.setItem(row_index, 1, QtWidgets.QTableWidgetItem(reviewed_by))
            self.review_table.setItem(row_index, 2, QtWidgets.QTableWidgetItem(version_label))
            self.review_table.setItem(row_index, 3, QtWidgets.QTableWidgetItem(notes))

    def _clear_policy_reviews(self) -> None:
        """Clear review history table."""

        self.review_table.setRowCount(0)
        self._latest_reviewed_at = None
        self.detail_last_reviewed.setText("")

    def _prompt_policy_review(self) -> dict | None:
        """Prompt for review details when recording a no-change review."""

        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("Record Review (No Changes)")
        layout = QtWidgets.QVBoxLayout(dialog)

        form = QtWidgets.QFormLayout()
        review_date = QtWidgets.QDateEdit(QtCore.QDate.currentDate())
        review_date.setCalendarPopup(True)
        review_date.setDisplayFormat("dd/MM/yyyy")
        notes_input = QtWidgets.QPlainTextEdit()

        form.addRow("Review Date", review_date)
        form.addRow("Notes", notes_input)
        layout.addLayout(form)

        button_row = QtWidgets.QHBoxLayout()
        save_button = QtWidgets.QPushButton("Save")
        cancel_button = QtWidgets.QPushButton("Cancel")
        save_button.clicked.connect(dialog.accept)
        cancel_button.clicked.connect(dialog.reject)
        button_row.addStretch(1)
        button_row.addWidget(save_button)
        button_row.addWidget(cancel_button)
        layout.addLayout(button_row)

        if dialog.exec() != QtWidgets.QDialog.Accepted:
            return None
        return {
            "reviewed_at": review_date.date().toString("yyyy-MM-dd"),
            "notes": notes_input.toPlainText().strip() or None,
        }

    def _record_policy_review(self) -> None:
        """Record a review without creating a new policy version."""

        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
            QtWidgets.QMessageBox.warning(
                self,
                "Select Version",
                "Select a policy version before recording a review.",
            )
            return
        if self._selected_version_integrity_issue():
            QtWidgets.QMessageBox.warning(
                self,
                "Integrity Issue",
                "Resolve the file integrity issue before recording a review.",
            )
            return
        version_id = self.version_table.item(selection[0].row(), 0).data(QtCore.Qt.UserRole)
        version_row = self.conn.execute(
            "SELECT status FROM policy_versions WHERE id = ?",
            (version_id,),
        ).fetchone()
        if version_row and (version_row["status"] or "").lower() == "draft":
            QtWidgets.QMessageBox.warning(
                self,
                "Review Not Allowed",
                "Draft policies can only be reviewed when activated.",
            )
            return
        if version_row and (version_row["status"] or "").lower() == "missing":
            QtWidgets.QMessageBox.warning(
                self,
                "Missing Policy",
                "This policy is marked as missing and cannot be reviewed.",
            )
            return
        review_details = self._prompt_policy_review()
        if not review_details:
            return
        add_policy_review(
            self.conn,
            version_id,
            self.user_id,
            review_details["reviewed_at"],
            review_details["notes"],
        )
        self._load_policy_reviews(version_id)
        if self.current_policy_id:
            self._load_policy_detail(self.current_policy_id)
            if self._select_version_row_by_id(version_id):
                self._on_version_selected()
            self._load_policy_reviews(version_id)
            self._refresh_policies(clear_selection=False)
        self._load_audit_log()

    def _upload_version(self) -> None:
        """Prompt for a file and add a policy version."""

        if not self.current_policy_id:
            QtWidgets.QMessageBox.warning(self, "Select Policy", "Select a policy first.")
            return
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Policy File")
        if not file_path:
            return
        metadata = self._prompt_version_metadata()
        if metadata is None:
            return
        try:
            add_policy_version(self.conn, self.current_policy_id, Path(file_path), None, metadata)
        except ValueError as exc:
            QtWidgets.QMessageBox.warning(self, "No Change", str(exc))
            return
        self._load_policy_detail(self.current_policy_id)
        self._refresh_policies(clear_selection=False)
        self._load_audit_log()

    def _mark_ratified(self) -> None:
        """Mark the selected version as ratified."""

        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
            return
        if self._selected_version_integrity_issue():
            QtWidgets.QMessageBox.warning(
                self,
                "Integrity Issue",
                "Resolve the file integrity issue before modifying this version.",
            )
            return
        if (
            QtWidgets.QMessageBox.question(
                self,
                "Confirm",
                "Mark selected version as ratified?",
            )
            != QtWidgets.QMessageBox.Yes
        ):
            return
        version_id = self.version_table.item(selection[0].row(), 0).data(QtCore.Qt.UserRole)
        mark_version_ratified(self.conn, version_id, self.user_id)
        if self.current_policy_id:
            self._load_policy_detail(self.current_policy_id)
            self._select_version_row_by_id(version_id)
            self._refresh_policies(clear_selection=False)
            self._load_audit_log()

    def _mark_unratified(self) -> None:
        """Mark the selected version as not ratified."""

        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
            return
        if self._selected_version_integrity_issue():
            QtWidgets.QMessageBox.warning(
                self,
                "Integrity Issue",
                "Resolve the file integrity issue before modifying this version.",
            )
            return
        if (
            QtWidgets.QMessageBox.question(
                self,
                "Confirm",
                "Mark selected version as not ratified?",
            )
            != QtWidgets.QMessageBox.Yes
        ):
            return
        version_id = self.version_table.item(selection[0].row(), 0).data(QtCore.Qt.UserRole)
        unmark_version_ratified(self.conn, version_id)
        if self.current_policy_id:
            self._load_policy_detail(self.current_policy_id)
            self._select_version_row_by_id(version_id)
            self._refresh_policies(clear_selection=False)
            self._load_audit_log()

    def _set_current(self) -> None:
        """Set the selected version as the current policy version."""

        if not self.current_policy_id:
            return
        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
            return
        if self._selected_version_integrity_issue():
            QtWidgets.QMessageBox.warning(
                self,
                "Integrity Issue",
                "Resolve the file integrity issue before modifying this version.",
            )
            return
        if (
            QtWidgets.QMessageBox.question(
                self,
                "Confirm",
                "Set selected version as current?",
            )
            != QtWidgets.QMessageBox.Yes
        ):
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
        self._load_policy_detail(self.current_policy_id)
        self._refresh_policies(clear_selection=False)
        self._load_audit_log()
        self._load_send_policies()

    def _set_not_current(self) -> None:
        """Unset the current policy version."""

        if not self.current_policy_id:
            return
        selection = self.version_table.selectionModel().selectedRows()
        selected_version_id = None
        if selection:
            selected_version_id = self.version_table.item(selection[0].row(), 0).data(
                QtCore.Qt.UserRole
            )
        if self._selected_version_integrity_issue():
            QtWidgets.QMessageBox.warning(
                self,
                "Integrity Issue",
                "Resolve the file integrity issue before modifying this version.",
            )
            return
        if (
            QtWidgets.QMessageBox.question(
                self,
                "Confirm",
                "Clear the current version selection?",
            )
            != QtWidgets.QMessageBox.Yes
        ):
            return
        unset_current_version(self.conn, self.current_policy_id)
        self._load_policy_detail(self.current_policy_id)
        if selected_version_id is not None:
            self._select_version_row_by_id(selected_version_id)
        self._refresh_policies(clear_selection=False)
        self._load_audit_log()
        self._load_send_policies()

    def _open_file_location(self) -> None:
        """Open the current version file in the OS file manager."""

        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
            return
        if self._selected_version_integrity_issue():
            QtWidgets.QMessageBox.warning(
                self,
                "Integrity Issue",
                "Resolve the file integrity issue before opening this file.",
            )
            return
        version_id = self.version_table.item(selection[0].row(), 0).data(QtCore.Qt.UserRole)
        file_path = get_version_file(self.conn, version_id)
        resolved_path = resolve_version_file_path(self.conn, version_id, file_path)
        if not resolved_path:
            row = self.conn.execute(
                """
                SELECT p.title, v.version_number, v.file_path
                FROM policy_versions v
                JOIN policies p ON p.id = v.policy_id
                WHERE v.id = ?
                """,
                (version_id,),
            ).fetchone()
            if row:
                audit.append_event_log(
                    self.conn,
                    {
                        "occurred_at": datetime.utcnow().isoformat(),
                        "actor": self._resolve_audit_actor(),
                        "action": "policy_file_missing",
                        "entity_type": "policy_version",
                        "entity_id": version_id,
                        "details": (
                            f"title={row['title']} "
                            f"version={row['version_number']} "
                            f"path={row['file_path']}"
                        ),
                    },
                )
                self.conn.commit()
            QtWidgets.QMessageBox.warning(
                self,
                "Missing File",
                "The policy file could not be found. Please confirm the policy root folder.",
            )
            self._load_audit_log()
            return
        QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(resolved_path)))

    def _print_policy_document(self) -> None:
        """Send the current version file to the default printer."""

        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
            return
        if self._selected_version_integrity_issue():
            QtWidgets.QMessageBox.warning(
                self,
                "Integrity Issue",
                "Resolve the file integrity issue before printing this version.",
            )
            return
        version_id = self.version_table.item(selection[0].row(), 0).data(QtCore.Qt.UserRole)
        file_path = get_version_file(self.conn, version_id)
        resolved_path = resolve_version_file_path(self.conn, version_id, file_path)
        if not resolved_path:
            QtWidgets.QMessageBox.warning(
                self,
                "Missing File",
                "The policy file could not be found. Please confirm the policy root folder.",
            )
            return
        try:
            if hasattr(os, "startfile"):
                os.startfile(str(resolved_path), "print")
            else:
                subprocess.run(["lpr", str(resolved_path)], check=False)
        except OSError as exc:
            QtWidgets.QMessageBox.warning(
                self,
                "Print Failed",
                f"Unable to print this policy file: {exc}",
            )

    def _on_version_selected(self) -> None:
        """Populate metadata controls for the selected version."""

        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
            self._clear_policy_metadata_fields()
            self._clear_policy_reviews()
            return
        integrity_issue = self._selected_version_integrity_issue()
        version_id = self.version_table.item(selection[0].row(), 0).data(QtCore.Qt.UserRole)
        version = self.conn.execute(
            """
            SELECT v.status,
                   v.review_due_date,
                   v.review_frequency_months,
                   v.notes,
                   v.owner,
                   v.ratified,
                   v.ratified_at,
                   u.username AS ratified_by
            FROM policy_versions v
            LEFT JOIN users u ON u.id = v.ratified_by_user_id
            WHERE v.id = ?
            """,
            (version_id,),
        ).fetchone()
        if not version:
            return
        is_missing_status = (version["status"] or "").lower() == "missing"
        self.detail_status.blockSignals(True)
        self.detail_review_due.blockSignals(True)
        self.detail_review_frequency.blockSignals(True)
        self.detail_notes.blockSignals(True)
        self.detail_title.blockSignals(True)
        self.detail_category.blockSignals(True)
        self.detail_owner.blockSignals(True)
        self.detail_title.setText(self._current_policy_title)
        self._populate_category_options(self._current_policy_category)
        self._populate_owner_options(version["owner"])
        self.detail_status.setCurrentText(version["status"] or "")
        self._set_date_field(
            self.detail_review_due,
            None if (version["status"] or "").lower() == "draft" else version["review_due_date"],
        )
        self.detail_review_due.setMaximumDate(QtCore.QDate(9999, 12, 31))
        if (version["status"] or "").lower() == "draft":
            self.detail_review_frequency.setCurrentIndex(-1)
        else:
            self._set_review_frequency_selection(version["review_frequency_months"])
        self.detail_notes.setPlainText(version["notes"] or "")
        self.detail_ratified.setText("Yes" if int(version["ratified"] or 0) else "No")
        self.detail_ratified_at.setText(self._format_datetime_display(version["ratified_at"] or ""))
        self.detail_ratified_by.setText(version["ratified_by"] or "")
        self._update_review_schedule_display()
        read_only = integrity_issue or is_missing_status
        self._set_policy_metadata_enabled(not read_only)
        self._apply_review_metadata_state(version["status"] or "", allow_edit=not read_only)
        self._set_version_action_state(not read_only)
        self.detail_status.blockSignals(False)
        self.detail_review_due.blockSignals(False)
        self.detail_review_frequency.blockSignals(False)
        self.detail_notes.blockSignals(False)
        self.detail_category.blockSignals(False)
        self.detail_title.blockSignals(False)
        self.detail_owner.blockSignals(False)
        self._notes_dirty = False
        self._title_dirty = False
        self._load_policy_reviews(version_id)

        if read_only:
            if is_missing_status:
                message = "This policy is missing and its details can no longer be edited."
                title = "Missing Policy"
            else:
                reason = self._selected_version_integrity_issue_reason()
                message = (
                    f"This version has an integrity issue: {reason}. Resolve it before editing."
                )
                title = "Integrity Issue"
            QtWidgets.QMessageBox.information(self, title, message)

    def _apply_traffic_row_color(self, row_index: int, status: str, reason: str) -> None:
        """Apply traffic-light color coding to a policy row."""

        color_map = {
            "Green": QtGui.QColor("#27f149"),
            "Amber": QtGui.QColor("#ffff1a"),
            "Red": QtGui.QColor("#e11d48"),
        }
        color = color_map.get(status)
        text_color = QtGui.QColor("#1f1f1f")
        for column in range(self.table.columnCount()):
            item = self.table.item(row_index, column)
            if not item:
                continue
            if color:
                item.setBackground(color)
                item.setForeground(text_color)
                item.setToolTip(reason)

    def _apply_no_current_row_color(self, row_index: int) -> None:
        """Apply a distinct color for policies without a current version."""

        text_color = QtGui.QColor("#1f1f1f")
        for column in range(self.table.columnCount()):
            item = self.table.item(row_index, column)
            if not item:
                continue
            item.setBackground(QtGui.QColor("#93c5fd"))
            item.setForeground(text_color)

    def _update_policy_field(self, field: str, value, *, confirm: bool = True) -> None:
        """Update a policy/version field with optional confirmation and audit logging."""

        if not self.current_policy_id:
            return
        if self._selected_version_is_missing():
            QtWidgets.QMessageBox.warning(
                self,
                "Missing Policy",
                "This policy is missing and its details can no longer be edited.",
            )
            return
        if self._selected_version_integrity_issue():
            QtWidgets.QMessageBox.warning(
                self,
                "Integrity Issue",
                "Resolve the file integrity issue before modifying this version.",
            )
            return
        selected = self.version_table.selectionModel().selectedRows()
        selected_version_id = None
        if selected:
            selected_version_id = self.version_table.item(selected[0].row(), 0).data(QtCore.Qt.UserRole)
        policy_row = self.conn.execute(
            "SELECT current_version_id FROM policies WHERE id = ?",
            (self.current_policy_id,),
        ).fetchone()
        if not policy_row:
            return
        current_version_id = selected_version_id or policy_row["current_version_id"]
        if current_version_id:
            current = self.conn.execute(
                f"SELECT {field} FROM policy_versions WHERE id = ?",
                (current_version_id,),
            ).fetchone()
        else:
            current = self.conn.execute(
                f"SELECT {field} FROM policies WHERE id = ?",
                (self.current_policy_id,),
            ).fetchone()
        if not current:
            return
        current_value = current[field]
        if current_value == value or (current_value is not None and str(current_value) == str(value)):
            return
        field_labels = {
            "status": "Status",
            "review_due_date": "Review Due",
            "review_frequency_months": "Review Frequency",
            "notes": "Notes",
        }
        label = field_labels.get(field, field)
        display_current = current_value
        display_value = value
        if field == "review_frequency_months":
            display_current = self._review_frequency_label(current_value)
            display_value = self._review_frequency_label(value)
        if confirm:
            response = QtWidgets.QMessageBox.question(
                self,
                "Confirm Change",
                f"Change {label} from {display_current} to {display_value}?",
            )
            if response != QtWidgets.QMessageBox.Yes:
                self._load_policy_detail(self.current_policy_id)
                return
        if current_version_id:
            self.conn.execute(
                f"UPDATE policy_versions SET {field} = ? WHERE id = ?",
                (value, current_version_id),
            )
        else:
            self.conn.execute(
                f"UPDATE policies SET {field} = ? WHERE id = ?",
                (value, self.current_policy_id),
            )
        self.conn.commit()
        audit.append_event_log(
            self.conn,
            {
                "occurred_at": datetime.utcnow().isoformat(),
                "actor": self._resolve_audit_actor(),
                "action": "update_policy_field",
                "entity_type": "policy_version" if current_version_id else "policy",
                "entity_id": current_version_id or self.current_policy_id,
                "details": f"{field}: {display_current} -> {display_value}",
            },
        )
        self._refresh_policies(clear_selection=False)
        self._load_policy_detail(self.current_policy_id)
        if current_version_id:
            self._select_version_row_by_id(current_version_id)
            self._load_policy_reviews(current_version_id)
        self._load_audit_log()

    def _format_file_size(self, size_bytes: int) -> str:
        """Format bytes into a human-readable size string."""

        if size_bytes < 1024:
            return f"{size_bytes} B"
        size_kb = size_bytes / 1024
        if size_kb < 1024:
            return f"{size_kb:.2f} KB"
        size_mb = size_kb / 1024
        if size_mb < 1024:
            return f"{size_mb:.2f} MB"
        size_gb = size_mb / 1024
        return f"{size_gb:.2f} GB"

    def _format_date_display(self, value: str) -> str:
        """Format an ISO date string for UI display."""

        if not value:
            return ""
        date_value = QtCore.QDate.fromString(value, "yyyy-MM-dd")
        if not date_value.isValid():
            return value
        return date_value.toString("dd/MM/yyyy")

    def _parse_date_value(self, value: str) -> date | None:
        """Parse a stored date string into a date object."""

        if not value:
            return None
        try:
            return datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError:
            return None

    def _add_months(self, source: date, months: int) -> date:
        """Add months to a date while keeping the day within month bounds."""

        month = source.month - 1 + months
        year = source.year + month // 12
        month = month % 12 + 1
        day = min(
            source.day,
            [
                31,
                29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28,
                31,
                30,
                31,
                30,
                31,
                31,
                30,
                31,
                30,
                31,
            ][month - 1],
        )
        return datetime(year, month, day).date()

    def _format_days_remaining(self, review_due_date: str | None) -> str:
        """Return a friendly days remaining label for a review due date."""

        if not review_due_date:
            return ""
        due_date = self._parse_date_value(review_due_date)
        if not due_date:
            return ""
        today = datetime.now().date()
        delta_days = (due_date - today).days
        if delta_days == 0:
            return "Due today"
        day_label = "day" if abs(delta_days) == 1 else "days"
        if delta_days < 0:
            return f"Overdue by {abs(delta_days)} {day_label}"
        return f"{delta_days} {day_label}"

    def _resolve_review_base_date(self) -> date:
        """Return the date to use as the base for next review calculations."""

        if self._latest_reviewed_at:
            parsed = self._parse_date_value(self._latest_reviewed_at)
            if parsed:
                return parsed
        return datetime.now().date()

    def _calculate_review_due_value(self, frequency: int | None, base_date: date | None = None) -> str:
        """Return a review due date based on last review and frequency."""

        base_date = base_date or self._resolve_review_base_date()
        if not frequency:
            return base_date.isoformat()
        review_due_date = self._add_months(base_date, int(frequency))
        return review_due_date.isoformat()

    def _populate_review_frequency_options(self, combo: QtWidgets.QComboBox) -> None:
        """Load review frequency choices into a combo box."""

        combo.clear()
        options = [
            ("Annual", 12),
            ("Biannual", 6),
            ("Quarterly", 3),
            ("Monthly", 1),
        ]
        for label, months in options:
            combo.addItem(label, months)

    def _set_review_frequency_selection(self, months: int | None) -> None:
        """Select the matching review frequency option."""

        index = self.detail_review_frequency.findData(months)
        if index == -1 and months:
            self.detail_review_frequency.addItem(f"Every {months} months", months)
            index = self.detail_review_frequency.findData(months)
        if index == -1:
            index = 0
        self.detail_review_frequency.setCurrentIndex(index)

    def _review_frequency_label(self, months: int | None) -> str:
        """Return a friendly label for a review frequency."""

        mapping = {12: "Annual", 6: "Biannual", 3: "Quarterly", 1: "Monthly"}
        if not months:
            return "None"
        return mapping.get(months, f"Every {months} months")

    def _update_review_schedule_display(self) -> None:
        """Refresh days remaining labels."""

        if (self.detail_status.currentText() or "").lower() == "draft":
            self.detail_review_days_remaining.setText("")
            return
        review_due_value = self._get_date_field_value(self.detail_review_due)
        self.detail_review_days_remaining.setText(self._format_days_remaining(review_due_value))

    def _apply_review_metadata_state(self, status: str, allow_edit: bool = True) -> None:
        """Adjust review metadata controls based on version status."""

        is_draft = (status or "").lower() == "draft"
        min_date = QtCore.QDate(1900, 1, 1)
        self.detail_review_due.setMinimumDate(min_date)
        if is_draft:
            self.detail_review_due.setEnabled(False)
            self.detail_review_due.setSpecialValueText("")
            self.detail_review_due.setDate(min_date)
            self.detail_review_due.setDisplayFormat(" ")
            self.detail_review_frequency.setCurrentIndex(-1)
            self.detail_review_frequency.setEnabled(False)
            return
        self.detail_review_due.setEnabled(allow_edit)
        self.detail_review_frequency.setEnabled(allow_edit)
        self.detail_review_due.setSpecialValueText("")
        if self._get_date_field_value(self.detail_review_due):
            self.detail_review_due.setDisplayFormat("dd/MM/yyyy")
        else:
            self.detail_review_due.setDisplayFormat(" ")

    def _format_datetime_display(self, value: str) -> str:
        """Format an ISO datetime string for UI display."""

        if not value:
            return ""
        date_value = QtCore.QDateTime.fromString(value, QtCore.Qt.ISODate)
        if not date_value.isValid():
            return value
        return date_value.date().toString("dd/MM/yyyy")

    def _format_review_date_display(self, value: str) -> str:
        """Format a review timestamp or date string for UI display."""

        if not value:
            return ""
        date_time = QtCore.QDateTime.fromString(value, QtCore.Qt.ISODate)
        if date_time.isValid():
            return date_time.date().toString("dd/MM/yyyy")
        return self._format_date_display(value)

    def _set_date_field(self, widget: QtWidgets.QDateEdit, value: str | None) -> None:
        """Configure a date widget with a stored date or blank state."""

        min_date = QtCore.QDate(1900, 1, 1)
        widget.setMinimumDate(min_date)
        if value:
            widget.setDisplayFormat("dd/MM/yyyy")
            widget.setDate(QtCore.QDate.fromString(value, "yyyy-MM-dd"))
        else:
            widget.setDate(min_date)
            widget.setSpecialValueText("")
            widget.setDisplayFormat(" ")

    def _get_date_field_value(self, widget: QtWidgets.QDateEdit) -> str:
        """Return the stored value for a date widget or an empty string."""

        min_date = QtCore.QDate(1900, 1, 1)
        if widget.date() == min_date and widget.displayFormat().strip() == "":
            return ""
        return widget.date().toString("yyyy-MM-dd")

    def eventFilter(self, obj: QtCore.QObject, event: QtCore.QEvent) -> bool:
        """Commit metadata edits when focus leaves editable widgets."""

        if obj is self.detail_notes and event.type() == QtCore.QEvent.FocusOut and self._notes_dirty:
            text_value = self.detail_notes.toPlainText().strip()
            self._notes_dirty = False
            self._update_policy_field("notes", text_value)
        if obj is self.detail_title and event.type() == QtCore.QEvent.FocusOut and self._title_dirty:
            title_value = self.detail_title.text().strip()
            self._title_dirty = False
            if title_value:
                self._update_policy_title(title_value)
        return super().eventFilter(obj, event)

    def _prompt_version_metadata(self) -> dict | None:
        """Prompt for status, owner, review, and notes when adding a version."""

        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("Version Metadata")
        layout = QtWidgets.QVBoxLayout(dialog)

        form = QtWidgets.QFormLayout()
        status_combo = QtWidgets.QComboBox()
        status_combo.addItems(["Draft", "Active", "Withdrawn", "Archived"])
        owner_combo = QtWidgets.QComboBox()
        owner_combo.setEditable(False)
        owner_combo.addItem("Unassigned", None)
        for owner in list_users(self.conn):
            if owner:
                owner_combo.addItem(owner, owner)
        review_due_date = QtWidgets.QDateEdit(QtCore.QDate.currentDate())
        review_due_date.setCalendarPopup(True)
        review_due_date.setDisplayFormat("dd/MM/yyyy")
        review_due_date.setMaximumDate(QtCore.QDate(9999, 12, 31))
        review_due_date.setReadOnly(True)
        review_due_date.setButtonSymbols(QtWidgets.QAbstractSpinBox.NoButtons)
        review_frequency = QtWidgets.QComboBox()
        self._populate_review_frequency_options(review_frequency)
        notes_input = QtWidgets.QPlainTextEdit()

        form.addRow("Status", status_combo)
        form.addRow("Owner", owner_combo)
        form.addRow("Review Due", review_due_date)
        form.addRow("Review Frequency", review_frequency)
        form.addRow("Notes", notes_input)
        layout.addLayout(form)

        button_row = QtWidgets.QHBoxLayout()
        save_button = QtWidgets.QPushButton("Save")
        cancel_button = QtWidgets.QPushButton("Cancel")
        save_button.clicked.connect(dialog.accept)
        cancel_button.clicked.connect(dialog.reject)
        button_row.addStretch(1)
        button_row.addWidget(save_button)
        button_row.addWidget(cancel_button)
        layout.addLayout(button_row)

        def auto_update_review_due() -> None:
            if not review_due_date.isEnabled():
                return
            frequency_value = review_frequency.currentData()
            base_date = QtCore.QDate.currentDate()
            if frequency_value:
                candidate = base_date.addMonths(int(frequency_value))
                review_due_date.setDate(candidate)
                return
            review_due_date.setDate(base_date)

        def update_metadata_state(status: str) -> None:
            is_draft = status == "Draft"
            min_date = QtCore.QDate(1900, 1, 1)
            review_due_date.setMinimumDate(min_date)
            if is_draft:
                review_due_date.setEnabled(False)
                review_due_date.setSpecialValueText("")
                review_due_date.setDate(min_date)
                review_due_date.setDisplayFormat(" ")
                review_due_date.setMaximumDate(QtCore.QDate(9999, 12, 31))
                review_frequency.setEnabled(False)
            else:
                review_due_date.setEnabled(True)
                review_due_date.setSpecialValueText("")
                review_due_date.setDisplayFormat("dd/MM/yyyy")
                if review_due_date.date() == min_date:
                    review_due_date.setDate(QtCore.QDate.currentDate())
                review_frequency.setEnabled(True)
                auto_update_review_due()
        status_combo.currentTextChanged.connect(update_metadata_state)
        review_frequency.currentIndexChanged.connect(auto_update_review_due)
        update_metadata_state(status_combo.currentText())

        if dialog.exec() != QtWidgets.QDialog.Accepted:
            return None
        return {
            "status": status_combo.currentText(),
            "owner": owner_combo.currentData(),
            "review_due_date": (
                ""
                if not review_due_date.isEnabled()
                else review_due_date.date().toString("yyyy-MM-dd")
            ),
            "review_frequency_months": review_frequency.currentData(),
            "notes": notes_input.toPlainText().strip() or None,
        }

    def _on_status_changed(self, status: str) -> None:
        """Handle status updates from the metadata form."""

        current_status = None
        current_version_id = None
        selected = self.version_table.selectionModel().selectedRows()
        if selected:
            version_id = self.version_table.item(selected[0].row(), 0).data(QtCore.Qt.UserRole)
            current_version_id = version_id
            version_row = self.conn.execute(
                "SELECT status FROM policy_versions WHERE id = ?",
                (version_id,),
            ).fetchone()
            if version_row:
                current_status = version_row["status"]
        elif self.current_policy_id:
            version_row = self.conn.execute(
                """
                SELECT v.id, v.status
                FROM policy_versions v
                JOIN policies p ON p.current_version_id = v.id
                WHERE p.id = ?
                """,
                (self.current_policy_id,),
            ).fetchone()
            if version_row:
                current_status = version_row["status"]
                current_version_id = version_row["id"]
        if (current_status or "").lower() == "active" and (status or "").lower() == "draft":
            QtWidgets.QMessageBox.warning(
                self,
                "Change Not Allowed",
                "Active policies cannot be changed back to Draft.",
            )
            if self.current_policy_id:
                self._load_policy_detail(self.current_policy_id)
            return
        if (current_status or "").lower() == "draft" and (status or "").lower() == "active":
            if self.user_id is None:
                QtWidgets.QMessageBox.warning(
                    self,
                    "Unavailable",
                    "User account not found. Unable to confirm status change.",
                )
                if self.current_policy_id:
                    self._load_policy_detail(self.current_policy_id)
                return
            password, ok = QtWidgets.QInputDialog.getText(
                self,
                "Confirm Password",
                "Enter your account password to activate this policy:",
                QtWidgets.QLineEdit.Password,
            )
            if not ok:
                if self.current_policy_id:
                    self._load_policy_detail(self.current_policy_id)
                return
            user_row = self.conn.execute(
                "SELECT password_hash, salt FROM users WHERE id = ?",
                (self.user_id,),
            ).fetchone()
            if not user_row or not security.verify_password(
                password,
                user_row["password_hash"],
                user_row["salt"],
            ):
                QtWidgets.QMessageBox.warning(self, "Invalid", "Password is incorrect.")
                if self.current_policy_id:
                    self._load_policy_detail(self.current_policy_id)
                return
            if self.current_policy_id and current_version_id:
                active_row = self.conn.execute(
                    """
                    SELECT id, version_number
                    FROM policy_versions
                    WHERE policy_id = ?
                      AND LOWER(status) = 'active'
                      AND id != ?
                    LIMIT 1
                    """,
                    (self.current_policy_id, current_version_id),
                ).fetchone()
                if active_row:
                    version_number = active_row["version_number"]
                    label = f"v{version_number}" if version_number is not None else "another version"
                    QtWidgets.QMessageBox.warning(
                        self,
                        "Change Not Allowed",
                        f"Only one active version is allowed. {label} is already active.",
                    )
                    if self.current_policy_id:
                        self._load_policy_detail(self.current_policy_id)
                    return
        self._update_policy_field("status", status)
        if (current_status or "").lower() == "draft" and (status or "").lower() == "active":
            if current_version_id:
                updated_status = self.conn.execute(
                    "SELECT status FROM policy_versions WHERE id = ?",
                    (current_version_id,),
                ).fetchone()
                if updated_status and (updated_status["status"] or "").lower() == "active":
                    reviewed_at = datetime.now().date().isoformat()
                    add_policy_review(
                        self.conn,
                        current_version_id,
                        self.user_id,
                        reviewed_at,
                        None,
                    )
                    if self.current_policy_id:
                        self._load_policy_detail(self.current_policy_id)
                        if self._select_version_row_by_id(current_version_id):
                            self._on_version_selected()
                        self._load_policy_reviews(current_version_id)
                        self._refresh_policies(clear_selection=False)
                        self._load_audit_log()
        self.detail_review_frequency.blockSignals(True)
        self.detail_review_due.blockSignals(True)
        self._apply_review_metadata_state(status, allow_edit=True)
        self.detail_review_due.blockSignals(False)
        self.detail_review_frequency.blockSignals(False)
        self._update_review_schedule_display()

    def _on_review_due_changed(self, value: QtCore.QDate) -> None:
        """Handle review due date updates from the metadata form."""

        if (self.detail_status.currentText() or "").lower() == "draft":
            return
        review_value = self._get_date_field_value(self.detail_review_due)
        self._update_policy_field("review_due_date", review_value)
        self._update_review_schedule_display()

    def _on_review_frequency_changed(self) -> None:
        """Handle review frequency updates from the metadata form."""

        if (self.detail_status.currentText() or "").lower() == "draft":
            return
        frequency_value = self.detail_review_frequency.currentData()
        self._update_policy_field("review_frequency_months", frequency_value)
        review_due_value = self._calculate_review_due_value(frequency_value)
        if review_due_value:
            self.detail_review_due.blockSignals(True)
            self.detail_review_due.setDate(QtCore.QDate.fromString(review_due_value, "yyyy-MM-dd"))
            self.detail_review_due.blockSignals(False)
            self._update_policy_field("review_due_date", review_due_value, confirm=False)
        self._update_review_schedule_display()

    def _mark_notes_dirty(self) -> None:
        """Track when notes are edited so updates can be saved on blur."""

        self._notes_dirty = True

    def _mark_title_dirty(self) -> None:
        """Track when the title is edited so updates can be saved on blur."""

        self._title_dirty = True

    def _update_policy_title(self, title: str) -> None:
        """Persist a policy title update with confirmation."""

        if not self.current_policy_id:
            return
        if self._selected_version_is_missing():
            QtWidgets.QMessageBox.warning(
                self,
                "Missing Policy",
                "This policy is missing and its details can no longer be edited.",
            )
            return
        policy_row = self.conn.execute(
            "SELECT title FROM policies WHERE id = ?",
            (self.current_policy_id,),
        ).fetchone()
        if not policy_row:
            return
        current_value = policy_row["title"]
        if current_value == title:
            return
        response = QtWidgets.QMessageBox.question(
            self,
            "Confirm Change",
            f"Change Title from {current_value} to {title}?",
        )
        if response != QtWidgets.QMessageBox.Yes:
            self._load_policy_detail(self.current_policy_id)
            return
        update_policy_title(self.conn, self.current_policy_id, title)
        self._refresh_policies(clear_selection=False)
        self._load_policy_detail(self.current_policy_id)
        self._load_audit_log()

    def _populate_category_options(self, selected: str | None) -> None:
        """Populate category options for the detail panel."""

        categories = list_categories(self.conn)
        if selected and selected not in categories:
            categories.append(selected)
        self.detail_category.clear()
        self.detail_category.addItems(categories)
        if selected:
            self.detail_category.setCurrentText(selected)
        else:
            self.detail_category.setCurrentIndex(-1)

    def _populate_owner_options(self, selected: str | None) -> None:
        """Populate owner options for the detail panel."""

        self._owner_refreshing = True
        owners = list_users(self.conn)
        if selected and selected not in owners:
            owners.append(selected)
        self.detail_owner.clear()
        self.detail_owner.addItem("Unassigned", None)
        for owner in owners:
            if owner:
                self.detail_owner.addItem(owner, owner)
        if selected:
            index = self.detail_owner.findData(selected)
        else:
            index = self.detail_owner.findData(None)
        self.detail_owner.setCurrentIndex(index if index >= 0 else 0)
        self._owner_refreshing = False

    def _set_policy_metadata_enabled(self, enabled: bool) -> None:
        """Enable or disable policy metadata fields."""

        self.detail_title.setEnabled(enabled)
        self.detail_category.setEnabled(enabled)
        self.detail_owner.setEnabled(enabled and self._is_admin())
        self.detail_status.setEnabled(enabled)
        self.detail_review_due.setEnabled(enabled)
        self.detail_review_frequency.setEnabled(enabled)
        self.detail_notes.setEnabled(enabled)
        self.detail_ratified.setEnabled(enabled)
        self.detail_ratified_at.setEnabled(enabled)
        self.detail_ratified_by.setEnabled(enabled)

    def _set_version_action_state(self, enabled: bool) -> None:
        """Enable or disable version-specific actions."""

        self.ratify_button.setEnabled(enabled)
        self.unratify_button.setEnabled(enabled)
        self.set_current_button.setEnabled(enabled)
        self.set_not_current_button.setEnabled(enabled)
        self.open_location_button.setEnabled(enabled)
        self.print_document_button.setEnabled(enabled)

    def _selected_version_integrity_issue_reason(self) -> str:
        """Return the integrity issue reason for the selected version, if any."""

        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
            return ""
        return self.version_table.item(selection[0].row(), 0).data(QtCore.Qt.UserRole + 1) or ""

    def _selected_version_integrity_issue(self) -> bool:
        """Return True if the selected version has a known integrity issue."""

        return bool(self._selected_version_integrity_issue_reason())

    def _selected_version_is_missing(self) -> bool:
        """Return True if the selected version has Missing status."""

        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
            return False
        version_id = self.version_table.item(selection[0].row(), 0).data(QtCore.Qt.UserRole)
        row = self.conn.execute(
            "SELECT status FROM policy_versions WHERE id = ?",
            (version_id,),
        ).fetchone()
        return bool(row and (row["status"] or "").lower() == "missing")

    def _clear_policy_metadata_fields(self) -> None:
        """Reset policy metadata fields when no version is selected."""

        self.detail_status.blockSignals(True)
        self.detail_review_due.blockSignals(True)
        self.detail_review_frequency.blockSignals(True)
        self.detail_notes.blockSignals(True)
        self.detail_title.blockSignals(True)
        self.detail_category.blockSignals(True)
        self.detail_owner.blockSignals(True)
        self._set_policy_metadata_enabled(False)
        self._set_version_action_state(False)
        self.detail_title.setText("")
        self.detail_status.setCurrentIndex(-1)
        self._set_date_field(self.detail_review_due, None)
        self.detail_review_frequency.setCurrentIndex(-1)
        self.detail_review_days_remaining.setText("")
        self.detail_notes.setPlainText("")
        self.detail_category.setCurrentIndex(-1)
        self.detail_owner.setCurrentIndex(-1)
        self.detail_ratified.setText("")
        self.detail_ratified_at.setText("")
        self.detail_ratified_by.setText("")
        self.detail_last_reviewed.setText("")
        self.detail_status.blockSignals(False)
        self.detail_review_due.blockSignals(False)
        self.detail_review_frequency.blockSignals(False)
        self.detail_notes.blockSignals(False)
        self.detail_category.blockSignals(False)
        self.detail_title.blockSignals(False)
        self.detail_owner.blockSignals(False)
        self._notes_dirty = False
        self._title_dirty = False

    def _on_owner_changed(self, owner: str) -> None:
        """Handle owner updates from the metadata form."""

        if self._owner_refreshing:
            return
        if not self.current_policy_id or not self._is_admin():
            return
        if self._selected_version_is_missing():
            QtWidgets.QMessageBox.warning(
                self,
                "Missing Policy",
                "This policy is missing and its details can no longer be edited.",
            )
            return
        if self._selected_version_integrity_issue():
            QtWidgets.QMessageBox.warning(
                self,
                "Integrity Issue",
                "Resolve the file integrity issue before modifying this version.",
            )
            return
        selected_owner = self.detail_owner.currentData()
        selected = self.version_table.selectionModel().selectedRows()
        selected_version_id = None
        if selected:
            selected_version_id = self.version_table.item(selected[0].row(), 0).data(QtCore.Qt.UserRole)
        policy_row = self.conn.execute(
            "SELECT current_version_id FROM policies WHERE id = ?",
            (self.current_policy_id,),
        ).fetchone()
        if not policy_row:
            return
        version_id = selected_version_id or policy_row["current_version_id"]
        if not version_id:
            return
        row = self.conn.execute(
            "SELECT owner FROM policy_versions WHERE id = ?",
            (version_id,),
        ).fetchone()
        if not row:
            return
        current_owner = row["owner"] or ""
        new_owner = selected_owner or ""
        if current_owner == new_owner:
            return
        current_label = current_owner or "Unassigned"
        new_label = new_owner or "Unassigned"
        response = QtWidgets.QMessageBox.question(
            self,
            "Confirm Change",
            f"Change Owner from {current_label} to {new_label}?",
        )
        if response != QtWidgets.QMessageBox.Yes:
            self._load_policy_detail(self.current_policy_id)
            return
        update_policy_version_owner(self.conn, version_id, selected_owner)
        self._refresh_policies(clear_selection=False)
        self._load_policy_detail(self.current_policy_id)
        self._load_audit_log()

    def _on_category_changed(self, category: str) -> None:
        """Handle category updates from the metadata form."""

        if not self.current_policy_id:
            return
        policy_row = self.conn.execute(
            "SELECT category FROM policies WHERE id = ?",
            (self.current_policy_id,),
        ).fetchone()
        if not policy_row:
            return
        current_value = policy_row["category"]
        if current_value == category:
            return
        response = QtWidgets.QMessageBox.question(
            self,
            "Confirm Change",
            f"Change Category from {current_value} to {category}?",
        )
        if response != QtWidgets.QMessageBox.Yes:
            self._load_policy_detail(self.current_policy_id)
            return
        update_policy_category(self.conn, self.current_policy_id, category)
        self._refresh_policies(clear_selection=False)
        self._load_policy_detail(self.current_policy_id)
        self._load_audit_log()

    def _build_policy_detail(self) -> QtWidgets.QWidget:
        """Build the policy detail tab UI."""

        wrapper = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(wrapper)

        versions = QtWidgets.QGroupBox("Version History")
        versions_layout = QtWidgets.QVBoxLayout(versions)
        self.version_table = QtWidgets.QTableWidget(0, 8)
        self.version_table.setHorizontalHeaderLabels(
            ["Created", "Version", "Current", "Ratified", "Status", "File Name", "Size", "Hash"]
        )
        self.version_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.version_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.version_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.version_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        version_font = self.version_table.font()
        version_font.setPointSize(9)
        version_font.setBold(True)
        self.version_table.setFont(version_font)
        self.version_table.setStyleSheet(
            "QTableWidget::item { color: white;}"
            "QTableWidget::item:selected { background-color: blue; color: white;}"
        )
        self.version_table.itemSelectionChanged.connect(self._on_version_selected)
        versions_layout.addWidget(self.version_table)

        summary = QtWidgets.QGroupBox("Policy Metadata")
        form = QtWidgets.QFormLayout(summary)
        self.detail_title = QtWidgets.QLineEdit()
        self.detail_title.setReadOnly(False)
        self.detail_title.textChanged.connect(self._mark_title_dirty)
        self.detail_title.installEventFilter(self)
        self.detail_category = QtWidgets.QComboBox()
        self.detail_category.setEditable(False)
        self.detail_category.currentTextChanged.connect(self._on_category_changed)
        self.detail_owner = QtWidgets.QComboBox()
        self.detail_owner.setEditable(False)
        self.detail_owner.currentTextChanged.connect(self._on_owner_changed)
        self.detail_status = QtWidgets.QComboBox()
        self.detail_status.addItems(["Draft", "Active", "Withdrawn", "Missing", "Archived"])
        missing_index = self.detail_status.findText("Missing")
        if missing_index >= 0:
            missing_item = self.detail_status.model().item(missing_index)
            if missing_item is not None:
                missing_item.setFlags(missing_item.flags() & ~QtCore.Qt.ItemIsEnabled)
        self.detail_status.currentTextChanged.connect(self._on_status_changed)
        self.detail_review_due = QtWidgets.QDateEdit()
        self.detail_review_due.setCalendarPopup(True)
        self.detail_review_due.setDisplayFormat("dd/MM/yyyy")
        self.detail_review_due.dateChanged.connect(self._on_review_due_changed)
        self.detail_review_due.setReadOnly(True)
        self.detail_review_due.setButtonSymbols(QtWidgets.QAbstractSpinBox.NoButtons)
        self.detail_last_reviewed = QtWidgets.QLineEdit()
        self.detail_last_reviewed.setReadOnly(True)
        self.detail_review_frequency = QtWidgets.QComboBox()
        self._populate_review_frequency_options(self.detail_review_frequency)
        self.detail_review_frequency.currentIndexChanged.connect(self._on_review_frequency_changed)
        self.detail_review_days_remaining = QtWidgets.QLineEdit()
        self.detail_review_days_remaining.setReadOnly(True)
        self.detail_notes = QtWidgets.QPlainTextEdit()
        self.detail_notes.setReadOnly(False)
        self.detail_notes.textChanged.connect(self._mark_notes_dirty)
        self.detail_notes.installEventFilter(self)
        self.detail_ratified = QtWidgets.QLineEdit()
        self.detail_ratified.setReadOnly(True)
        self.detail_ratified_at = QtWidgets.QLineEdit()
        self.detail_ratified_at.setReadOnly(True)
        self.detail_ratified_by = QtWidgets.QLineEdit()
        self.detail_ratified_by.setReadOnly(True)

        form.addRow("Title", self.detail_title)
        form.addRow("Category", self.detail_category)
        form.addRow("Owner", self.detail_owner)
        form.addRow("Status", self.detail_status)
        form.addRow("Last Reviewed", self.detail_last_reviewed)
        form.addRow("Review Due", self.detail_review_due)
        form.addRow("Review Frequency", self.detail_review_frequency)
        form.addRow("Days Remaining", self.detail_review_days_remaining)
        form.addRow("Notes", self.detail_notes)
        form.addRow("Ratified", self.detail_ratified)
        form.addRow("Ratified At", self.detail_ratified_at)
        form.addRow("Ratified By", self.detail_ratified_by)

        reviews = QtWidgets.QGroupBox("Reviews (No Changes)")
        reviews_layout = QtWidgets.QVBoxLayout(reviews)
        self.review_table = QtWidgets.QTableWidget(0, 4)
        self.review_table.setHorizontalHeaderLabels(
            ["Reviewed At", "Reviewed By", "Version", "Notes"]
        )
        self.review_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.review_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.review_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.review_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        review_font = self.review_table.font()
        review_font.setPointSize(9)
        review_font.setBold(True)
        self.review_table.setFont(review_font)
        self.review_table.setStyleSheet(
            "QTableWidget::item { color: white; }"
            "QTableWidget::item:selected { background-color: blue; color: white; }"
        )
        reviews_layout.addWidget(self.review_table)
        review_button_row = QtWidgets.QHBoxLayout()
        review_button_row.addStretch(1)
        self.review_button = QtWidgets.QPushButton("Record Review")
        self.review_button.clicked.connect(self._record_policy_review)
        review_button_row.addWidget(self.review_button)
        reviews_layout.addLayout(review_button_row)

        button_row = QtWidgets.QHBoxLayout()
        self.ratify_button = QtWidgets.QPushButton("Mark Ratified")
        self.ratify_button.clicked.connect(self._mark_ratified)
        self.unratify_button = QtWidgets.QPushButton("Mark Unratified")
        self.unratify_button.clicked.connect(self._mark_unratified)
        self.set_current_button = QtWidgets.QPushButton("Set Current")
        self.set_current_button.clicked.connect(self._set_current)
        self.set_not_current_button = QtWidgets.QPushButton("Set Not Current")
        self.set_not_current_button.clicked.connect(self._set_not_current)
        self.open_location_button = QtWidgets.QPushButton("Open Policy Document")
        self.open_location_button.clicked.connect(self._open_file_location)
        self.print_document_button = QtWidgets.QPushButton("Print Policy Document")
        self.print_document_button.clicked.connect(self._print_policy_document)
        self.add_version_button = QtWidgets.QPushButton("Add Version")
        self.add_version_button.clicked.connect(self._upload_version)
        button_row.addWidget(self.add_version_button)
        button_row.addStretch(2)
        button_row.addWidget(self.ratify_button)
        button_row.addWidget(self.unratify_button)
        button_row.addStretch(2)
        button_row.addWidget(self.set_current_button)
        button_row.addWidget(self.set_not_current_button)
        button_row.addStretch(2)
        button_row.addWidget(self.open_location_button)
        button_row.addWidget(self.print_document_button)

        layout.addWidget(versions)
        layout.addWidget(summary)
        layout.addWidget(reviews)
        layout.addLayout(button_row)
        return wrapper

    def _build_email_compose(self) -> QtWidgets.QWidget:
        """Build the policy distributor tab UI."""

        wrapper = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(wrapper)

        policy_group = QtWidgets.QGroupBox("Policies to Send")
        policy_layout = QtWidgets.QVBoxLayout(policy_group)
        select_controls = QtWidgets.QHBoxLayout()
        self.policy_send_select_all = QtWidgets.QPushButton("Select All Shown")
        self.policy_send_select_all.clicked.connect(self._toggle_all_send_policies)
        select_controls.addWidget(self.policy_send_select_all)
        self.policy_send_deselect_all = QtWidgets.QPushButton("Deselect All Shown")
        self.policy_send_deselect_all.clicked.connect(self._deselect_all_send_policies)
        select_controls.addWidget(self.policy_send_deselect_all)
        select_controls.addStretch()
        policy_layout.addLayout(select_controls)
        self.policy_send_search = QtWidgets.QLineEdit()
        self.policy_send_search.setPlaceholderText("Search policies...")
        self.policy_send_search.textChanged.connect(self._filter_send_policies)
        policy_layout.addWidget(self.policy_send_search)
        self.policy_send_table = QtWidgets.QTableWidget(0, 5)
        self.policy_send_table.setHorizontalHeaderLabels(
            ["Select", "Title", "Version", "Category", "Size"]
        )
        self.policy_send_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)

        self.policy_send_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.policy_send_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)


        send_font = self.policy_send_table.font()
        send_font.setPointSize(9)
        send_font.setBold(True)
        self.policy_send_table.setFont(send_font)
        self.policy_send_table.setStyleSheet(
            "QTableWidget::item { color: white; }"
            "QTableWidget::item:selected { background-color: blue; color: white; }"
        )

        self.policy_send_table.itemChanged.connect(self._on_send_policy_item_changed)
        self.policy_send_table.itemClicked.connect(self._on_send_policy_item_clicked)
        policy_layout.addWidget(self.policy_send_table)

        recipient_group = QtWidgets.QGroupBox("Recipients")
        recipient_layout = QtWidgets.QVBoxLayout(recipient_group)
        recipient_controls = QtWidgets.QHBoxLayout()
        self.staff_select_all = QtWidgets.QPushButton("Select All Shown")
        self.staff_select_all.clicked.connect(self._select_all_staff)
        recipient_controls.addWidget(self.staff_select_all)
        self.staff_deselect_all = QtWidgets.QPushButton("Deselect All shown")
        self.staff_deselect_all.clicked.connect(self._deselect_all_staff)
        recipient_controls.addWidget(self.staff_deselect_all)
        recipient_controls.addStretch()
        recipient_layout.addLayout(recipient_controls)
        self.staff_search = QtWidgets.QLineEdit()
        self.staff_search.setPlaceholderText("Search staff...")
        self.staff_search.textChanged.connect(self._filter_staff)
        recipient_layout.addWidget(self.staff_search)
        self.staff_table = QtWidgets.QTableWidget(0, 4)
        self.staff_table.setHorizontalHeaderLabels(["Select", "Name", "Email", "Team"])
        staff_header = self.staff_table.horizontalHeader()
        staff_header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        for col in range(1, 4):
            staff_header.setSectionResizeMode(col, QtWidgets.QHeaderView.Stretch)
        staff_header.setStretchLastSection(True)
        self.staff_table.itemChanged.connect(self._on_staff_item_changed)

        self.staff_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.staff_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.staff_table.setItemDelegate(BoldTableItemDelegate(self.staff_table))

        audit_font = self.staff_table.font()
        audit_font.setPointSize(9)
        audit_font.setBold(True)
        self.staff_table.setFont(audit_font)

        self.staff_table.setStyleSheet(
            "QTableWidget::item { color: white; font-weight: bold; }"
            "QTableWidget::item:selected { background-color: blue; color: white; }"
        )

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
        """Load current policy versions into the send table."""

        rows = self.conn.execute(
            """
            SELECT p.title, p.category, v.id AS version_id, v.version_number, v.file_size_bytes
            FROM policy_versions v
            JOIN policies p ON p.id = v.policy_id
            WHERE p.current_version_id = v.id
            ORDER BY p.category, p.title, v.version_number DESC
            """
        ).fetchall()
        self.policy_send_table.blockSignals(True)
        self.policy_send_table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            checkbox = QtWidgets.QTableWidgetItem()
            checkbox.setFlags(
                QtCore.Qt.ItemIsUserCheckable
                | QtCore.Qt.ItemIsEnabled
                | QtCore.Qt.ItemIsSelectable
                | QtCore.Qt.ItemIsEditable
            )
            checkbox.setCheckState(QtCore.Qt.Unchecked)
            checkbox.setData(QtCore.Qt.UserRole + 1, row["file_size_bytes"] or 0)
            self.policy_send_table.setItem(row_index, 0, checkbox)
            self.policy_send_table.setItem(row_index, 1, QtWidgets.QTableWidgetItem(row["title"]))
            self.policy_send_table.setItem(row_index, 2, QtWidgets.QTableWidgetItem(str(row["version_number"])))
            self.policy_send_table.setItem(row_index, 3, QtWidgets.QTableWidgetItem(row["category"]))
            self.policy_send_table.setItem(
                row_index,
                4,
                QtWidgets.QTableWidgetItem(self._format_file_size(row["file_size_bytes"])),
            )
            self.policy_send_table.item(row_index, 0).setData(QtCore.Qt.UserRole, row["version_id"])
        self.policy_send_table.blockSignals(False)
        self._filter_send_policies(self.policy_send_search.text())
        self._recalculate_attachments()

    def _filter_send_policies(self, text: str) -> None:
        """Filter visible policies in the send table."""

        text = text.lower().strip()
        for row in range(self.policy_send_table.rowCount()):
            title = self.policy_send_table.item(row, 1).text().lower()
            category = self.policy_send_table.item(row, 3).text().lower()
            match = text in title or text in category
            self.policy_send_table.setRowHidden(row, not match if text else False)
        self._sync_send_policy_select_all()

    def _visible_policy_rows(self) -> list[int]:
        """Return row indices for visible policy send rows."""

        return [
            row
            for row in range(self.policy_send_table.rowCount())
            if not self.policy_send_table.isRowHidden(row)
        ]

    def _sync_send_policy_select_all(self) -> None:
        """Sync select/deselect buttons with the current selection state."""

        visible_rows = self._visible_policy_rows()
        if not visible_rows:
            self.policy_send_select_all.setEnabled(False)
            self.policy_send_deselect_all.setEnabled(False)
            return
        self.policy_send_select_all.setEnabled(True)
        any_checked = False
        all_checked = True
        for row in visible_rows:
            item = self.policy_send_table.item(row, 0)
            if not item or item.checkState() != QtCore.Qt.Checked:
                all_checked = False
            else:
                any_checked = True
        self.policy_send_select_all.setEnabled(not all_checked)
        self.policy_send_deselect_all.setEnabled(any_checked)

    def _toggle_all_send_policies(self, _: bool) -> None:
        """Select all visible policies in the send table."""

        check_state = QtCore.Qt.Checked
        self.policy_send_table.blockSignals(True)
        for row in self._visible_policy_rows():
            item = self.policy_send_table.item(row, 0)
            item.setCheckState(check_state)
        self.policy_send_table.blockSignals(False)
        self._recalculate_attachments()

    def _on_send_policy_item_changed(self, item: QtWidgets.QTableWidgetItem) -> None:
        """Recalculate attachment totals when a checkbox changes."""

        if item.column() != 0:
            return
        QtCore.QTimer.singleShot(0, self._recalculate_attachments)

    def _on_send_policy_item_clicked(self, item: QtWidgets.QTableWidgetItem) -> None:
        """Recalculate attachment totals when a checkbox is clicked."""

        if item.column() != 0:
            return
        QtCore.QTimer.singleShot(0, self._recalculate_attachments)

    def _deselect_all_send_policies(self, _: bool) -> None:
        """Deselect all visible policies in the send table."""

        self.policy_send_table.blockSignals(True)
        for row in self._visible_policy_rows():
            item = self.policy_send_table.item(row, 0)
            item.setCheckState(QtCore.Qt.Unchecked)
        self.policy_send_table.blockSignals(False)
        self._recalculate_attachments()

    def _visible_staff_rows(self) -> list[int]:
        """Return row indices for visible staff rows."""

        return [
            row
            for row in range(self.staff_table.rowCount())
            if not self.staff_table.isRowHidden(row)
        ]

    def _sync_staff_select_all(self) -> None:
        """Sync staff select/deselect buttons with the current selection state."""

        visible_rows = self._visible_staff_rows()
        if not visible_rows:
            self.staff_select_all.setEnabled(False)
            self.staff_deselect_all.setEnabled(False)
            return
        self.staff_select_all.setEnabled(True)
        any_checked = False
        all_checked = True
        for row in visible_rows:
            item = self.staff_table.item(row, 0)
            if not item or item.checkState() != QtCore.Qt.Checked:
                all_checked = False
            else:
                any_checked = True
        self.staff_select_all.setEnabled(not all_checked)
        self.staff_deselect_all.setEnabled(any_checked)

    def _select_all_staff(self, _: bool) -> None:
        """Select all visible staff rows."""

        self._set_staff_check_state(QtCore.Qt.Checked)

    def _deselect_all_staff(self, _: bool) -> None:
        """Deselect all visible staff rows."""

        self._set_staff_check_state(QtCore.Qt.Unchecked)

    def _set_staff_check_state(self, check_state: QtCore.Qt.CheckState) -> None:
        """Set the check state for all visible staff rows."""

        self.staff_table.blockSignals(True)
        for row in self._visible_staff_rows():
            item = self.staff_table.item(row, 0)
            if not item:
                item = QtWidgets.QTableWidgetItem()
                item.setFlags(
                    QtCore.Qt.ItemIsUserCheckable
                    | QtCore.Qt.ItemIsEnabled
                    | QtCore.Qt.ItemIsSelectable
                    | QtCore.Qt.ItemIsEditable
                )
                self.staff_table.setItem(row, 0, item)
            item.setCheckState(check_state)
        self.staff_table.blockSignals(False)
        self._sync_staff_select_all()

    def _load_staff(self) -> None:
        """Load staff records by running the Access extractor and parsing its CSV."""

        base_dir = config.get_paths().data_dir
        access_path = base_dir / "staff_details_extractor.accdb"
        if not access_path.exists():
            packaged_path = None
            if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
                packaged_path = Path(sys._MEIPASS) / "staff_details_extractor.accdb"
            else:
                packaged_path = Path(sys.executable).resolve().parent / "staff_details_extractor.accdb"
            if packaged_path and packaged_path.exists():
                try:
                    shutil.copy2(packaged_path, access_path)
                except OSError:
                    QtWidgets.QMessageBox.warning(
                        self,
                        "Missing Extractor",
                        f"Unable to copy staff extractor to {access_path}.",
                    )
                    return
        csv_path = base_dir / "staff_details.csv"
        if not access_path.exists():
            QtWidgets.QMessageBox.warning(
                self,
                "Missing Extractor",
                f"Expected staff extractor at {access_path}.",
            )
            return

        if csv_path.exists():
            try:
                csv_path.unlink()
            except OSError:
                QtWidgets.QMessageBox.warning(
                    self,
                    "CSV Locked",
                    f"Unable to remove existing CSV at {csv_path}. Close it and try again.",
                )
                return

        try:
            self._run_staff_extractor(access_path)
        except RuntimeError as exc:
            QtWidgets.QMessageBox.warning(self, "Extractor Error", str(exc))
            return

        if not self._wait_for_staff_csv(csv_path):
            QtWidgets.QMessageBox.warning(
                self,
                "CSV Not Found",
                f"staff_details.csv was not generated in {base_dir}.",
            )
            return

        try:
            self._staff_records = self._read_staff_csv(csv_path)
        finally:
            try:
                csv_path.unlink()
            except OSError:
                pass

        self.staff_table.setRowCount(len(self._staff_records))
        item_font = self.staff_table.font()
        item_font.setBold(True)
        for row_index, row in enumerate(self._staff_records):
            checkbox = QtWidgets.QTableWidgetItem()
            checkbox.setFlags(
                QtCore.Qt.ItemIsUserCheckable
                | QtCore.Qt.ItemIsEnabled
                | QtCore.Qt.ItemIsSelectable
                | QtCore.Qt.ItemIsEditable
            )
            checkbox.setCheckState(QtCore.Qt.Unchecked)
            name = row.get("name", "")
            email = row.get("email", "")
            team = row.get("team", "")
            checkbox.setFont(item_font)
            name_item = QtWidgets.QTableWidgetItem(name or "")
            name_item.setFont(item_font)
            email_item = QtWidgets.QTableWidgetItem(email or "")
            email_item.setFont(item_font)
            team_item = QtWidgets.QTableWidgetItem(team or "")
            team_item.setFont(item_font)
            self.staff_table.setItem(row_index, 0, checkbox)
            self.staff_table.setItem(row_index, 1, name_item)
            self.staff_table.setItem(row_index, 2, email_item)
            self.staff_table.setItem(row_index, 3, team_item)
        self._filter_staff(self.staff_search.text())
        self._append_audit_event(
            "load_staff",
            "staff",
            None,
            f"records={len(self._staff_records)}",
        )
        self.conn.commit()
        self._refresh_audit_log_if_visible()

    def _run_staff_extractor(self, access_path: Path) -> None:
        """Run the Access staff extractor frontend."""

        if os.name != "nt":
            raise RuntimeError("Staff extractor requires Microsoft Access on Windows.")
        subprocess.run(["cmd", "/c", "start", "/wait", "", str(access_path)], check=False)

    def _wait_for_staff_csv(self, csv_path: Path, timeout_seconds: int = 60) -> bool:
        """Wait for the staff CSV export to appear."""

        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            QtCore.QCoreApplication.processEvents()
            if csv_path.exists() and csv_path.stat().st_size > 0:
                return True
            time.sleep(0.2)
        return False

    def _read_staff_csv(self, csv_path: Path) -> list[dict[str, str]]:
        """Read staff details from the CSV exported by Access."""

        records: list[dict[str, str]] = []
        with csv_path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                first_name = (row.get("FirstName") or "").strip()
                last_name = (row.get("LastName") or "").strip()
                email = (row.get("EmailAddress") or "").strip()
                team = (row.get("DepartmentID") or "").strip()
                name_parts = [part for part in [first_name, last_name] if part]
                name = " ".join(name_parts).strip()
                if not (name or email or team):
                    continue
                records.append({"name": name, "email": email, "team": team})
        return records

    def _filter_staff(self, text: str) -> None:
        """Filter staff recipients by name or email."""

        text = text.lower().strip()
        for row in range(self.staff_table.rowCount()):
            name = self.staff_table.item(row, 1).text().lower()
            email = self.staff_table.item(row, 2).text().lower()
            team = self.staff_table.item(row, 3).text().lower()
            match = text in name or text in email or text in team
            self.staff_table.setRowHidden(row, not match if text else False)
        self._sync_staff_select_all()

    def _on_staff_item_changed(self, item: QtWidgets.QTableWidgetItem) -> None:
        """Sync staff selection controls when a checkbox changes."""

        if item.column() != 0:
            return
        QtCore.QTimer.singleShot(0, self._sync_staff_select_all)

    def _confirm_recipients(self, recipients: list[tuple[str, str]]) -> bool:
        """Confirm the final recipient list before sending."""

        count = len(recipients)
        preview_limit = 25
        lines = []
        for email, name in recipients[:preview_limit]:
            label = f"{name} <{email}>" if name and name != email else email
            lines.append(label)
        if count > preview_limit:
            lines.append(f"...and {count - preview_limit} more")
        message = "Send to the following recipients?\n\n"
        message += f"Total recipients: {count}\n\n"
        message += "\n".join(lines) if lines else "(No recipients)"
        response = QtWidgets.QMessageBox.question(
            self,
            "Confirm Recipients",
            message,
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        )
        return response == QtWidgets.QMessageBox.Yes

    def _append_audit_event(
        self,
        action: str,
        entity_type: str,
        entity_id: int | None,
        details: str | None,
    ) -> None:
        """Append a standard audit event row."""

        audit.append_event_log(
            self.conn,
            {
                "occurred_at": datetime.utcnow().isoformat(),
                "actor": self._resolve_audit_actor(),
                "action": action,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "details": details,
            },
        )

    def _resolve_audit_actor(self) -> str | None:
        """Resolve the current audit actor for UI-driven logging."""

        if self.username:
            return self.username
        try:
            return os.getlogin()
        except OSError:
            return None

    def _refresh_audit_log_if_visible(self) -> None:
        """Refresh the audit log table when it is visible."""

        if not hasattr(self, "audit_table"):
            return
        if not self.audit_table.isVisible():
            return
        self._load_audit_log()

    def _recalculate_attachments(self) -> None:
        """Update total size and split plan based on selected policies."""

        total_bytes = 0
        for row in range(self.policy_send_table.rowCount()):
            item = self.policy_send_table.item(row, 0)
            if not item or item.checkState() != QtCore.Qt.Checked:
                continue
            size = item.data(QtCore.Qt.UserRole + 1)
            try:
                size_bytes = int(size)
            except (TypeError, ValueError):
                size_bytes = 0
            total_bytes += size_bytes
        total_mb = total_bytes / (1024 * 1024)
        self.total_attachment_label.setText(self._format_file_size(total_bytes))
        self._sync_send_policy_select_all()

        max_mb = float(config.get_setting(self.conn, "max_attachment_mb", 0) or 0)
        if max_mb and total_mb > max_mb:
            parts = int(total_mb // max_mb) + 1
            self.split_plan_label.setText(f"Split into {parts} emails")
        else:
            self.split_plan_label.setText("Single email")

    def _send_email(self) -> None:
        """Send selected policies to selected recipients via Outlook."""

        selected_versions: list[int] = []
        for row in range(self.policy_send_table.rowCount()):
            item = self.policy_send_table.item(row, 0)
            if item.checkState() == QtCore.Qt.Checked:
                selected_versions.append(item.data(QtCore.Qt.UserRole))

        recipients_by_email: dict[str, tuple[str, str]] = {}
        for row in range(self.staff_table.rowCount()):
            item = self.staff_table.item(row, 0)
            if item and item.checkState() == QtCore.Qt.Checked:
                email = self.staff_table.item(row, 2).text().strip()
                name = self.staff_table.item(row, 1).text().strip()
                if not email:
                    continue
                recipients_by_email[email.lower()] = (email, name or email)

        manual_entries = re.split(r"[,\n;]+", self.manual_emails.text())
        invalid_manual: list[str] = []
        for entry in manual_entries:
            cleaned = entry.strip()
            if not cleaned:
                continue
            _, parsed_email = parseaddr(cleaned)
            parsed_email = parsed_email.strip()
            if not parsed_email or "@" not in parsed_email:
                invalid_manual.append(cleaned)
                continue
            key = parsed_email.lower()
            recipients_by_email.setdefault(key, (parsed_email, parsed_email))

        if invalid_manual:
            QtWidgets.QMessageBox.warning(
                self,
                "Invalid emails",
                "These addresses are invalid and will be skipped:\n"
                + "\n".join(invalid_manual),
            )

        recipients = list(recipients_by_email.values())

        if not selected_versions or not recipients:
            QtWidgets.QMessageBox.warning(self, "Missing", "Select policies and recipients.")
            return
        if not self._confirm_recipients(recipients):
            return

        max_mb = float(config.get_setting(self.conn, "max_attachment_mb", 0) or 0)
        attachments: list[tuple[str, int]] = []
        policy_rows = []
        total_bytes = 0
        missing_attachments: list[str] = []
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
            resolved_path = resolve_version_file_path(
                self.conn,
                row["version_id"],
                row["file_path"],
            )
            if not resolved_path:
                missing_attachments.append(
                    f"{row['title']} (v{row['version_number']}): {row['file_path']}"
                )
                continue
            attachments.append((str(resolved_path), row["file_size_bytes"]))
            policy_rows.append(row)
            total_bytes += row["file_size_bytes"]

        if missing_attachments:
            QtWidgets.QMessageBox.warning(
                self,
                "Missing files",
                "One or more policy files could not be found:\n"
                + "\n".join(missing_attachments),
            )
            return

        total_mb = total_bytes / (1024 * 1024)
        parts = 1
        if max_mb and total_mb > max_mb:
            parts = int(total_mb // max_mb) + 1

        subject_base = "Policy/Policies Enclosed"
        policy_lines = [f"- {row['title']} (v{row['version_number']})" for row in policy_rows]

        max_bytes = int(max_mb * 1024 * 1024) if max_mb else 0
        oversized_attachments: list[str] = []
        if max_bytes:
            for path, size in attachments:
                if size > max_bytes:
                    oversized_attachments.append(f"{os.path.basename(path)} ({size / (1024 * 1024):.2f} MB)")
        if oversized_attachments:
            QtWidgets.QMessageBox.warning(
                self,
                "Attachment too large",
                "These files exceed the maximum attachment size and cannot be sent:\n"
                + "\n".join(oversized_attachments),
            )
            return

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
        failures: list[str] = []
        for part_index, chunk in enumerate(attachment_chunks, start=1):
            subject = subject_base
            if parts > 1:
                subject = f"{subject_base} (Part {part_index} of {parts})"
            attachment_paths = [path for path, _ in chunk]
            total_attachment_bytes = sum(size for _, size in chunk)
            for recipient_email, recipient_name in recipients:
                raw_name = (recipient_name or recipient_email).strip()
                if "@" in raw_name:
                    first_name = raw_name.split("@")[0].split(".")[0].split(" ")[0]
                else:
                    first_name = raw_name.split(" ")[0]
                body_lines = [
                    f"Dear {first_name},",
                    "",
                    "Please find the following policy/policies attached.",
                    "",
                    *policy_lines,
                    "",
                    "Please ensure you read the policy/policies carefully.",
                    "",
                    "Kind regards",
                    "",
                    "Martha Trust",
                ]
                body = "\n".join(body_lines)
                try:
                    entry_id = outlook.send_email(
                        subject, body, [recipient_email], attachment_paths
                    )
                    status = "SENT"
                    error_text = ""
                except outlook.OutlookError as exc:
                    entry_id = ""
                    status = "FAILED"
                    error_text = str(exc)
                    failures.append(f"{recipient_email}: {subject}: {error_text}")

                for row in policy_rows:
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
                            "total_attachment_bytes_for_part": total_attachment_bytes,
                            "outlook_entry_id": entry_id,
                            "status": status,
                            "error_text": error_text,
                        },
                    )
                    self._append_audit_event(
                        "email_policy",
                        "policy_version",
                        row["version_id"],
                        (
                            "recipient="
                            f"{recipient_email}; name={recipient_name or recipient_email}; "
                            f"subject={subject}; status={status}; part={part_index}/{parts}"
                        ),
                    )
        self.conn.commit()
        self._refresh_audit_log_if_visible()

        if failures:
            QtWidgets.QMessageBox.warning(
                self,
                "Send issues",
                "Email processing completed with errors:\n" + "\n".join(failures),
            )
        else:
            QtWidgets.QMessageBox.information(self, "Sent", "Email processing completed.")

    def _build_audit_dialog(self) -> QtWidgets.QDialog:
        """Build the audit log dialog window."""

        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("Audit Log")
        dialog.setWindowFlags(
            dialog.windowFlags()
            | QtCore.Qt.WindowMaximizeButtonHint
            | QtCore.Qt.WindowMinimizeButtonHint
        )
        dialog_layout = QtWidgets.QVBoxLayout(dialog)
        dialog_layout.addWidget(self._build_audit_log())
        dialog.resize(900, 600)
        return dialog

    def _build_audit_log(self) -> QtWidgets.QWidget:
        """Build the audit log tab UI."""

        wrapper = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(wrapper)

        filters = QtWidgets.QHBoxLayout()
        self.audit_start = QtWidgets.QDateEdit()
        self.audit_start.setCalendarPopup(True)
        self.audit_start.setDisplayFormat("dd/MM/yyyy")
        self.audit_start.setDate(QtCore.QDate(2026, 1, 1))
        self.audit_end = QtWidgets.QDateEdit()
        self.audit_end.setCalendarPopup(True)
        self.audit_end.setDisplayFormat("dd/MM/yyyy")
        self.audit_end.setDate(QtCore.QDate.currentDate())
        filters.addWidget(self.audit_start)
        filters.addWidget(self.audit_end)
        self.audit_search = QtWidgets.QLineEdit()
        self.audit_search.setPlaceholderText("Search audit log...")
        self.audit_search.textChanged.connect(self._load_audit_log)
        filters.addWidget(self.audit_search)
        self.audit_hide_email_policy = QtWidgets.QCheckBox("Hide Email Logs")
        self.audit_hide_email_policy.toggled.connect(self._load_audit_log)
        filters.addWidget(self.audit_hide_email_policy)

        self.audit_table = QtWidgets.QTableWidget(0, 5)
        self.audit_table.setHorizontalHeaderLabels(
            ["Occurred At", "Actor", "Action", "Entity", "Details"]
        )
        self.audit_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.audit_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        self.audit_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.audit_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

        audit_font = self.audit_table.font()
        audit_font.setPointSize(9)
        audit_font.setBold(False)
        self.audit_table.setFont(audit_font)

        self.audit_table.setStyleSheet(
            "QTableWidget::item { color: white;}"
            "QTableWidget::item:selected { background-color: blue; color: white; }"
        )

        button_row = QtWidgets.QHBoxLayout()
        export_button = QtWidgets.QPushButton("Export All Logs")
        export_button.clicked.connect(self._export_audit_csv)
        export_visible_button = QtWidgets.QPushButton("Export Logs Shown")
        export_visible_button.clicked.connect(self._export_audit_csv_shown)
        verify_button = QtWidgets.QPushButton("Verify Log Integrity")
        verify_button.clicked.connect(self._verify_audit)
        refresh_button = QtWidgets.QPushButton("Refresh Logs")
        refresh_button.clicked.connect(self._load_audit_log)
        button_row.addWidget(export_button)
        button_row.addWidget(export_visible_button)
        button_row.addWidget(verify_button)
        button_row.addWidget(refresh_button)
        button_row.addStretch(1)

        layout.addLayout(filters)
        layout.addWidget(self.audit_table)
        layout.addLayout(button_row)
        return wrapper

    def _load_audit_log(self) -> None:
        """Load audit events into the audit log table."""

        rows = self._fetch_audit_rows()
        self.audit_table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            entity = row["entity_type"]
            if row["policy_title"]:
                entity = row["policy_title"]
                if row["version_number"] is not None:
                    entity = f"{entity} (v{row['version_number']})"
            elif row["entity_id"] is not None:
                entity = f"{entity} #{row['entity_id']}"
            self.audit_table.setItem(
                row_index,
                0,
                QtWidgets.QTableWidgetItem(self._format_datetime_display(row["occurred_at"])),
            )
            self.audit_table.setItem(row_index, 1, QtWidgets.QTableWidgetItem(row["actor"] or ""))
            self.audit_table.setItem(row_index, 2, QtWidgets.QTableWidgetItem(row["action"]))
            self.audit_table.setItem(row_index, 3, QtWidgets.QTableWidgetItem(entity))
            self.audit_table.setItem(row_index, 4, QtWidgets.QTableWidgetItem(row["details"] or ""))

    def _fetch_audit_rows(self) -> list[sqlite3.Row]:
        """Fetch audit rows using the current filters."""

        start_date = self.audit_start.date().toString("yyyy-MM-dd")
        end_date = self.audit_end.date().toString("yyyy-MM-dd")
        search_text = self.audit_search.text().strip().lower()
        search_clause = ""
        action_clause = ""
        params: list[str] = [start_date, end_date]
        if self.audit_hide_email_policy.isChecked():
            action_clause = "AND ae.action != ?"
            params.append("email_policy")
        if search_text:
            search_clause = """
                AND (
                    lower(COALESCE(ae.actor, '')) LIKE ?
                    OR lower(COALESCE(ae.action, '')) LIKE ?
                    OR lower(COALESCE(ae.entity_type, '')) LIKE ?
                    OR lower(COALESCE(ae.details, '')) LIKE ?
                    OR lower(COALESCE(p.title, pv_policy.title, '')) LIKE ?
                    OR lower(COALESCE(CAST(pv.version_number AS TEXT), '')) LIKE ?
                    OR lower(COALESCE(CAST(ae.entity_id AS TEXT), '')) LIKE ?
                )
            """
            like_value = f"%{search_text}%"
            params.extend([like_value] * 7)
        return self.conn.execute(
            f"""
            SELECT ae.occurred_at,
                   ae.actor,
                   ae.action,
                   ae.entity_type,
                   ae.entity_id,
                   ae.details,
                   COALESCE(p.title, pv_policy.title) AS policy_title,
                   pv.version_number AS version_number
            FROM audit_events ae
            LEFT JOIN policies p
                ON ae.entity_type = 'policy' AND p.id = ae.entity_id
            LEFT JOIN policy_versions pv
                ON ae.entity_type = 'policy_version' AND pv.id = ae.entity_id
            LEFT JOIN policies pv_policy
                ON pv.policy_id = pv_policy.id
            WHERE date(occurred_at) BETWEEN ? AND ?
            {action_clause}
            {search_clause}
            ORDER BY occurred_at DESC
            """,
            params,
        ).fetchall()

    def _export_audit_csv(self) -> None:
        """Export the audit log table to CSV."""

        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export CSV", "audit_log.csv")
        if not path:
            return
        rows = self.conn.execute("SELECT * FROM audit_events ORDER BY occurred_at DESC").fetchall()
        import csv

        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            if rows:
                writer.writerow(rows[0].keys())
            for row in rows:
                writer.writerow(list(row))

    def _export_audit_csv_shown(self) -> None:
        """Export the currently shown audit rows to CSV."""

        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export CSV", "audit_log_filtered.csv")
        if not path:
            return
        import csv

        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            headers = [
                self.audit_table.horizontalHeaderItem(col).text()
                for col in range(self.audit_table.columnCount())
            ]
            writer.writerow(headers)
            for row in range(self.audit_table.rowCount()):
                writer.writerow(
                    [
                        self.audit_table.item(row, col).text() if self.audit_table.item(row, col) else ""
                        for col in range(self.audit_table.columnCount())
                    ]
                )

    def _verify_audit(self) -> None:
        """Verify audit log integrity and show the result."""

        _, message = audit.verify_event_log(self.conn)
        QtWidgets.QMessageBox.information(self, "Audit Log", message)

    def _build_settings_dialog(self) -> QtWidgets.QDialog:
        """Build the settings dialog window."""

        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("Settings")
        dialog_layout = QtWidgets.QVBoxLayout(dialog)
        dialog_layout.addWidget(self._build_settings())
        dialog.resize(720, 620)
        return dialog

    def _build_settings(self) -> QtWidgets.QWidget:
        """Build the settings tab UI."""

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
        """Open a folder selector for the policy root."""

        directory = QtWidgets.QFileDialog.getExistingDirectory(self, "Policy Root")
        if directory:
            self.policy_root_input.setText(directory)

    def _save_settings(self) -> None:
        """Persist settings from the UI to the config table."""

        current_policy_root = config.get_setting(self.conn, "policy_root", "")
        current_amber_months = config.get_setting(self.conn, "amber_months", 2)
        current_overdue_days = config.get_setting(self.conn, "overdue_grace_days", 0)
        current_max_attachment = config.get_setting(self.conn, "max_attachment_mb", 0)

        new_policy_root = self.policy_root_input.text().strip()
        new_amber_months = self.amber_months_input.value()
        new_overdue_days = self.overdue_days_input.value()
        new_max_attachment = self.max_attachment_input.value()

        config.set_setting(self.conn, "policy_root", new_policy_root)
        config.set_setting(self.conn, "amber_months", new_amber_months)
        config.set_setting(self.conn, "overdue_grace_days", new_overdue_days)
        config.set_setting(self.conn, "max_attachment_mb", new_max_attachment)

        changes = []
        if current_policy_root != new_policy_root:
            changes.append(f"policy_root: {current_policy_root} -> {new_policy_root}")
        if str(current_amber_months) != str(new_amber_months):
            changes.append(f"amber_months: {current_amber_months} -> {new_amber_months}")
        if str(current_overdue_days) != str(new_overdue_days):
            changes.append(f"overdue_grace_days: {current_overdue_days} -> {new_overdue_days}")
        if str(current_max_attachment) != str(new_max_attachment):
            changes.append(f"max_attachment_mb: {current_max_attachment} -> {new_max_attachment}")
        if changes:
            self._append_audit_event(
                "update_settings",
                "config",
                None,
                "; ".join(changes),
            )
        QtWidgets.QMessageBox.information(self, "Saved", "Settings updated.")

    def _load_settings(self) -> None:
        """Load saved settings into the UI fields."""

        self.policy_root_input.setText(config.get_setting(self.conn, "policy_root", ""))
        self.amber_months_input.setValue(int(config.get_setting(self.conn, "amber_months", 2) or 2))
        self.overdue_days_input.setValue(int(config.get_setting(self.conn, "overdue_grace_days", 0) or 0))
        self.max_attachment_input.setValue(int(config.get_setting(self.conn, "max_attachment_mb", 0) or 0))

    def _open_data_folder(self) -> None:
        """Open the application's data directory."""

        data_dir = config.get_paths().data_dir
        QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(data_dir)))

    def _backup_export(self) -> None:
        """Create a backup zip containing the database and optional files."""

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
