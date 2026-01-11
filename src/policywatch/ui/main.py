from __future__ import annotations

import os
import re
import sqlite3
from datetime import datetime
from email.utils import parseaddr
from pathlib import Path

from PyQt5 import QtCore, QtGui, QtWidgets

from policywatch import audit, config
from policywatch.integrations import access, outlook
from policywatch.services import (
    add_policy_version,
    build_staff_query,
    export_backup,
    get_version_file,
    resolve_version_file_path,
    list_categories,
    list_policies,
    list_versions,
    mark_version_ratified,
    unmark_version_ratified,
    parse_mapping_json,
    set_current_version,
    unset_current_version,
    update_policy_category,
    update_policy_title,
)
from policywatch.ui.dialogs import CategoryManagerDialog, PolicyDialog


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, username: str, conn: sqlite3.Connection, parent=None):
        super().__init__(parent)
        self.conn = conn
        self.current_policy_id: int | None = None
        self._notes_dirty = False
        self._title_dirty = False
        self._selected_row: int | None = None
        self._selected_version_row: int | None = None
        self._current_policy_title = ""
        self._current_policy_category = ""

        self.setWindowTitle("Policy Watch")

        toolbar = self.addToolBar("Main")
        toolbar.setMovable(False)

        new_policy_action = QtWidgets.QAction("New Policy", self)
        new_policy_action.triggered.connect(self._open_new_policy)
        toolbar.addAction(new_policy_action)

        manage_categories_action = QtWidgets.QAction("Manage Categories", self)
        manage_categories_action.triggered.connect(self._open_categories)
        toolbar.addAction(manage_categories_action)

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
        self.traffic_filter.addItems(["All", "In Date", "Review Due", "Expired"])
        self.traffic_filter.currentIndexChanged.connect(self._refresh_policies)

        self.status_filter = QtWidgets.QComboBox()
        self.status_filter.addItems(["All Statuses", "Draft", "Active", "Withdrawn", "Archived"])
        self.status_filter.currentIndexChanged.connect(self._refresh_policies)

        self.ratified_filter = QtWidgets.QComboBox()
        self.ratified_filter.addItems(["All", "Ratified", "Not Ratified"])
        self.ratified_filter.currentIndexChanged.connect(self._refresh_policies)

        self.show_expired = QtWidgets.QCheckBox("Show expired")
        self.show_expired.setChecked(True)
        self.show_expired.setVisible(False)

        filter_row = QtWidgets.QHBoxLayout()
        filter_row.addWidget(self.search_input, 2)
        filter_row.addWidget(self.category_filter, 1)
        filter_row.addWidget(self.traffic_filter, 1)
        filter_row.addWidget(self.status_filter, 1)
        filter_row.addWidget(self.ratified_filter, 1)

        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            [
                "Category",
                "Title",
                "Status",
                "Current Version",
                "Expiry",
                "Ratified",
            ]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setStyleSheet("QTableView::item:selected { background-color: hotpink; }")
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
        self.policy_detail_index = self.tabs.addTab(policy_detail, "Policy Detail")
        self.policy_distributor_index = self.tabs.addTab(email_compose, "Policy Distributor")
        self.audit_log_index = self.tabs.addTab(audit_log, "Audit Log")
        self.settings_index = self.tabs.addTab(settings, "Settings")
        self.tabs.tabBar().setTabVisible(self.audit_log_index, False)
        self.tabs.tabBar().setTabVisible(self.settings_index, False)
        self.tabs.currentChanged.connect(self._on_tab_changed)

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

    def _refresh_policies(self, clear_selection: bool = True) -> None:
        policies = list_policies(self.conn)
        filtered = []
        search_text = self.search_input.text().strip().lower()
        category = self.category_filter.currentText()
        traffic = self.traffic_filter.currentText()
        status = self.status_filter.currentText()
        ratified_filter = self.ratified_filter.currentText()
        show_expired = True
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
                if traffic == "Expired" and policy.traffic_status != "Red":
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
            category_item = QtWidgets.QTableWidgetItem(policy.category)
            title_item = QtWidgets.QTableWidgetItem(policy.title)
            if policy.current_version_id:
                status_item = QtWidgets.QTableWidgetItem(policy.status or "")
                current_version_item = QtWidgets.QTableWidgetItem(
                    str(policy.current_version_number) if policy.current_version_number else ""
                )
                expiry_item = QtWidgets.QTableWidgetItem(self._format_date_display(policy.expiry_date))
                ratified_item = QtWidgets.QTableWidgetItem("Yes" if policy.ratified else "No")
            else:
                status_item = QtWidgets.QTableWidgetItem("")
                current_version_item = QtWidgets.QTableWidgetItem("")
                expiry_item = QtWidgets.QTableWidgetItem("")
                ratified_item = QtWidgets.QTableWidgetItem("")
            items = [
                category_item,
                title_item,
                status_item,
                current_version_item,
                expiry_item,
                ratified_item,
            ]
            for column, item in enumerate(items):
                font = item.font()
                font.setBold(True)
                item.setFont(font)
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
            self._selected_row = None
        elif selected_policy_id:
            if not self._select_policy_row_by_id(selected_policy_id):
                self.table.clearSelection()
                self.current_policy_id = None
                self._selected_row = None

    def _on_policy_selected(self) -> None:
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            return
        policy_id = self.table.item(selected[0].row(), 0).data(QtCore.Qt.UserRole)
        self.current_policy_id = policy_id
        self._load_policy_detail(policy_id)
        self._highlight_selected_row(selected[0].row())

    def _open_settings(self) -> None:
        self.tabs.setCurrentIndex(self.settings_index)

    def _open_audit_log(self) -> None:
        self.tabs.setCurrentIndex(self.audit_log_index)

    def _highlight_selected_row(self, row_index: int) -> None:
        if self._selected_row is not None and self._selected_row != row_index:
            self._set_row_bold(self._selected_row, False)
        self._selected_row = row_index
        self._set_row_bold(row_index, True)

    def _set_row_bold(self, row_index: int, enabled: bool) -> None:
        for column in range(self.table.columnCount()):
            item = self.table.item(row_index, column)
            if not item:
                continue
            font = item.font()
            font.setBold(True)
            item.setFont(font)

    def _highlight_version_row(self, row_index: int) -> None:
        if self._selected_version_row is not None and self._selected_version_row != row_index:
            self._set_version_row_bold(self._selected_version_row, False)
        self._selected_version_row = row_index
        self._set_version_row_bold(row_index, True)

    def _set_version_row_bold(self, row_index: int, enabled: bool) -> None:
        for column in range(self.version_table.columnCount()):
            item = self.version_table.item(row_index, column)
            if not item:
                continue
            font = item.font()
            font.setBold(True)
            item.setFont(font)

    def _select_version_row_by_id(self, version_id: int) -> None:
        for row_index in range(self.version_table.rowCount()):
            row_version_id = self.version_table.item(row_index, 0).data(QtCore.Qt.UserRole)
            if row_version_id == version_id:
                self.version_table.selectRow(row_index)
                self._highlight_version_row(row_index)
                break

    def _select_policy_row_by_id(self, policy_id: int) -> bool:
        for row_index in range(self.table.rowCount()):
            row_policy_id = self.table.item(row_index, 0).data(QtCore.Qt.UserRole)
            if row_policy_id == policy_id:
                self.table.selectRow(row_index)
                self._highlight_selected_row(row_index)
                return True
        return False

    def _on_tab_changed(self, index: int) -> None:
        if index == self.policy_detail_index:
            selection = self.table.selectionModel().selectedRows()
            if not selection:
                self._block_policy_detail_tab()
                return
            selected_row = selection[0].row()
            if self._selected_row != selected_row or not self.current_policy_id:
                self._block_policy_detail_tab()
                return
        if index == self.policy_distributor_index:
            self._load_send_policies()

    def _block_policy_detail_tab(self) -> None:
        self.tabs.blockSignals(True)
        self.tabs.setCurrentIndex(0)
        self.tabs.blockSignals(False)
        QtWidgets.QMessageBox.warning(self, "Select Policy", "Select a policy first.")

    def _open_categories(self) -> None:
        def _refresh_categories_and_audit() -> None:
            self._refresh_categories()
            self._load_audit_log()

        dialog = CategoryManagerDialog(self.conn, _refresh_categories_and_audit, self)
        dialog.exec()
        self._refresh_policies(clear_selection=False)
        self._load_policy_detail(self.current_policy_id)
        self._load_audit_log()

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
        self._load_audit_log()

    def _load_policy_detail(self, policy_id: int) -> None:
        policy = self.conn.execute(
            "SELECT * FROM policies WHERE id = ?",
            (policy_id,),
        ).fetchone()
        if not policy:
            return
        self._selected_version_row = None
        self._current_policy_title = policy["title"] or ""
        self._current_policy_category = policy["category"] or ""
        self.detail_status.blockSignals(True)
        self.detail_expiry.blockSignals(True)
        self.detail_notes.blockSignals(True)
        self.detail_title.blockSignals(True)
        self.detail_category.blockSignals(True)
        self._populate_category_options(self._current_policy_category)
        self._clear_policy_metadata_fields()
        self.detail_status.blockSignals(False)
        self.detail_expiry.blockSignals(False)
        self.detail_notes.blockSignals(False)
        self.detail_category.blockSignals(False)
        self.detail_title.blockSignals(False)
        self._notes_dirty = False
        self._title_dirty = False

        versions = list_versions(self.conn, policy_id)
        headers = ["Created", "Version", "Current", "Ratified", "Status", "File Name", "Size", "Hash"]
        self.version_table.clearContents()
        self.version_table.setColumnCount(len(headers))
        self.version_table.setHorizontalHeaderLabels(headers)
        self.version_table.setRowCount(len(versions))
        for row_index, version in enumerate(versions):
            is_current = policy["current_version_id"] == version["id"]
            created_item = QtWidgets.QTableWidgetItem(
                self._format_datetime_display(version["created_at"])
            )
            version_item = QtWidgets.QTableWidgetItem(str(version["version_number"]))
            current_item = QtWidgets.QTableWidgetItem("Current" if is_current else "Not Current")
            ratified_value = "Yes" if int(version["ratified"] or 0) else "No"
            ratified_item = QtWidgets.QTableWidgetItem(ratified_value)
            status_item = QtWidgets.QTableWidgetItem(version["status"] or "")
            filename_item = QtWidgets.QTableWidgetItem(version["original_filename"])
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
                font = item.font()
                font.setBold(True)
                item.setFont(font)
                self.version_table.setItem(row_index, column, item)
            self.version_table.item(row_index, 0).setData(QtCore.Qt.UserRole, version["id"])
        if policy["current_version_id"]:
            self._select_version_row_by_id(policy["current_version_id"])

    def _upload_version(self) -> None:
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
        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
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
        mark_version_ratified(self.conn, version_id, None)
        if self.current_policy_id:
            self._load_policy_detail(self.current_policy_id)
            self._select_version_row_by_id(version_id)
            self._refresh_policies(clear_selection=False)
            self._load_audit_log()

    def _mark_unratified(self) -> None:
        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
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
        if not self.current_policy_id:
            return
        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
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
        if not self.current_policy_id:
            return
        selection = self.version_table.selectionModel().selectedRows()
        selected_version_id = None
        if selection:
            selected_version_id = self.version_table.item(selection[0].row(), 0).data(
                QtCore.Qt.UserRole
            )
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
        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
            return
        version_id = self.version_table.item(selection[0].row(), 0).data(QtCore.Qt.UserRole)
        file_path = get_version_file(self.conn, version_id)
        QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(file_path))

    def _on_version_selected(self) -> None:
        selection = self.version_table.selectionModel().selectedRows()
        if not selection:
            if self._selected_version_row is not None:
                self._set_version_row_bold(self._selected_version_row, False)
            self._selected_version_row = None
            self._clear_policy_metadata_fields()
            return
        self._highlight_version_row(selection[0].row())
        version_id = self.version_table.item(selection[0].row(), 0).data(QtCore.Qt.UserRole)
        version = self.conn.execute(
            """
            SELECT status, expiry_date, notes
            FROM policy_versions
            WHERE id = ?
            """,
            (version_id,),
        ).fetchone()
        if not version:
            return
        self.detail_status.blockSignals(True)
        self.detail_expiry.blockSignals(True)
        self.detail_notes.blockSignals(True)
        self.detail_title.blockSignals(True)
        self.detail_category.blockSignals(True)
        self._set_policy_metadata_enabled(True)
        self.detail_title.setText(self._current_policy_title)
        self._populate_category_options(self._current_policy_category)
        self.detail_status.setCurrentText(version["status"] or "")
        self._set_date_field(self.detail_expiry, version["expiry_date"])
        self.detail_notes.setPlainText(version["notes"] or "")
        self.detail_status.blockSignals(False)
        self.detail_expiry.blockSignals(False)
        self.detail_notes.blockSignals(False)
        self.detail_category.blockSignals(False)
        self.detail_title.blockSignals(False)
        self._notes_dirty = False
        self._title_dirty = False

    def _apply_traffic_row_color(self, row_index: int, status: str, reason: str) -> None:
        color_map = {
            "Green": QtGui.QColor("#9be8a6"),
            "Amber": QtGui.QColor("#ffe066"),
            "Red": QtGui.QColor("#f2a4aa"),
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
        text_color = QtGui.QColor("#1f1f1f")
        for column in range(self.table.columnCount()):
            item = self.table.item(row_index, column)
            if not item:
                continue
            item.setBackground(QtGui.QColor("#93c5fd"))
            item.setForeground(text_color)

    def _update_policy_field(self, field: str, value: str) -> None:
        if not self.current_policy_id:
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
            "expiry_date": "Expiry",
            "notes": "Notes",
        }
        label = field_labels.get(field, field)
        response = QtWidgets.QMessageBox.question(
            self,
            "Confirm Change",
            f"Change {label} from {current_value} to {value}?",
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
        if field == "expiry_date":
            if current_version_id:
                self.conn.execute(
                    "UPDATE policy_versions SET review_due_date = ? WHERE id = ?",
                    (value, current_version_id),
                )
            else:
                self.conn.execute(
                    "UPDATE policies SET review_due_date = ? WHERE id = ?",
                    (value, self.current_policy_id),
                )
        self.conn.commit()
        try:
            actor = os.getlogin()
        except OSError:
            actor = None
        audit.append_event_log(
            self.conn,
            {
                "occurred_at": datetime.utcnow().isoformat(),
                "actor": actor,
                "action": "update_policy_field",
                "entity_type": "policy_version" if current_version_id else "policy",
                "entity_id": current_version_id or self.current_policy_id,
                "details": f"{field}: {current_value} -> {value}",
            },
        )
        self._refresh_policies(clear_selection=False)
        self._load_policy_detail(self.current_policy_id)
        self._load_audit_log()

    def _format_file_size(self, size_bytes: int) -> str:
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
        if not value:
            return ""
        date_value = QtCore.QDate.fromString(value, "yyyy-MM-dd")
        if not date_value.isValid():
            return value
        return date_value.toString("dd/MM/yyyy")

    def _format_datetime_display(self, value: str) -> str:
        if not value:
            return ""
        date_value = QtCore.QDateTime.fromString(value, QtCore.Qt.ISODate)
        if not date_value.isValid():
            return value
        return date_value.date().toString("dd/MM/yyyy")

    def _set_date_field(self, widget: QtWidgets.QDateEdit, value: str | None) -> None:
        min_date = QtCore.QDate(1900, 1, 1)
        widget.setMinimumDate(min_date)
        if value:
            widget.setDisplayFormat("dd/MM/yyyy")
            widget.setDate(QtCore.QDate.fromString(value, "yyyy-MM-dd"))
        else:
            widget.setDate(min_date)
            widget.setSpecialValueText("")
            widget.setDisplayFormat(" ")

    def eventFilter(self, obj: QtCore.QObject, event: QtCore.QEvent) -> bool:
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
        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("Version Metadata")
        layout = QtWidgets.QVBoxLayout(dialog)

        form = QtWidgets.QFormLayout()
        status_combo = QtWidgets.QComboBox()
        status_combo.addItems(["Draft", "Active", "Withdrawn", "Archived"])
        expiry_date = QtWidgets.QDateEdit(QtCore.QDate.currentDate())
        expiry_date.setCalendarPopup(True)
        expiry_date.setDisplayFormat("dd/MM/yyyy")
        expiry_date.setEnabled(True)
        notes_input = QtWidgets.QPlainTextEdit()

        form.addRow("Status", status_combo)
        form.addRow("Expiry", expiry_date)
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

        def update_metadata_state(status: str) -> None:
            is_draft = status == "Draft"
            min_date = QtCore.QDate(1900, 1, 1)
            expiry_date.setMinimumDate(min_date)
            if is_draft:
                expiry_date.setEnabled(False)
                expiry_date.setSpecialValueText("")
                expiry_date.setDate(min_date)
                expiry_date.setDisplayFormat(" ")
            else:
                expiry_date.setEnabled(True)
                expiry_date.setSpecialValueText("")
                expiry_date.setDisplayFormat("dd/MM/yyyy")
                if expiry_date.date() == min_date:
                    expiry_date.setDate(QtCore.QDate.currentDate())
        status_combo.currentTextChanged.connect(update_metadata_state)
        update_metadata_state(status_combo.currentText())

        if dialog.exec() != QtWidgets.QDialog.Accepted:
            return None
        return {
            "status": status_combo.currentText(),
            "expiry_date": "" if not expiry_date.isEnabled() else expiry_date.date().toString("yyyy-MM-dd"),
            "notes": notes_input.toPlainText().strip() or None,
        }

    def _on_status_changed(self, status: str) -> None:
        self._update_policy_field("status", status)

    def _on_expiry_changed(self, value: QtCore.QDate) -> None:
        self._update_policy_field("expiry_date", value.toString("yyyy-MM-dd"))

    def _mark_notes_dirty(self) -> None:
        self._notes_dirty = True

    def _mark_title_dirty(self) -> None:
        self._title_dirty = True

    def _update_policy_title(self, title: str) -> None:
        if not self.current_policy_id:
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
        categories = list_categories(self.conn)
        if selected and selected not in categories:
            categories.append(selected)
        self.detail_category.clear()
        self.detail_category.addItems(categories)
        if selected:
            self.detail_category.setCurrentText(selected)
        else:
            self.detail_category.setCurrentIndex(-1)

    def _set_policy_metadata_enabled(self, enabled: bool) -> None:
        self.detail_title.setEnabled(enabled)
        self.detail_category.setEnabled(enabled)
        self.detail_status.setEnabled(enabled)
        self.detail_expiry.setEnabled(enabled)
        self.detail_notes.setEnabled(enabled)

    def _clear_policy_metadata_fields(self) -> None:
        self.detail_status.blockSignals(True)
        self.detail_expiry.blockSignals(True)
        self.detail_notes.blockSignals(True)
        self.detail_title.blockSignals(True)
        self.detail_category.blockSignals(True)
        self._set_policy_metadata_enabled(False)
        self.detail_title.setText("")
        self.detail_status.setCurrentIndex(-1)
        self._set_date_field(self.detail_expiry, None)
        self.detail_notes.setPlainText("")
        self.detail_category.setCurrentIndex(-1)
        self.detail_status.blockSignals(False)
        self.detail_expiry.blockSignals(False)
        self.detail_notes.blockSignals(False)
        self.detail_category.blockSignals(False)
        self.detail_title.blockSignals(False)
        self._notes_dirty = False
        self._title_dirty = False

    def _on_category_changed(self, category: str) -> None:
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
        self.version_table.setStyleSheet(
            "QTableView::item:selected { background-color: hotpink; }"
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
        self.detail_status = QtWidgets.QComboBox()
        self.detail_status.addItems(["Draft", "Active", "Withdrawn", "Archived"])
        self.detail_status.currentTextChanged.connect(self._on_status_changed)
        self.detail_expiry = QtWidgets.QDateEdit()
        self.detail_expiry.setCalendarPopup(True)
        self.detail_expiry.setDisplayFormat("dd/MM/yyyy")
        self.detail_expiry.dateChanged.connect(self._on_expiry_changed)
        self.detail_notes = QtWidgets.QPlainTextEdit()
        self.detail_notes.setReadOnly(False)
        self.detail_notes.textChanged.connect(self._mark_notes_dirty)
        self.detail_notes.installEventFilter(self)

        form.addRow("Title", self.detail_title)
        form.addRow("Category", self.detail_category)
        form.addRow("Status", self.detail_status)
        form.addRow("Expiry", self.detail_expiry)
        form.addRow("Notes", self.detail_notes)

        button_row = QtWidgets.QHBoxLayout()
        ratify_button = QtWidgets.QPushButton("Mark Ratified")
        ratify_button.clicked.connect(self._mark_ratified)
        unratify_button = QtWidgets.QPushButton("Mark Unratified")
        unratify_button.clicked.connect(self._mark_unratified)
        set_current_button = QtWidgets.QPushButton("Set Current")
        set_current_button.clicked.connect(self._set_current)
        set_not_current_button = QtWidgets.QPushButton("Set Not Current")
        set_not_current_button.clicked.connect(self._set_not_current)
        open_location_button = QtWidgets.QPushButton("Open Policy Document")
        open_location_button.clicked.connect(self._open_file_location)
        add_version_button = QtWidgets.QPushButton("Add Version")
        add_version_button.clicked.connect(self._upload_version)
        button_row.addWidget(add_version_button)
        button_row.addStretch(2)
        button_row.addWidget(ratify_button)
        button_row.addWidget(unratify_button)
        button_row.addStretch(2)
        button_row.addWidget(set_current_button)
        button_row.addWidget(set_not_current_button)
        button_row.addStretch(2)
        button_row.addWidget(open_location_button)

        layout.addWidget(versions)
        layout.addWidget(summary)
        layout.addLayout(button_row)
        return wrapper

    def _build_email_compose(self) -> QtWidgets.QWidget:
        wrapper = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(wrapper)

        policy_group = QtWidgets.QGroupBox("Policies to Send")
        policy_layout = QtWidgets.QVBoxLayout(policy_group)
        select_controls = QtWidgets.QHBoxLayout()
        self.policy_send_select_all = QtWidgets.QPushButton("Select all shown")
        self.policy_send_select_all.clicked.connect(self._toggle_all_send_policies)
        select_controls.addWidget(self.policy_send_select_all)
        self.policy_send_deselect_all = QtWidgets.QPushButton("Deselect all shown")
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
        self.policy_send_table.itemChanged.connect(self._on_send_policy_item_changed)
        self.policy_send_table.itemClicked.connect(self._on_send_policy_item_clicked)
        policy_layout.addWidget(self.policy_send_table)

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
        text = text.lower().strip()
        for row in range(self.policy_send_table.rowCount()):
            title = self.policy_send_table.item(row, 1).text().lower()
            category = self.policy_send_table.item(row, 3).text().lower()
            match = text in title or text in category
            self.policy_send_table.setRowHidden(row, not match if text else False)
        self._sync_send_policy_select_all()

    def _visible_policy_rows(self) -> list[int]:
        return [
            row
            for row in range(self.policy_send_table.rowCount())
            if not self.policy_send_table.isRowHidden(row)
        ]

    def _sync_send_policy_select_all(self) -> None:
        return

    def _toggle_all_send_policies(self, _: bool) -> None:
        check_state = QtCore.Qt.Checked
        self.policy_send_table.blockSignals(True)
        for row in self._visible_policy_rows():
            item = self.policy_send_table.item(row, 0)
            item.setCheckState(check_state)
        self.policy_send_table.blockSignals(False)
        self._recalculate_attachments()

    def _on_send_policy_item_changed(self, item: QtWidgets.QTableWidgetItem) -> None:
        if item.column() != 0:
            return
        QtCore.QTimer.singleShot(0, self._recalculate_attachments)

    def _on_send_policy_item_clicked(self, item: QtWidgets.QTableWidgetItem) -> None:
        if item.column() != 0:
            return
        QtCore.QTimer.singleShot(0, self._recalculate_attachments)

    def _deselect_all_send_policies(self, _: bool) -> None:
        self.policy_send_table.blockSignals(True)
        for row in self._visible_policy_rows():
            item = self.policy_send_table.item(row, 0)
            item.setCheckState(QtCore.Qt.Unchecked)
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

        if failures:
            QtWidgets.QMessageBox.warning(
                self,
                "Send issues",
                "Email processing completed with errors:\n" + "\n".join(failures),
            )
        else:
            QtWidgets.QMessageBox.information(self, "Sent", "Email processing completed.")

    def _build_audit_log(self) -> QtWidgets.QWidget:
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

        self.audit_table = QtWidgets.QTableWidget(0, 5)
        self.audit_table.setHorizontalHeaderLabels(
            ["Occurred At", "Actor", "Action", "Entity", "Details"]
        )
        self.audit_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.audit_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

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
        start_date = self.audit_start.date().toString("yyyy-MM-dd")
        end_date = self.audit_end.date().toString("yyyy-MM-dd")
        rows = self.conn.execute(
            """
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
            ORDER BY occurred_at DESC
            """,
            (start_date, end_date),
        ).fetchall()
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

    def _export_audit_csv(self) -> None:
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

    def _verify_audit(self) -> None:
        ok, message = audit.verify_event_log(self.conn)
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
