"""Dialog windows used throughout the Policy Watch UI."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Callable

from PyQt5 import QtCore, QtWidgets

from policywatch.services import add_policy_version, create_category, create_policy
from policywatch.ui.style import apply_table_style


class CategoryManagerDialog(QtWidgets.QDialog):
    """Dialog for creating and deleting policy categories."""

    def __init__(self, conn: sqlite3.Connection, on_updated: Callable[[], None], parent=None):
        """Initialize the category management dialog UI."""

        super().__init__(parent)
        self.conn = conn
        self.on_updated = on_updated
        self.setWindowTitle("Manage Categories")
        self.setModal(True)

        self.category_input = QtWidgets.QLineEdit()
        self.category_input.setPlaceholderText("New category name")

        add_button = QtWidgets.QPushButton("Add")
        add_button.clicked.connect(self._add_category)

        delete_button = QtWidgets.QPushButton("Delete Selected")
        delete_button.clicked.connect(self._delete_selected)

        input_row = QtWidgets.QHBoxLayout()
        input_row.addWidget(self.category_input)
        input_row.addWidget(add_button)
        input_row.addWidget(delete_button)

        self.table = QtWidgets.QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["ID", "Name"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        apply_table_style(self.table)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(input_row)
        layout.addWidget(self.table)

        self._load_categories()

    def _load_categories(self) -> None:
        """Populate the category table with current values."""

        rows = self.conn.execute("SELECT id, name FROM categories ORDER BY name").fetchall()
        self.table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            self.table.setItem(row_index, 0, QtWidgets.QTableWidgetItem(str(row["id"])))
            self.table.setItem(row_index, 1, QtWidgets.QTableWidgetItem(row["name"]))

    def _add_category(self) -> None:
        """Add a new category and refresh the view."""

        name = self.category_input.text().strip()
        if not name:
            return
        try:
            create_category(self.conn, name)
        except sqlite3.IntegrityError:
            QtWidgets.QMessageBox.warning(self, "Duplicate", "Category already exists.")
            return
        self.category_input.clear()
        self._load_categories()
        self.on_updated()

    def _delete_selected(self) -> None:
        """Delete the selected category after validating usage."""

        selection = self.table.selectionModel().selectedRows()
        if not selection:
            return
        row = selection[0].row()
        category_id = int(self.table.item(row, 0).text())
        policy_count = self.conn.execute(
            "SELECT COUNT(*) AS count FROM policies WHERE category = (SELECT name FROM categories WHERE id = ?)",
            (category_id,),
        ).fetchone()
        if policy_count and policy_count["count"] > 0:
            QtWidgets.QMessageBox.warning(self, "In Use", "Category is assigned to policies.")
            return
        with self.conn:
            self.conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        self._load_categories()
        self.on_updated()


class PolicyDialog(QtWidgets.QDialog):
    """Dialog for creating a policy and uploading its initial file."""

    def __init__(self, conn: sqlite3.Connection, on_saved: Callable[[], None], parent=None):
        """Initialize the new policy dialog UI."""

        super().__init__(parent)
        self.conn = conn
        self.on_saved = on_saved
        self.setWindowTitle("New Policy")
        self.setModal(True)

        self.title_input = QtWidgets.QLineEdit()
        self.category_combo = QtWidgets.QComboBox()
        self.category_combo.setEditable(False)
        self.status_combo = QtWidgets.QComboBox()
        self.status_combo.addItems(["Draft", "Active", "Withdrawn", "Archived"])
        self.status_combo.currentTextChanged.connect(self._update_metadata_state)

        self.expiry_date = QtWidgets.QDateEdit(QtCore.QDate.currentDate())
        self.expiry_date.setCalendarPopup(True)
        self.expiry_date.setDisplayFormat("dd/MM/yyyy")
        self.expiry_date.setEnabled(True)

        self.notes_input = QtWidgets.QPlainTextEdit()
        self.file_path_input = QtWidgets.QLineEdit()
        self.file_path_input.setReadOnly(True)
        browse_button = QtWidgets.QPushButton("Browse")
        browse_button.clicked.connect(self._browse_file)
        file_row = QtWidgets.QHBoxLayout()
        file_row.addWidget(self.file_path_input)
        file_row.addWidget(browse_button)
        file_container = QtWidgets.QWidget()
        file_container.setLayout(file_row)

        form = QtWidgets.QFormLayout()
        form.addRow("Title", self.title_input)
        form.addRow("Category", self.category_combo)
        form.addRow("Status", self.status_combo)
        form.addRow("Expiry", self.expiry_date)
        form.addRow("Notes", self.notes_input)
        form.addRow("Policy File", file_container)

        self.save_button = QtWidgets.QPushButton("Save")
        self.save_button.clicked.connect(self._save)
        cancel_button = QtWidgets.QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)

        button_row = QtWidgets.QHBoxLayout()
        button_row.addStretch(1)
        button_row.addWidget(self.save_button)
        button_row.addWidget(cancel_button)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addLayout(button_row)

        self._load_categories()
        self._update_metadata_state(self.status_combo.currentText())

    def _load_categories(self) -> None:
        """Load categories into the dropdown and toggle save availability."""

        rows = self.conn.execute("SELECT name FROM categories ORDER BY name").fetchall()
        self.category_combo.clear()
        self.category_combo.addItems([row["name"] for row in rows])
        has_categories = bool(rows)
        self.save_button.setEnabled(has_categories)
        if not has_categories:
            QtWidgets.QMessageBox.warning(
                self,
                "Missing Categories",
                "Create at least one category before adding policies.",
            )

    def _save(self) -> None:
        """Persist the policy and its initial version."""

        title = self.title_input.text().strip()
        category = self.category_combo.currentText().strip()
        if not title or not category:
            QtWidgets.QMessageBox.warning(self, "Missing", "Title and category are required.")
            return
        file_path = self.file_path_input.text().strip()
        if not file_path:
            QtWidgets.QMessageBox.warning(self, "Missing", "Select a policy document.")
            return
        policy_id = create_policy(
            self.conn,
            title=title,
            category=category,
            status=self.status_combo.currentText(),
            expiry=self._expiry_value(),
            notes=self.notes_input.toPlainText().strip() or None,
            created_by_user_id=None,
        )
        try:
            add_policy_version(
                self.conn,
                policy_id,
                Path(file_path),
                None,
                {
                    "status": self.status_combo.currentText(),
                    "expiry_date": self._expiry_value(),
                    "notes": self.notes_input.toPlainText().strip() or None,
                },
            )
        except ValueError as exc:
            QtWidgets.QMessageBox.warning(self, "No Change", str(exc))
            return
        self.on_saved()
        self.accept()

    def _browse_file(self) -> None:
        """Open a file chooser for the policy document."""

        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Policy Document")
        if file_path:
            self.file_path_input.setText(file_path)

    def _update_metadata_state(self, status: str) -> None:
        """Enable or disable expiry date based on the selected status."""

        is_draft = status == "Draft"
        min_date = QtCore.QDate(1900, 1, 1)
        self.expiry_date.setMinimumDate(min_date)
        if is_draft:
            self.expiry_date.setEnabled(False)
            self.expiry_date.setSpecialValueText("")
            self.expiry_date.setDate(min_date)
            self.expiry_date.setDisplayFormat(" ")
        else:
            self.expiry_date.setEnabled(True)
            self.expiry_date.setSpecialValueText("")
            self.expiry_date.setDisplayFormat("dd/MM/yyyy")
            if self.expiry_date.date() == min_date:
                self.expiry_date.setDate(QtCore.QDate.currentDate())

    def _expiry_value(self) -> str:
        """Return the expiry date value or empty string for draft policies."""

        if not self.expiry_date.isEnabled():
            return ""
        return self.expiry_date.date().toString("yyyy-MM-dd")
