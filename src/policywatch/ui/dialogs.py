from __future__ import annotations

import datetime
import sqlite3
from typing import Callable

from PySide6 import QtCore, QtWidgets

from policywatch.policies import slugify


class CategoryManagerDialog(QtWidgets.QDialog):
    def __init__(self, conn: sqlite3.Connection, on_updated: Callable[[], None], parent=None):
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

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(input_row)
        layout.addWidget(self.table)

        self._load_categories()

    def _load_categories(self) -> None:
        rows = self.conn.execute("SELECT id, name FROM categories ORDER BY name").fetchall()
        self.table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            self.table.setItem(row_index, 0, QtWidgets.QTableWidgetItem(str(row["id"])))
            self.table.setItem(row_index, 1, QtWidgets.QTableWidgetItem(row["name"]))

    def _add_category(self) -> None:
        name = self.category_input.text().strip()
        if not name:
            return
        created_at = datetime.datetime.utcnow().isoformat()
        try:
            with self.conn:
                self.conn.execute(
                    "INSERT INTO categories (name, created_at) VALUES (?, ?)",
                    (name, created_at),
                )
        except sqlite3.IntegrityError:
            QtWidgets.QMessageBox.warning(self, "Duplicate", "Category already exists.")
            return
        self.category_input.clear()
        self._load_categories()
        self.on_updated()

    def _delete_selected(self) -> None:
        selection = self.table.selectionModel().selectedRows()
        if not selection:
            return
        row = selection[0].row()
        category_id = int(self.table.item(row, 0).text())
        with self.conn:
            self.conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        self._load_categories()
        self.on_updated()


class PolicyDialog(QtWidgets.QDialog):
    def __init__(self, conn: sqlite3.Connection, on_saved: Callable[[], None], parent=None):
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

        self.effective_date = QtWidgets.QDateEdit(QtCore.QDate.currentDate())
        self.effective_date.setCalendarPopup(True)
        self.review_due_date = QtWidgets.QDateEdit(QtCore.QDate.currentDate())
        self.review_due_date.setCalendarPopup(True)
        self.expiry_date = QtWidgets.QDateEdit(QtCore.QDate.currentDate())
        self.expiry_date.setCalendarPopup(True)

        self.owner_input = QtWidgets.QLineEdit()
        self.notes_input = QtWidgets.QPlainTextEdit()

        form = QtWidgets.QFormLayout()
        form.addRow("Title", self.title_input)
        form.addRow("Category", self.category_combo)
        form.addRow("Status", self.status_combo)
        form.addRow("Effective Date", self.effective_date)
        form.addRow("Review Due", self.review_due_date)
        form.addRow("Expiry", self.expiry_date)
        form.addRow("Owner", self.owner_input)
        form.addRow("Notes", self.notes_input)

        save_button = QtWidgets.QPushButton("Save")
        save_button.clicked.connect(self._save)
        cancel_button = QtWidgets.QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)

        button_row = QtWidgets.QHBoxLayout()
        button_row.addStretch(1)
        button_row.addWidget(save_button)
        button_row.addWidget(cancel_button)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addLayout(button_row)

        self._load_categories()

    def _load_categories(self) -> None:
        rows = self.conn.execute("SELECT name FROM categories ORDER BY name").fetchall()
        self.category_combo.clear()
        self.category_combo.addItems([row["name"] for row in rows])

    def _save(self) -> None:
        title = self.title_input.text().strip()
        category = self.category_combo.currentText().strip()
        if not title or not category:
            QtWidgets.QMessageBox.warning(self, "Missing", "Title and category are required.")
            return

        created_at = datetime.datetime.utcnow().isoformat()
        slug = slugify(title)
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO policies (
                    title, slug, category, status, ratified, ratified_at, ratified_by_user_id,
                    effective_date, review_due_date, expiry_date, owner, notes,
                    current_version_id, created_at, created_by_user_id
                ) VALUES (?, ?, ?, ?, 0, NULL, NULL, ?, ?, ?, ?, ?, NULL, ?, NULL)
                """,
                (
                    title,
                    slug,
                    category,
                    self.status_combo.currentText(),
                    self.effective_date.date().toString("yyyy-MM-dd"),
                    self.review_due_date.date().toString("yyyy-MM-dd"),
                    self.expiry_date.date().toString("yyyy-MM-dd"),
                    self.owner_input.text().strip() or None,
                    self.notes_input.toPlainText().strip() or None,
                    created_at,
                ),
            )
        self.on_saved()
        self.accept()
