"""Dialog windows used throughout the Policy Watch UI."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Callable

from PyQt5 import QtCore, QtWidgets

from policywatch.core import security
from policywatch.services import (
    add_policy_version,
    create_category,
    create_policy,
    create_user,
    delete_category,
    update_user_password,
)


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
        delete_category(self.conn, category_id)
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

        self.owner_combo = QtWidgets.QComboBox()
        self.owner_combo.setEditable(False)

        self.review_due_date = QtWidgets.QDateEdit(QtCore.QDate.currentDate())
        self.review_due_date.setCalendarPopup(True)
        self.review_due_date.setDisplayFormat("dd/MM/yyyy")
        self.review_due_date.setReadOnly(True)
        self.review_due_date.setButtonSymbols(QtWidgets.QAbstractSpinBox.NoButtons)
        self.review_frequency_combo = QtWidgets.QComboBox()
        self._populate_review_frequency_options(self.review_frequency_combo)
        self.review_frequency_combo.currentIndexChanged.connect(self._auto_update_review_due)

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
        form.addRow("Owner", self.owner_combo)
        form.addRow("Review Due", self.review_due_date)
        form.addRow("Review Frequency", self.review_frequency_combo)
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
        self._load_owners()
        self._update_metadata_state(self.status_combo.currentText())
        self._auto_update_review_due()

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

    def _load_owners(self) -> None:
        """Load owners into the dropdown."""

        rows = self.conn.execute("SELECT username FROM users ORDER BY username").fetchall()
        self.owner_combo.clear()
        self.owner_combo.addItem("Unassigned", None)
        for row in rows:
            username = row["username"]
            if username:
                self.owner_combo.addItem(username, username)

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
            review_due_date=self._review_due_value(),
            review_frequency_months=self._review_frequency_value(),
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
                    "owner": self.owner_combo.currentData(),
                    "review_due_date": self._review_due_value(),
                    "review_frequency_months": self._review_frequency_value(),
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
        """Enable or disable review metadata based on the selected status."""

        is_draft = status == "Draft"
        min_date = QtCore.QDate(1900, 1, 1)
        self.review_due_date.setMinimumDate(min_date)
        if is_draft:
            self.review_due_date.setEnabled(False)
            self.review_due_date.setSpecialValueText("")
            self.review_due_date.setDate(min_date)
            self.review_due_date.setDisplayFormat(" ")
            self.review_due_date.setReadOnly(True)
            self.review_frequency_combo.setEnabled(False)
        else:
            self.review_due_date.setEnabled(True)
            self.review_due_date.setSpecialValueText("")
            self.review_due_date.setDisplayFormat("dd/MM/yyyy")
            self.review_due_date.setReadOnly(True)
            if self.review_due_date.date() == min_date:
                self.review_due_date.setDate(QtCore.QDate.currentDate())
            self.review_frequency_combo.setEnabled(True)
        self._auto_update_review_due()

    def _review_due_value(self) -> str:
        """Return the review due date value or empty string when not set."""

        if not self.review_due_date.isEnabled():
            return ""
        min_date = QtCore.QDate(1900, 1, 1)
        if self.review_due_date.date() == min_date and self.review_due_date.displayFormat().strip() == "":
            return ""
        return self.review_due_date.date().toString("yyyy-MM-dd")

    def _review_frequency_value(self) -> int | None:
        """Return the review frequency value in months."""

        return self.review_frequency_combo.currentData()

    def _auto_update_review_due(self) -> None:
        """Update review due based on frequency."""

        if not self.review_due_date.isEnabled():
            return
        frequency = self.review_frequency_combo.currentData()
        base_date = QtCore.QDate.currentDate()
        if frequency:
            candidate = base_date.addMonths(int(frequency))
            self.review_due_date.setDate(candidate)
            return
        self.review_due_date.setDate(base_date)

    def _populate_review_frequency_options(self, combo: QtWidgets.QComboBox) -> None:
        """Populate review frequency options."""

        combo.clear()
        options = [
            ("None", None),
            ("Annual", 12),
            ("Biannual", 6),
            ("Quarterly", 3),
            ("Monthly", 1),
        ]
        for label, months in options:
            combo.addItem(label, months)


class AccountCreationDialog(QtWidgets.QDialog):
    """Dialog for creating new user accounts."""

    def __init__(self, conn: sqlite3.Connection, created_by_user_id: int | None, parent=None) -> None:
        """Initialize the account creation dialog UI."""

        super().__init__(parent)
        self.conn = conn
        self.created_by_user_id = created_by_user_id
        self.setWindowTitle("Create Account")
        self.setModal(True)

        self.username_input = QtWidgets.QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.role_combo = QtWidgets.QComboBox()
        self.role_combo.addItems(["User", "Admin"])
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.confirm_input = QtWidgets.QLineEdit()
        self.confirm_input.setEchoMode(QtWidgets.QLineEdit.Password)

        form = QtWidgets.QFormLayout()
        form.addRow("Username", self.username_input)
        form.addRow("Role", self.role_combo)
        form.addRow("Password", self.password_input)
        form.addRow("Confirm Password", self.confirm_input)

        create_button = QtWidgets.QPushButton("Create")
        create_button.clicked.connect(self._create_account)
        cancel_button = QtWidgets.QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)

        button_row = QtWidgets.QHBoxLayout()
        button_row.addStretch(1)
        button_row.addWidget(create_button)
        button_row.addWidget(cancel_button)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addLayout(button_row)

    def _create_account(self) -> None:
        """Validate inputs and create the user account."""

        username = self.username_input.text().strip()
        password = self.password_input.text()
        confirm = self.confirm_input.text()
        role = self.role_combo.currentText()
        if not username or not password:
            QtWidgets.QMessageBox.warning(self, "Missing", "Username and password are required.")
            return
        if password != confirm:
            QtWidgets.QMessageBox.warning(self, "Mismatch", "Passwords do not match.")
            return
        if len(password) < 8:
            QtWidgets.QMessageBox.warning(self, "Weak Password", "Passwords must be at least 8 characters.")
            return
        try:
            create_user(self.conn, username, password, role, self.created_by_user_id)
        except sqlite3.IntegrityError:
            QtWidgets.QMessageBox.warning(self, "Duplicate", "That username already exists.")
            return
        QtWidgets.QMessageBox.information(self, "Account Created", "User account created successfully.")
        self.accept()


class PasswordChangeDialog(QtWidgets.QDialog):
    """Dialog for updating the current user's password."""

    def __init__(self, conn: sqlite3.Connection, user_id: int, username: str, parent=None) -> None:
        """Initialize the password change dialog UI."""

        super().__init__(parent)
        self.conn = conn
        self.user_id = user_id
        self.username = username
        self.setWindowTitle("Change Password")
        self.setModal(True)

        self.current_input = QtWidgets.QLineEdit()
        self.current_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.new_input = QtWidgets.QLineEdit()
        self.new_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.confirm_input = QtWidgets.QLineEdit()
        self.confirm_input.setEchoMode(QtWidgets.QLineEdit.Password)

        form = QtWidgets.QFormLayout()
        form.addRow("Current Password", self.current_input)
        form.addRow("New Password", self.new_input)
        form.addRow("Confirm New Password", self.confirm_input)

        save_button = QtWidgets.QPushButton("Save")
        save_button.clicked.connect(self._change_password)
        cancel_button = QtWidgets.QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)

        button_row = QtWidgets.QHBoxLayout()
        button_row.addStretch(1)
        button_row.addWidget(save_button)
        button_row.addWidget(cancel_button)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addLayout(button_row)

    def _change_password(self) -> None:
        """Validate and update the password for the current user."""

        current = self.current_input.text()
        new_password = self.new_input.text()
        confirm = self.confirm_input.text()
        if not current or not new_password:
            QtWidgets.QMessageBox.warning(self, "Missing", "All password fields are required.")
            return
        if new_password != confirm:
            QtWidgets.QMessageBox.warning(self, "Mismatch", "New passwords do not match.")
            return
        if len(new_password) < 8:
            QtWidgets.QMessageBox.warning(self, "Weak Password", "Passwords must be at least 8 characters.")
            return
        row = self.conn.execute(
            "SELECT password_hash, salt FROM users WHERE id = ?",
            (self.user_id,),
        ).fetchone()
        if not row or not security.verify_password(current, row["password_hash"], row["salt"]):
            QtWidgets.QMessageBox.warning(self, "Invalid", "Current password is incorrect.")
            return
        update_user_password(self.conn, self.user_id, new_password)
        QtWidgets.QMessageBox.information(self, "Updated", "Password updated successfully.")
        self.accept()
