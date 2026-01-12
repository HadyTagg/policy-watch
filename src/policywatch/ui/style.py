"""Shared styling helpers for Policy Watch UI components."""

from __future__ import annotations

from PyQt5 import QtWidgets

TABLE_STYLESHEET = """
QTableWidget {
    color: #ffffff;
}
QHeaderView::section {
    color: #ffffff;
}
QTableView::item:selected {
    background-color: hotpink;
}
"""


def apply_table_style(table: QtWidgets.QTableWidget) -> None:
    """Apply consistent styling to table widgets."""

    table.setStyleSheet(TABLE_STYLESHEET)
