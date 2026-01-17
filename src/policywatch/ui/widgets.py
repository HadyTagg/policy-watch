"""Reusable UI widgets and delegates for Policy Watch."""

from __future__ import annotations

from PyQt5 import QtCore, QtGui, QtWidgets

from policywatch.ui import theme

PILL_STYLE_MAP = {
    "draft": theme.STATUS_COLORS["neutral"],
    "active": theme.STATUS_COLORS["info"],
    "withdrawn": theme.STATUS_COLORS["warning"],
    "missing": theme.STATUS_COLORS["danger"],
    "archived": theme.STATUS_COLORS["neutral"],
    "no version": theme.STATUS_COLORS["neutral"],
    "ratified": theme.STATUS_COLORS["info"],
    "awaiting": theme.STATUS_COLORS["warning"],
    "overdue": theme.STATUS_COLORS["danger"],
    "due soon": theme.STATUS_COLORS["warning"],
    "in date": theme.STATUS_COLORS["info"],
    "review due": theme.STATUS_COLORS["warning"],
    "review scheduled": theme.STATUS_COLORS["neutral"],
    "ok": theme.STATUS_COLORS["info"],
    "no schedule": theme.STATUS_COLORS["neutral"],
    "current": theme.STATUS_COLORS["info"],
    "not current": theme.STATUS_COLORS["neutral"],
    "yes": theme.STATUS_COLORS["info"],
    "no": theme.STATUS_COLORS["warning"],
}


class KpiCard(QtWidgets.QFrame):
    """Clickable KPI card for dashboard filters."""

    clicked = QtCore.pyqtSignal(str)

    def __init__(self, key: str, title: str, value: str = "0", parent=None) -> None:
        super().__init__(parent)
        self.key = key
        self.setObjectName("KpiCard")
        self.setProperty("active", False)
        self.setCursor(QtCore.Qt.PointingHandCursor)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(
            theme.SPACING["md"],
            theme.SPACING["md"],
            theme.SPACING["md"],
            theme.SPACING["md"],
        )
        layout.setSpacing(theme.SPACING["xs"])

        self.title_label = QtWidgets.QLabel(title)
        self.title_label.setObjectName("KpiTitle")
        self.value_label = QtWidgets.QLabel(value)
        self.value_label.setObjectName("KpiValue")

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addStretch()

    def set_value(self, value: int | str) -> None:
        """Update the displayed KPI value."""

        self.value_label.setText(str(value))

    def set_active(self, active: bool) -> None:
        """Toggle active styling on the card."""

        self.setProperty("active", active)
        self.style().unpolish(self)
        self.style().polish(self)
        self.update()

    def mousePressEvent(self, event: QtGui.QMouseEvent) -> None:
        """Emit clicked signal on left-click."""

        if event.button() == QtCore.Qt.LeftButton:
            self.clicked.emit(self.key)
        super().mousePressEvent(event)


class PillDelegate(QtWidgets.QStyledItemDelegate):
    """Paints pill-style labels inside a table cell."""

    def __init__(
        self,
        style_map: dict[str, dict[str, str]] | None = None,
        parent: QtCore.QObject | None = None,
        default_style: dict[str, str] | None = None,
    ) -> None:
        super().__init__(parent)
        self._style_map = {key.lower(): value for key, value in (style_map or {}).items()}
        self._default_style = default_style

    def paint(
        self,
        painter: QtGui.QPainter,
        option: QtWidgets.QStyleOptionViewItem,
        index: QtCore.QModelIndex,
    ) -> None:
        raw_text = index.data(QtCore.Qt.DisplayRole)
        label = str(raw_text).strip() if raw_text is not None else ""
        if not label:
            super().paint(painter, option, index)
            return

        style = self._style_map.get(label.lower(), self._default_style)
        if not style:
            super().paint(painter, option, index)
            return

        painter.save()
        painter.setRenderHint(QtGui.QPainter.Antialiasing)

        style_option = QtWidgets.QStyleOptionViewItem(option)
        style = style_option.widget.style() if style_option.widget else QtWidgets.QApplication.style()
        style.drawPrimitive(QtWidgets.QStyle.PE_PanelItemViewItem, style_option, painter, style_option.widget)

        font = QtGui.QFont(option.font)
        font.setPointSize(theme.FONT_SIZES["small"])
        font.setWeight(QtGui.QFont.Medium)
        painter.setFont(font)
        metrics = QtGui.QFontMetrics(font)

        padding_x = theme.SPACING["sm"]
        padding_y = theme.SPACING["xs"]
        max_text_width = max(0, option.rect.width() - padding_x * 2 - 8)
        elided_label = metrics.elidedText(label, QtCore.Qt.ElideRight, max_text_width)
        text_width = metrics.horizontalAdvance(elided_label)
        chip_width = min(text_width + padding_x * 2, option.rect.width() - 6)
        chip_height = min(metrics.height() + padding_y * 2, option.rect.height() - 6)

        chip_rect = QtCore.QRect(option.rect)
        chip_rect.setWidth(chip_width)
        chip_rect.setHeight(chip_height)
        chip_rect.moveLeft(option.rect.left() + (option.rect.width() - chip_rect.width()) // 2)
        chip_rect.moveTop(option.rect.top() + (option.rect.height() - chip_rect.height()) // 2)

        painter.setBrush(QtGui.QColor(style["bg"]))
        painter.setPen(QtGui.QPen(QtGui.QColor(style["border"])))
        radius = chip_rect.height() / 2
        painter.drawRoundedRect(chip_rect, radius, radius)

        painter.setPen(QtGui.QColor(style["fg"]))
        painter.drawText(chip_rect, QtCore.Qt.AlignCenter, elided_label)
        painter.restore()

    def sizeHint(self, option: QtWidgets.QStyleOptionViewItem, index: QtCore.QModelIndex) -> QtCore.QSize:
        size = super().sizeHint(option, index)
        return QtCore.QSize(size.width(), max(size.height(), 28))


def apply_pill_delegate(
    table: QtWidgets.QTableWidget,
    columns: list[int | str] | int | str,
    style_map: dict[str, dict[str, str]] | None = None,
    default_style: dict[str, str] | None = None,
) -> None:
    """Apply a shared pill delegate to the provided columns."""

    if isinstance(columns, (int, str)):
        columns = [columns]
    delegate = PillDelegate(style_map or PILL_STYLE_MAP, table, default_style=default_style)
    for column in columns:
        if isinstance(column, int):
            table.setItemDelegateForColumn(column, delegate)
            continue
        match_index = None
        for idx in range(table.columnCount()):
            header_item = table.horizontalHeaderItem(idx)
            if header_item and header_item.text().strip().lower() == column.strip().lower():
                match_index = idx
                break
        if match_index is not None:
            table.setItemDelegateForColumn(match_index, delegate)
