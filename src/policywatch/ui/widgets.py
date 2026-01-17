"""Reusable UI widgets and delegates for Policy Watch."""

from __future__ import annotations

from PyQt5 import QtCore, QtGui, QtWidgets

from policywatch.ui import theme

CHIP_DATA_ROLE = QtCore.Qt.UserRole + 2


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


class StatusChipDelegate(QtWidgets.QStyledItemDelegate):
    """Paints a pill-style status chip inside a table cell."""

    def paint(
        self,
        painter: QtGui.QPainter,
        option: QtWidgets.QStyleOptionViewItem,
        index: QtCore.QModelIndex,
    ) -> None:
        data = index.data(CHIP_DATA_ROLE)
        if not data:
            super().paint(painter, option, index)
            return

        label = data.get("label", "")
        kind = data.get("kind", "neutral")
        colors = theme.STATUS_COLORS.get(kind, theme.STATUS_COLORS["neutral"])

        painter.save()
        painter.setRenderHint(QtGui.QPainter.Antialiasing)

        font = QtGui.QFont(option.font)
        font.setPointSize(theme.FONT_SIZES["small"])
        font.setWeight(QtGui.QFont.Medium)
        painter.setFont(font)
        metrics = QtGui.QFontMetrics(font)

        padding_x = theme.SPACING["sm"]
        padding_y = theme.SPACING["xs"]
        text_width = metrics.horizontalAdvance(label)
        chip_width = text_width + padding_x * 2
        chip_height = metrics.height() + padding_y * 2

        chip_rect = QtCore.QRect(option.rect)
        chip_rect.setWidth(min(chip_width, option.rect.width() - 4))
        chip_rect.setHeight(min(chip_height, option.rect.height() - 4))
        chip_rect.moveLeft(option.rect.left() + (option.rect.width() - chip_rect.width()) // 2)
        chip_rect.moveTop(option.rect.top() + (option.rect.height() - chip_rect.height()) // 2)

        painter.setBrush(QtGui.QColor(colors["bg"]))
        painter.setPen(QtGui.QPen(QtGui.QColor(colors["border"])))
        radius = chip_rect.height() / 2
        painter.drawRoundedRect(chip_rect, radius, radius)

        painter.setPen(QtGui.QColor(colors["fg"]))
        painter.drawText(chip_rect, QtCore.Qt.AlignCenter, label)
        painter.restore()

    def sizeHint(self, option: QtWidgets.QStyleOptionViewItem, index: QtCore.QModelIndex) -> QtCore.QSize:
        size = super().sizeHint(option, index)
        return QtCore.QSize(size.width(), max(size.height(), 36))
