"""Reusable UI widgets and delegates for Policy Watch."""

from __future__ import annotations

from PyQt5 import QtCore, QtGui, QtWidgets

from policywatch.ui import theme
from policywatch.ui.styles import PILL_STYLES


FOCUSLESS_TABLE_STYLES = """
QTableView::item:focus {
    outline: none;
    border: none;
}
QTableWidget::item:focus {
    outline: none;
    border: none;
}
""".strip()


def _standard_pixmap(name: str, fallback: QtWidgets.QStyle.StandardPixmap) -> QtWidgets.QStyle.StandardPixmap:
    """Return a standard pixmap if available, otherwise a fallback."""

    return getattr(QtWidgets.QStyle, name, fallback)


STANDARD_ICON_MAP = {
    "add": _standard_pixmap("SP_FileDialogNewFolder", QtWidgets.QStyle.SP_FileDialogNewFolder),
    "edit": _standard_pixmap("SP_FileDialogDetailedView", QtWidgets.QStyle.SP_FileDialogDetailedView),
    "delete": _standard_pixmap("SP_TrashIcon", QtWidgets.QStyle.SP_DialogDiscardButton),
    "archive": _standard_pixmap("SP_DialogDiscardButton", QtWidgets.QStyle.SP_DialogDiscardButton),
    "save": _standard_pixmap("SP_DialogSaveButton", QtWidgets.QStyle.SP_DialogSaveButton),
    "export": _standard_pixmap("SP_ArrowDown", QtWidgets.QStyle.SP_DialogSaveButton),
    "backup": _standard_pixmap("SP_DialogSaveButton", QtWidgets.QStyle.SP_DialogSaveButton),
    "send": _standard_pixmap("SP_ArrowRight", QtWidgets.QStyle.SP_CommandLink),
    "refresh": _standard_pixmap("SP_BrowserReload", QtWidgets.QStyle.SP_BrowserReload),
    "search": _standard_pixmap("SP_FileDialogContentsView", QtWidgets.QStyle.SP_FileDialogContentsView),
    "open": _standard_pixmap("SP_DialogOpenButton", QtWidgets.QStyle.SP_DialogOpenButton),
    "view": _standard_pixmap("SP_FileDialogInfoView", QtWidgets.QStyle.SP_FileDialogInfoView),
    "approve": _standard_pixmap("SP_DialogApplyButton", QtWidgets.QStyle.SP_DialogApplyButton),
    "cancel": _standard_pixmap("SP_DialogCancelButton", QtWidgets.QStyle.SP_DialogCancelButton),
    "print": _standard_pixmap("SP_PrinterIcon", QtWidgets.QStyle.SP_FileIcon),
    "login": _standard_pixmap("SP_DialogOkButton", QtWidgets.QStyle.SP_DialogOkButton),
    "select": _standard_pixmap("SP_DialogYesButton", QtWidgets.QStyle.SP_DialogYesButton),
    "deselect": _standard_pixmap("SP_DialogNoButton", QtWidgets.QStyle.SP_DialogNoButton),
    "folder": _standard_pixmap("SP_DirOpenIcon", QtWidgets.QStyle.SP_DirOpenIcon),
}


def set_button_icon(button: QtWidgets.QAbstractButton, icon_name: str, size: int = 16) -> None:
    """Assign a standard icon to a button using a shared name map."""

    pixmap = STANDARD_ICON_MAP.get(icon_name)
    if pixmap is None:
        return
    icon = button.style().standardIcon(pixmap)
    button.setIcon(icon)
    button.setIconSize(QtCore.QSize(size, size))


class KpiCard(QtWidgets.QFrame):
    """Clickable KPI card for dashboard filters."""

    clicked = QtCore.pyqtSignal(str)

    def __init__(self, key: str, title: str, value: str = "0", parent=None) -> None:
        super().__init__(parent)
        self.key = key
        self.setObjectName("KpiCard")
        self.setProperty("active", False)
        self.setCursor(QtCore.Qt.PointingHandCursor)
        self.setMinimumHeight(theme.SPACING["xl"] * 5)
        self.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding,
            QtWidgets.QSizePolicy.Expanding,
        )

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(
            theme.SPACING["md"],
            theme.SPACING["md"],
            theme.SPACING["md"],
            theme.SPACING["md"],
        )
        layout.setSpacing(theme.SPACING["sm"])
        layout.setAlignment(QtCore.Qt.AlignCenter)

        self.title_label = QtWidgets.QLabel(title)
        self.title_label.setObjectName("KpiTitle")
        self.title_label.setAlignment(QtCore.Qt.AlignCenter)
        title_font = QtGui.QFont(self.title_label.font())
        title_font.setPointSize(theme.FONT_SIZES["small"])
        title_font.setWeight(QtGui.QFont.Medium)
        self.title_label.setFont(title_font)
        self.value_label = QtWidgets.QLabel(value)
        self.value_label.setObjectName("KpiValue")
        self.value_label.setAlignment(QtCore.Qt.AlignCenter)
        value_font = QtGui.QFont(self.value_label.font())
        value_font.setPointSize(36)
        value_font.setWeight(QtGui.QFont.Bold)
        self.value_label.setFont(value_font)

        layout.addWidget(self.title_label, alignment=QtCore.Qt.AlignCenter)
        layout.addWidget(self.value_label, alignment=QtCore.Qt.AlignCenter)

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

        if option.rect.width() <= 8 or option.rect.height() <= 8:
            super().paint(painter, option, index)
            return

        painter.save()
        painter.setRenderHint(QtGui.QPainter.Antialiasing)

        style_option = QtWidgets.QStyleOptionViewItem(option)
        widget_style = (
            style_option.widget.style() if style_option.widget else QtWidgets.QApplication.style()
        )
        widget_style.drawPrimitive(
            QtWidgets.QStyle.PE_PanelItemViewItem,
            style_option,
            painter,
            style_option.widget,
        )

        font = QtGui.QFont(option.font)
        font.setPointSize(theme.FONT_SIZES["small"])
        font.setWeight(QtGui.QFont.Medium)
        painter.setFont(font)
        metrics = QtGui.QFontMetrics(font)

        padding_x = theme.SPACING["sm"]
        padding_y = theme.SPACING["xs"]
        max_text_width = max(0, option.rect.width() - padding_x * 2 - 8)
        if max_text_width <= 0:
            painter.restore()
            super().paint(painter, option, index)
            return
        elided_label = metrics.elidedText(label, QtCore.Qt.ElideRight, max_text_width)
        text_width = metrics.horizontalAdvance(elided_label)
        chip_width = min(text_width + padding_x * 2, option.rect.width() - 6)
        chip_height = min(metrics.height() + padding_y * 2, option.rect.height() - 6)
        if chip_width <= 0 or chip_height <= 0:
            painter.restore()
            super().paint(painter, option, index)
            return

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


class EnumComboPillDelegate(PillDelegate):
    """Combo box editor delegate that preserves pill styling."""

    def __init__(
        self,
        options: list[str],
        on_commit,
        parent: QtCore.QObject | None = None,
        popup_delay_ms: int = 0,
        style_map: dict[str, dict[str, str]] | None = None,
        default_style: dict[str, str] | None = None,
    ) -> None:
        super().__init__(style_map or PILL_STYLES, parent, default_style=default_style)
        self._options = options
        self._on_commit = on_commit
        self._popup_delay_ms = max(0, int(popup_delay_ms))

    def createEditor(
        self,
        parent: QtWidgets.QWidget,
        option: QtWidgets.QStyleOptionViewItem,
        index: QtCore.QModelIndex,
    ) -> QtWidgets.QWidget:
        combo = QtWidgets.QComboBox(parent)
        combo.addItems(self._options)
        combo.setEditable(False)
        combo.currentIndexChanged.connect(self._commit_combo_selection)
        QtCore.QTimer.singleShot(self._popup_delay_ms, combo.showPopup)
        return combo

    def setEditorData(self, editor: QtWidgets.QWidget, index: QtCore.QModelIndex) -> None:
        if not isinstance(editor, QtWidgets.QComboBox):
            super().setEditorData(editor, index)
            return
        value = str(index.data(QtCore.Qt.DisplayRole) or "")
        index_value = editor.findText(value)
        if index_value >= 0:
            editor.setCurrentIndex(index_value)

    def setModelData(
        self,
        editor: QtWidgets.QWidget,
        model: QtCore.QAbstractItemModel,
        index: QtCore.QModelIndex,
    ) -> None:
        if not isinstance(editor, QtWidgets.QComboBox):
            super().setModelData(editor, model, index)
            return
        value = editor.currentText()
        if callable(self._on_commit):
            self._on_commit(index, value)

    def _commit_combo_selection(self) -> None:
        editor = self.sender()
        if not isinstance(editor, QtWidgets.QComboBox):
            return
        self.commitData.emit(editor)
        self.closeEditor.emit(editor, QtWidgets.QAbstractItemDelegate.NoHint)


def apply_pill_delegate(
    table: QtWidgets.QTableWidget,
    columns: list[int | str] | int | str,
    style_map: dict[str, dict[str, str]] | None = None,
    default_style: dict[str, str] | None = None,
) -> None:
    """Apply a shared pill delegate to the provided columns."""

    if isinstance(columns, (int, str)):
        columns = [columns]
    delegate = PillDelegate(style_map or PILL_STYLES, table, default_style=default_style)
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


def apply_table_focusless(table: QtWidgets.QAbstractItemView) -> None:
    """Ensure table views do not draw a focus rectangle around cells."""

    table.setStyle(theme.FocuslessTableStyle(table.style()))
    current_stylesheet = table.styleSheet()
    if FOCUSLESS_TABLE_STYLES in current_stylesheet:
        return
    combined = "\n".join(part for part in [current_stylesheet, FOCUSLESS_TABLE_STYLES] if part)
    table.setStyleSheet(combined)
