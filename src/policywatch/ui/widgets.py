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


def _current_theme_colors() -> dict[str, str]:
    """Return theme-aware color tokens for the active application theme."""

    app = QtWidgets.QApplication.instance()
    theme_name = app.property("policywatch_theme") if app else "light"
    if theme_name == "dark":
        return theme.DARK_COLORS
    return theme.COLORS


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


class TimelineStepWidget(QtWidgets.QWidget):
    """Single step widget for the policy lifecycle timeline."""

    def __init__(self, label: str, icon: str, parent=None) -> None:
        super().__init__(parent)
        self._label_text = label
        self._icon_text = icon
        self._state = "upcoming"
        self._diameter = theme.SPACING["xl"] + theme.SPACING["sm"]
        self._border_width = 2

        self.setFocusPolicy(QtCore.Qt.NoFocus)

        self.circle = QtWidgets.QLabel(self._icon_text)
        self.circle.setObjectName("TimelineStepCircle")
        self.circle.setAlignment(QtCore.Qt.AlignCenter)
        self.circle.setFixedSize(self._diameter, self._diameter)
        self.circle.setFocusPolicy(QtCore.Qt.NoFocus)

        self.label = QtWidgets.QLabel(self._label_text)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setWordWrap(False)
        self.label.setFocusPolicy(QtCore.Qt.NoFocus)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(theme.SPACING["xs"])
        layout.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignHCenter)
        layout.addWidget(self.circle, alignment=QtCore.Qt.AlignCenter)
        layout.addWidget(self.label, alignment=QtCore.Qt.AlignCenter)

        self.apply_state(self._state)

    def apply_state(self, state: str) -> None:
        """Apply styling for the requested state."""

        self._state = state
        colors = _current_theme_colors()
        base_color = QtGui.QColor(colors["neutral_0"])
        text_color = QtGui.QColor(colors["neutral_900"])
        muted_text = QtGui.QColor(colors["neutral_500"])
        border_color = QtGui.QColor(colors["neutral_200"])
        accent_color = QtGui.QColor(colors["accent"])
        highlight_text = QtGui.QColor(colors["neutral_0"])

        icon_font = QtGui.QFont(self.circle.font())
        icon_font.setPointSize(theme.FONT_SIZES["heading"])
        icon_font.setWeight(QtGui.QFont.Bold if state == "current" else QtGui.QFont.Medium)

        if state == "completed":
            circle_bg = accent_color
            circle_border = accent_color
            icon_color = highlight_text
            label_color = text_color
            label_weight = QtGui.QFont.Medium
            self.circle.setText("✓")
        elif state == "current":
            circle_bg = base_color
            circle_border = accent_color
            icon_color = accent_color
            label_color = accent_color
            label_weight = QtGui.QFont.Bold
            self.circle.setText(self._icon_text)
        else:
            circle_bg = base_color
            circle_border = border_color
            icon_color = muted_text
            label_color = muted_text
            label_weight = QtGui.QFont.Medium
            self.circle.setText(self._icon_text)

        radius = self._diameter // 2
        self.circle.setStyleSheet(
            f"""
            QLabel#TimelineStepCircle {{
                background-color: {circle_bg.name()};
                border: {self._border_width}px solid {circle_border.name()};
                border-radius: {radius}px;
                color: {icon_color.name()};
            }}
            """.strip()
        )
        self.circle.setFont(icon_font)
        label_font = QtGui.QFont(self.label.font())
        label_font.setWeight(label_weight)
        label_font.setPointSize(theme.FONT_SIZES["small"])
        self.label.setFont(label_font)
        self.label.setStyleSheet(f"color: {label_color.name()};")

        if state == "current":
            glow = QtWidgets.QGraphicsDropShadowEffect(self.circle)
            glow.setBlurRadius(12)
            glow.setOffset(0, 0)
            glow_color = QtGui.QColor(accent_color)
            glow_color.setAlpha(140)
            glow.setColor(glow_color)
            self.circle.setGraphicsEffect(glow)
        else:
            self.circle.setGraphicsEffect(None)


class TimelineConnector(QtWidgets.QFrame):
    """Connector line between timeline steps."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setFocusPolicy(QtCore.Qt.NoFocus)
        self.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.setFixedHeight(2)
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)

    def apply_state(self, state: str) -> None:
        """Apply styling for the connector state."""

        colors = _current_theme_colors()
        border_color = QtGui.QColor(colors["neutral_200"])
        accent_color = QtGui.QColor(colors["accent"])
        line_color = accent_color if state == "completed" else border_color
        self.setStyleSheet(f"background-color: {line_color.name()};")


class PolicyLifecycleTimeline(QtWidgets.QWidget):
    """Visual timeline for the policy version lifecycle."""

    steps = [
        ("Draft", "✎"),
        ("Ratified", "✓"),
        ("Active", "⚡"),
        ("Withdrawn", "⛔"),
        ("Archived", "🗃"),
    ]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setFocusPolicy(QtCore.Qt.NoFocus)
        self._stage = None
        self._connector_wraps: list[QtWidgets.QWidget] = []
        self.setObjectName("PolicyLifecycleTimeline")

        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(theme.SPACING["lg"], theme.SPACING["md"], theme.SPACING["lg"], theme.SPACING["md"])
        layout.setSpacing(theme.SPACING["sm"])
        layout.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignHCenter)

        self._step_widgets: list[TimelineStepWidget] = []
        self._connector_widgets: list[TimelineConnector] = []

        for index, (label, icon) in enumerate(self.steps):
            step = TimelineStepWidget(label, icon, self)
            self._step_widgets.append(step)
            layout.addWidget(step, 0, QtCore.Qt.AlignTop)
            if index < len(self.steps) - 1:
                connector = TimelineConnector(self)
                connector_wrap = QtWidgets.QWidget(self)
                connector_layout = QtWidgets.QVBoxLayout(connector_wrap)
                connector_layout.setContentsMargins(0, 0, 0, 0)
                connector_layout.setSpacing(0)
                connector_layout.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignHCenter)
                connector_layout.addSpacing(step.circle.height() // 2 - connector.height() // 2)
                connector_layout.addWidget(connector, alignment=QtCore.Qt.AlignHCenter)
                self._connector_wraps.append(connector_wrap)
                self._connector_widgets.append(connector)
                layout.addWidget(connector_wrap, 1)

        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.setMinimumHeight(theme.SPACING["xl"] * 3 + theme.SPACING["sm"])
        self.set_stage(None)

    def set_stage(self, stage: str | None) -> None:
        """Update the timeline to reflect the current lifecycle stage."""

        self._stage = stage
        self._apply_styles()

    def _apply_styles(self) -> None:
        self._apply_container_style()
        stages = [label for label, _ in self.steps]
        if self._stage in stages:
            current_index = stages.index(self._stage)
        else:
            current_index = None

        for index, step in enumerate(self._step_widgets):
            if current_index is None:
                state = "upcoming"
            elif index < current_index:
                state = "completed"
            elif index == current_index:
                state = "current"
            else:
                state = "upcoming"
            step.apply_state(state)

        for index, connector in enumerate(self._connector_widgets):
            if current_index is None:
                state = "upcoming"
            elif index < current_index:
                state = "completed"
            else:
                state = "upcoming"
            connector.apply_state(state)

    def _apply_container_style(self) -> None:
        colors = _current_theme_colors()
        background = colors["neutral_50"]
        border = colors["neutral_100"]
        stylesheet = f"""
            #PolicyLifecycleTimeline {{
                background-color: {background};
                border: 1px solid {border};
                border-radius: {theme.SPACING['sm']}px;
            }}
            """.strip()
        if self.styleSheet() != stylesheet:
            self.setStyleSheet(stylesheet)

    def changeEvent(self, event: QtCore.QEvent) -> None:
        """Refresh styles on theme or palette changes."""

        if event.type() in (QtCore.QEvent.PaletteChange, QtCore.QEvent.StyleChange):
            self._apply_styles()
        super().changeEvent(event)


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
