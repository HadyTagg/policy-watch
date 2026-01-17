"""Design system tokens and theme helpers for Policy Watch."""

from __future__ import annotations

from PyQt5 import QtGui, QtWidgets

FONT_FALLBACKS = ["Inter", "Segoe UI", "Arial"]
FONT_SIZES = {
    "base": 10,
    "small": 9,
    "heading": 12,
    "title": 14,
}
SPACING = {
    "xs": 4,
    "sm": 8,
    "md": 12,
    "lg": 16,
    "xl": 24,
}
COLORS = {
    "neutral_0": "#f8fafc",
    "neutral_50": "#f1f5f9",
    "neutral_100": "#e2e8f0",
    "neutral_200": "#cbd5e1",
    "neutral_300": "#cbd5e1",
    "neutral_500": "#64748b",
    "neutral_700": "#334155",
    "neutral_900": "#0f172a",
    "accent": "#2563eb",
}
STATUS_COLORS = {
    "neutral": {"bg": "#e2e8f0", "fg": "#1e293b", "border": "#cbd5e1"},
    "info": {"bg": "#dbeafe", "fg": "#1e3a8a", "border": "#93c5fd"},
    "warning": {"bg": "#fef3c7", "fg": "#92400e", "border": "#fcd34d"},
    "danger": {"bg": "#fee2e2", "fg": "#991b1b", "border": "#fca5a5"},
}


def resolve_font_family() -> str:
    """Return the preferred font family available on the system."""

    families = set(QtGui.QFontDatabase().families())
    for candidate in FONT_FALLBACKS:
        if candidate in families:
            return candidate
    return QtGui.QFont().family()


def build_stylesheet(font_family: str) -> str:
    """Construct the application stylesheet using the design tokens."""

    return f"""
    QWidget {{
        font-family: '{font_family}';
        font-size: {FONT_SIZES['base']}pt;
        color: {COLORS['neutral_900']};
    }}
    QMainWindow {{
        background-color: {COLORS['neutral_0']};
    }}
    QToolBar {{
        background: {COLORS['neutral_0']};
        border-bottom: 1px solid {COLORS['neutral_100']};
        spacing: {SPACING['sm']}px;
    }}
    QToolButton {{
        background: {COLORS['neutral_0']};
        border: 1px solid transparent;
        padding: 6px 10px;
        border-radius: 6px;
    }}
    QToolButton:hover {{
        background: {COLORS['neutral_50']};
        border-color: {COLORS['neutral_100']};
    }}
    QLineEdit, QComboBox, QDateEdit, QTextEdit, QPlainTextEdit {{
        background-color: #ffffff;
        border: 1px solid {COLORS['neutral_100']};
        border-radius: 6px;
        padding: 6px 8px;
    }}
    QLineEdit:focus, QComboBox:focus, QDateEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
        border: 1px solid {COLORS['accent']};
    }}
    QComboBox::drop-down {{
        border: none;
        width: 20px;
    }}
    QPushButton {{
        background-color: {COLORS['neutral_0']};
        border: 1px solid {COLORS['neutral_100']};
        border-radius: 6px;
        padding: 6px 12px;
    }}
    QPushButton:hover {{
        background-color: {COLORS['neutral_50']};
        border-color: {COLORS['neutral_300']};
    }}
    QPushButton:disabled {{
        color: {COLORS['neutral_500']};
    }}
    QHeaderView::section {{
        background: {COLORS['neutral_50']};
        color: {COLORS['neutral_700']};
        border: none;
        border-bottom: 1px solid {COLORS['neutral_100']};
        padding: 8px 6px;
        font-weight: 600;
    }}
    QTableView {{
        background: #ffffff;
        border: 1px solid {COLORS['neutral_100']};
        border-radius: 8px;
        gridline-color: transparent;
        selection-background-color: {COLORS['accent']};
        selection-color: #ffffff;
    }}
    QTableView::item {{
        padding: 8px;
    }}
    QTableView::item:hover {{
        background-color: {COLORS['neutral_50']};
    }}
    QTabWidget::pane {{
        border: 1px solid {COLORS['neutral_100']};
        border-top: none;
        border-bottom-left-radius: 6px;
        border-bottom-right-radius: 6px;
    }}
    QTabBar::tab {{
        background: {COLORS['neutral_50']};
        border: 1px solid {COLORS['neutral_100']};
        border-bottom: none;
        padding: 8px 12px;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        margin-right: 4px;
    }}
    QTabBar::tab:selected {{
        background: #ffffff;
        border-color: {COLORS['neutral_300']};
    }}
    QFrame#KpiCard {{
        background: #ffffff;
        border: 1px solid {COLORS['neutral_100']};
        border-radius: 10px;
    }}
    QFrame#KpiCard:hover {{
        background: {COLORS['neutral_50']};
        border-color: {COLORS['accent']};
    }}
    QFrame#KpiCard[active="true"] {{
        background: #eff6ff;
        border-color: {COLORS['accent']};
    }}
    QLabel#KpiTitle {{
        color: {COLORS['neutral_500']};
        font-size: {FONT_SIZES['small']}pt;
    }}
    QLabel#KpiValue {{
        font-size: {FONT_SIZES['title']}pt;
        font-weight: 700;
        color: {COLORS['neutral_900']};
    }}
    """


def apply_theme(app: QtWidgets.QApplication) -> None:
    """Apply the Policy Watch theme to the application."""

    font_family = resolve_font_family()
    app.setStyle("Fusion")
    app.setFont(QtGui.QFont(font_family, FONT_SIZES["base"]))

    palette = app.palette()
    palette.setColor(palette.Window, QtGui.QColor(COLORS["neutral_0"]))
    palette.setColor(palette.WindowText, QtGui.QColor(COLORS["neutral_900"]))
    palette.setColor(palette.Base, QtGui.QColor("#ffffff"))
    palette.setColor(palette.AlternateBase, QtGui.QColor(COLORS["neutral_50"]))
    palette.setColor(palette.Text, QtGui.QColor(COLORS["neutral_900"]))
    palette.setColor(palette.Button, QtGui.QColor(COLORS["neutral_0"]))
    palette.setColor(palette.ButtonText, QtGui.QColor(COLORS["neutral_900"]))
    palette.setColor(palette.Highlight, QtGui.QColor(COLORS["accent"]))
    palette.setColor(palette.HighlightedText, QtGui.QColor("#ffffff"))
    app.setPalette(palette)
    app.setStyleSheet(build_stylesheet(font_family))
