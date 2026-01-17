"""Shared UI style mappings for Policy Watch widgets."""

from __future__ import annotations

PILL_STYLES: dict[str, dict[str, str]] = {
    "draft": {"bg": "#e0f2fe", "fg": "#0c4a6e", "border": "#38bdf8"},
    "active": {"bg": "#dcfce7", "fg": "#14532d", "border": "#22c55e"},
    "withdrawn": {"bg": "#ffedd5", "fg": "#7c2d12", "border": "#fb923c"},
    "archived": {"bg": "#e5e7eb", "fg": "#111827", "border": "#9ca3af"},
    "missing": {"bg": "#fee2e2", "fg": "#7f1d1d", "border": "#ef4444"},
    "no version": {"bg": "#e5e7eb", "fg": "#1f2937", "border": "#9ca3af"},
    "ratified": {"bg": "#dcfce7", "fg": "#14532d", "border": "#22c55e"},
    "awaiting": {"bg": "#fef3c7", "fg": "#92400e", "border": "#f59e0b"},
    "awaiting ratification": {"bg": "#fef3c7", "fg": "#92400e", "border": "#f59e0b"},
    "not ratified": {"bg": "#fef3c7", "fg": "#92400e", "border": "#f59e0b"},
    "overdue": {"bg": "#fee2e2", "fg": "#7f1d1d", "border": "#ef4444"},
    "due soon": {"bg": "#fef3c7", "fg": "#92400e", "border": "#f59e0b"},
    "review due": {"bg": "#fef3c7", "fg": "#92400e", "border": "#f59e0b"},
    "in date": {"bg": "#dcfce7", "fg": "#14532d", "border": "#22c55e"},
    "ok": {"bg": "#dcfce7", "fg": "#14532d", "border": "#22c55e"},
    "review scheduled": {"bg": "#e5e7eb", "fg": "#1f2937", "border": "#9ca3af"},
    "no schedule": {"bg": "#e5e7eb", "fg": "#1f2937", "border": "#9ca3af"},
    "current": {"bg": "#dcfce7", "fg": "#14532d", "border": "#22c55e"},
    "not current": {"bg": "#e5e7eb", "fg": "#1f2937", "border": "#9ca3af"},
    "yes": {"bg": "#dcfce7", "fg": "#14532d", "border": "#22c55e"},
    "no": {"bg": "#fef3c7", "fg": "#92400e", "border": "#f59e0b"},
}
