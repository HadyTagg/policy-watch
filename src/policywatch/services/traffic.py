from __future__ import annotations

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class TrafficResult:
    status: str
    reason: str


def _add_months(source: date, months: int) -> date:
    month = source.month - 1 + months
    year = source.year + month // 12
    month = month % 12 + 1
    day = min(source.day, [31, 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1])
    return date(year, month, day)


def traffic_light_status(
    today: date,
    expiry_date: date,
    amber_months: int,
) -> TrafficResult:
    if today > expiry_date:
        return TrafficResult(status="Red", reason="Expired")

    amber_threshold = _add_months(today, amber_months)
    if expiry_date <= amber_threshold:
        return TrafficResult(status="Amber", reason="Review Due")

    return TrafficResult(status="Green", reason="In Date")
