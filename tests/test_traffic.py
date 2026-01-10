from datetime import date

from policywatch.traffic import traffic_light_status


def test_traffic_green():
    result = traffic_light_status(
        today=date(2024, 1, 1),
        review_due_date=date(2024, 6, 1),
        expiry_date=date(2025, 1, 1),
        amber_months=2,
        overdue_grace_days=0,
    )
    assert result.status == "Green"
    assert result.reason == "Current"


def test_traffic_amber():
    result = traffic_light_status(
        today=date(2024, 1, 1),
        review_due_date=date(2024, 2, 15),
        expiry_date=date(2025, 1, 1),
        amber_months=2,
        overdue_grace_days=0,
    )
    assert result.status == "Amber"
    assert result.reason == "Review upcoming"


def test_traffic_red_overdue():
    result = traffic_light_status(
        today=date(2024, 3, 2),
        review_due_date=date(2024, 3, 1),
        expiry_date=date(2025, 1, 1),
        amber_months=2,
        overdue_grace_days=0,
    )
    assert result.status == "Red"
    assert result.reason == "Review overdue"


def test_traffic_red_expired():
    result = traffic_light_status(
        today=date(2024, 4, 1),
        review_due_date=date(2024, 3, 1),
        expiry_date=date(2024, 3, 31),
        amber_months=2,
        overdue_grace_days=14,
    )
    assert result.status == "Red"
    assert result.reason == "Expired"
