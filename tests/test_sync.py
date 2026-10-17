"""Tests for the sync's time handling. Run them with:  uv run pytest"""

from datetime import datetime, timedelta, timezone

from callguard.sources import changed_query
from callguard.sync import utc, windows


def test_nvd_times_without_a_zone_are_utc():
    assert utc("2026-10-16T20:17:52.880") == datetime(2026, 10, 16, 20, 17, 52, 880000, tzinfo=timezone.utc)


def test_windows_stay_within_nvds_120_day_limit():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    parts = list(windows(start, start + timedelta(days=300)))
    assert len(parts) == 3
    assert all(end - begin <= timedelta(days=120) for begin, end in parts)
    assert parts[0][0] == start and parts[-1][1] == start + timedelta(days=300)
    assert all(parts[i][1] == parts[i + 1][0] for i in range(len(parts) - 1))  # no gaps, no overlaps


def test_changed_query_format():
    t = datetime(2026, 10, 17, 10, 0, tzinfo=timezone.utc)
    assert changed_query(t, t + timedelta(hours=2)) == (
        "lastModStartDate=2026-10-17T10%3A00%3A00.000%2B00%3A00&lastModEndDate=2026-10-17T12%3A00%3A00.000%2B00%3A00")
