"""Tests for what code tells the answer-writing model (no AI calls). Run them with:  uv run pytest"""

from callguard.answer import patch_order
from callguard.retrieve import Hit


def record(cve, kev, epss, cvss):
    return {"id": cve, "exploited": {"since": "2025-01-07"} if kev else None, "epss": {"score": epss},
            "cvss": {"score": cvss}}


def test_patch_order_follows_the_rule_not_the_search_order():
    # M4: the CVE named in the question is found first, but the CVE it chains with has the higher forecast
    hits = [Hit(record("CVE-2024-55550", True, 0.38, 2.7), "exact lookup"),
            Hit(record("CVE-2024-41713", True, 0.97, 9.1), "mentioned in CVE-2024-55550"),
            Hit(record("CVE-2024-35286", False, 0.99, 9.8), "patch-priority rule")]
    assert patch_order(hits) == ["CVE-2024-41713", "CVE-2024-55550", "CVE-2024-35286"]


def test_patch_order_leaves_out_versions_not_affected():
    hits = [Hit(record("CVE-A", True, 0.9, 9.0), "search", {"status": "not affected", "because": "outside"}),
            Hit(record("CVE-B", False, 0.1, 5.0), "search", {"status": "affected", "because": "inside"})]
    assert patch_order(hits) == ["CVE-B"]
