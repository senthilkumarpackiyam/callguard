"""Automated tests for the version checker, using real cases from the exam (eval/questions.toml).

Run them with:  uv run pytest
"""

import json
from pathlib import Path

import pytest

from callguard.versions import check, compare, parse

RECORDS = {r["id"]: r for r in (json.loads(line) for line in
                                open(Path(__file__).resolve().parents[1] / "data" / "processed" / "cves.jsonl"))}


@pytest.mark.parametrize("lower, higher", [
    ("9.8.1.201", "9.8.2.0"),
    ("14.0", "14SU2"),        # numbers sort before letters
    ("14SU2", "14su5"),       # Cisco service updates, any case
    ("14", "14SU1"),          # a release comes before its service updates
    ("5.1.0", "5.1.0.SP6"),
    ("12.6(1)ES9", "12.6(2)"),
    ("R6.4.0.136", "6.4.0.4006"),  # a leading R is ignored
])
def test_ordering(lower, higher):
    assert compare(parse(lower), parse(higher)) == -1


def test_trailing_zeros_are_equal():
    assert compare(parse("16.0"), parse("16")) == 0


@pytest.mark.parametrize("cve, version, expected", [
    ("CVE-2026-20362", "12.6(2)ES3", "affected"),      # V1: on Cisco's list of builds
    ("CVE-2026-20362", "12.6(2)ES99", "not affected"),  # not on the list
    ("CVE-2024-41713", "9.8.1.201", "affected"),       # V2: "up to and including"
    ("CVE-2024-41713", "9.8.2.0", "not affected"),     # V3: after the range
    ("CVE-2025-52913", "9.8.2.0", "unknown"),          # V3: versions only in the description
    ("CVE-2022-26499", "18.9.0", "affected"),          # V4
    ("CVE-2022-26651", "18.9.0", "affected"),          # V4
    ("CVE-2022-26651", "18.11.2", "not affected"),     # the fixed version
    ("CVE-2017-14100", "18.9.0", "not affected"),      # an older Asterisk branch
    ("CVE-2026-20045", "14SU2", "affected"),           # V5: "from 12.5 before 14su5"
    ("CVE-2026-20230", "14SU2", "affected"),           # V5
    ("CVE-2026-20045", "14SU5", "not affected"),       # the end of the range is excluded
    ("CVE-2025-64328", "17.0.2.40", "affected"),       # ">= 17.0.2.36, < 17.0.3"
    ("CVE-2025-64328", "17.0.3", "not affected"),
])
def test_exam_cases(cve, version, expected):
    assert check(RECORDS[cve], version)["status"] == expected


def test_garbled_version_text():
    # CISA wrote '9.8-SP1-\/9.8.1.5\/'; it means 9.8.1.5, so 9.8.2.0 is after the range
    assert parse("9.8-SP1-\\/9.8.1.5\\/") == parse("9.8.1.5")
    assert check(RECORDS["CVE-2024-35287"], "9.8.2.0")["status"] == "not affected"


def test_sources_that_disagree_are_reported():
    # NVD: up to and including 9.8.1.201. CISA: before 9.8.2.12. Cautious answer, with the disagreement named
    result = check(RECORDS["CVE-2024-47223"], "9.8.2.0")
    assert result["status"] == "affected"
    assert "disagree" in result["because"]
