"""Tests for the website's data side: the page, the list, details and downloads (no AI calls).

Run them with:  uv run pytest
"""

from fastapi.testclient import TestClient

from callguard.web import app

client = TestClient(app)


def test_page_and_brand_assets():
    page = client.get("/")
    assert page.status_code == 200 and "CallGuard" in page.text
    assert client.get("/static/brand/logo-mark.svg").status_code == 200


def test_status():
    status = client.get("/api/status").json()
    assert status["records"] > 800 and status["exploited"] >= 11
    assert status["products_covered"] == 24 and "Mitel" in status["vendors"]


def test_list_filters():
    exploited = client.get("/api/cves", params={"exploited": "true", "limit": 200}).json()
    assert exploited["total"] >= 11 and all(c["exploited"] for c in exploited["items"])
    mitel = client.get("/api/cves", params={"vendor": "Mitel", "limit": 200}).json()
    assert mitel["total"] > 0 and all("Mitel" in c["vendors"] for c in mitel["items"])
    critical = client.get("/api/cves", params={"severity": "CRITICAL"}).json()
    assert all(c["severity"] == "CRITICAL" for c in critical["items"])
    found = client.get("/api/cves", params={"q": "CVE-2024-41713"}).json()
    assert [c["id"] for c in found["items"]] == ["CVE-2024-41713"]


def test_newest_first():
    dates = [c["published"] for c in client.get("/api/cves", params={"limit": 50}).json()["items"]]
    assert dates == sorted(dates, reverse=True)


def test_detail():
    record = client.get("/api/cves/cve-2024-41713").json()
    assert record["exploited"]["ransomware"] == "Known" and record["nvd_page"].endswith("CVE-2024-41713")
    assert client.get("/api/cves/CVE-1999-0001").status_code == 404


def test_exports():
    csv = client.get("/api/export/cves.csv", params={"vendor": "Mitel"})
    assert csv.headers["content-type"].startswith("text/csv") and "CVE,Published" in csv.text
    assert client.get("/api/export/cves.xlsx").content[:2] == b"PK"  # Excel files are zip archives
    assert client.get("/api/export/cves.pdf", params={"exploited": "true"}).content[:4] == b"%PDF"
    assert client.get("/api/export/cves.doc").status_code == 404


def test_answer_pdf():
    pdf = client.post("/api/export/answer.pdf", json={
        "question": "What is CVE-2024-41713?",
        "text": "A **critical** flaw [CVE-2024-41713] → see [NVD](https://nvd.nist.gov).\n\n- one\n- two"})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
