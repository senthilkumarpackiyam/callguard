"""Phase 0 setup check: Python, the .env file, and every outside service CallGuard uses.

Run it with:  uv run scripts/check_setup.py
"""

import os
import subprocess
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv
from langsmith import Client

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")  # loads your keys into this program; they are never printed

SAMPLE_CVE = "CVE-2024-41713"  # Mitel MiCollab flaw; it's in KEV, so every source knows it
PASS, FAIL, TODO = "✅", "❌", "⬜"
results = []
http = httpx.Client(timeout=30, follow_redirects=True,
                    headers={"User-Agent": "callguard-setup-check"})


def report(status, name, detail):
    results.append(status)
    print(f"{status} {name:<11} {detail}")


def check(name, fn):
    """Run one check, turning a crash into a red line instead of stopping the script."""
    try:
        fn()
    except Exception as e:
        report(FAIL, name, f"{type(e).__name__}: {e}")


def python():
    v = sys.version_info
    report(PASS if v[:2] == (3, 12) else FAIL, "Python", f"{v.major}.{v.minor}.{v.micro}")


def env_file():
    if not (ROOT / ".env").exists():
        report(FAIL, ".env", "missing: copy .env.example to .env")
        return
    ignored = subprocess.run(["git", "check-ignore", "-q", ".env"], cwd=ROOT).returncode == 0
    report(PASS if ignored else FAIL, ".env",
           "exists, and Git ignores it" if ignored else "exists, but Git would save it!")


def nvd():
    key = os.getenv("NVD_API_KEY")
    r = http.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                 params={"cveId": SAMPLE_CVE}, headers={"apiKey": key} if key else {})
    if r.status_code != 200:
        report(FAIL, "NVD", f"HTTP {r.status_code} {r.headers.get('message', '')}".strip())
    elif key:
        report(PASS, "NVD", f"key accepted; found {SAMPLE_CVE}")
    else:
        report(PASS, "NVD", "works without a key (optional: NVD_API_KEY gives a 10x higher rate limit)")


def kev():
    r = http.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    r.raise_for_status()
    data = r.json()
    report(PASS, "CISA KEV", f"{len(data['vulnerabilities'])} entries, catalog {data['catalogVersion']}")


def epss():
    r = http.get("https://api.first.org/data/v1/epss", params={"cve": SAMPLE_CVE})
    r.raise_for_status()
    row = r.json()["data"][0]
    report(PASS, "FIRST EPSS", f"{SAMPLE_CVE} scores {float(row['epss']):.2f} on {row['date']}")


def cve_org():
    r = http.get(f"https://cveawg.mitre.org/api/cve/{SAMPLE_CVE}")
    r.raise_for_status()
    report(PASS, "CVE.org", f"{SAMPLE_CVE} is {r.json()['cveMetadata']['state']}")


def nebius():
    key = os.getenv("NEBIUS_API_KEY")
    base = (os.getenv("NEBIUS_BASE_URL") or "https://api.tokenfactory.nebius.com/v1/").rstrip("/")
    if not key:
        report(TODO, "Nebius", "add NEBIUS_API_KEY to .env")
        return
    r = http.get(f"{base}/models", headers={"Authorization": f"Bearer {key}"})
    if r.status_code == 200:
        report(PASS, "Nebius", f"key accepted; {len(r.json().get('data', []))} models available")
    else:
        report(FAIL, "Nebius", f"HTTP {r.status_code}: check NEBIUS_API_KEY and NEBIUS_BASE_URL")


def langsmith():
    if not os.getenv("LANGSMITH_API_KEY"):
        report(PASS, "LangSmith", "optional: no key, so tracing is off (LANGSMITH_API_KEY turns it on)")
        return
    next(iter(Client().list_projects(limit=1)), None)  # raises if the key is rejected
    report(PASS, "LangSmith", "key accepted")


if __name__ == "__main__":
    print("CallGuard setup check\n")
    for name, fn in [("Python", python), (".env", env_file), ("NVD", nvd), ("CISA KEV", kev),
                     ("FIRST EPSS", epss), ("CVE.org", cve_org), ("Nebius", nebius),
                     ("LangSmith", langsmith)]:
        check(name, fn)
    print(f"\n{results.count(PASS)} passed, {results.count(TODO)} waiting for you, "
          f"{results.count(FAIL)} failed")
    sys.exit(1 if FAIL in results else 0)
