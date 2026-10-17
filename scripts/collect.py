"""Phase 2 pipeline: collect, filter, enrich, clean and save CallGuard's CVE records.

Run it with:  uv run scripts/collect.py
Re-clean the last download without fetching again:  uv run scripts/collect.py --offline

Writes data/processed/cves.jsonl (one clean record per line) and data/processed/manifest.json.
Raw downloads go to data/raw/, which Git doesn't save.
"""

import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from callguard.clean import clean_record
from callguard.products import load_products, match_products
from callguard.sources import Sources, keyword_query

ROOT = Path(__file__).resolve().parent.parent
RAW, PROCESSED = ROOT / "data" / "raw", ROOT / "data" / "processed"

# Ask NVD for every CVE that mentions one of these vendors, then keep only our products:
# like pulling every ticket for an account, then filtering by product line.
VENDOR_QUERIES = [("Cisco", False), ("Avaya", False), ("Mitel", False), ("ShoreTel", False), ("Aastra", False),
                  ("Asterisk", False), ("Digium", False), ("Sangoma", False), ("FreePBX", False),
                  ("Genesys", False), ("Verint", False), ("Five9", False), ("Amazon Connect", True),
                  ("CXone", False), ("inContact", False), ("Twilio", False)]


def main():
    load_dotenv(ROOT / ".env")
    offline = "--offline" in sys.argv
    started = time.time()
    sources = Sources(os.getenv("NVD_API_KEY"))
    products = load_products()
    (RAW / "nvd").mkdir(parents=True, exist_ok=True)
    PROCESSED.mkdir(parents=True, exist_ok=True)

    raw = {}
    if offline:
        print("1. Collect: reusing the last download in data/raw/")
        for path in sorted((RAW / "nvd").glob("*.json")):
            for v in json.loads(path.read_text())["vulnerabilities"]:
                raw[v["cve"]["id"]] = v["cve"]
    else:
        print("1. Collect: asking NVD for each vendor's CVEs (a few seconds' pause between requests)")
        for keyword, exact in VENDOR_QUERIES:
            slug = re.sub(r"\W+", "_", keyword.lower())
            for start, total, page in sources.nvd_pages(keyword_query(keyword, exact)):
                (RAW / "nvd" / f"{slug}_{start}.json").write_text(json.dumps(page))
                for v in page["vulnerabilities"]:
                    raw[v["cve"]["id"]] = v["cve"]
                print(f"   {keyword}: {min(start + 2000, total)} of {total}")
    print(f"   {len(raw)} different CVEs mention these vendors")

    print("2. Filter: keeping CVEs for the products in config/products.toml")
    kept, counts = {}, Counter()
    for cve_id, cve in raw.items():
        found, matched_by = match_products(cve, products)
        if any(p.scope in ("in", "cloud") for p in found):
            kept[cve_id] = (cve, found, matched_by)
            counts[f"kept (matched by {matched_by})"] += 1
        else:
            counts["dropped: out-of-scope products" if found else "dropped: other products"] += 1
    for label, n in sorted(counts.items()):
        print(f"   {label}: {n}")

    print("3. Enrich: adding CISA KEV and FIRST EPSS")
    if offline:
        kev, epss = json.loads((RAW / "kev.json").read_text()), json.loads((RAW / "epss.json").read_text())
    else:
        kev = sources.kev_catalog()
        (RAW / "kev.json").write_text(json.dumps(kev))
        epss = sources.epss_scores(kept)
        (RAW / "epss.json").write_text(json.dumps(epss))
    kev_by_id = {k["cveID"]: k for k in kev["vulnerabilities"]}
    print(f"   KEV catalog {kev['catalogVersion']}: {sum(i in kev_by_id for i in kept)} of our CVEs are listed")
    print(f"   EPSS: scores for {len(epss)} of {len(kept)} CVEs")

    print("4. Clean and save")
    records = [clean_record(cve, found, matched_by, kev_by_id.get(cve_id), epss.get(cve_id))
               for cve_id, (cve, found, matched_by) in sorted(kept.items())]
    with open(PROCESSED / "cves.jsonl", "w") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    previous = json.loads((PROCESSED / "manifest.json").read_text()) if offline else {}
    manifest = {
        # offline runs keep the original download time: that's what "data as of" means
        "collected_at": previous.get("collected_at") or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "nvd": {"queries": [k for k, _ in VENDOR_QUERIES], "cves_scanned": len(raw),
                "newest_change": max(c["lastModified"] for c in raw.values())},
        "kev": {"catalog_version": kev["catalogVersion"], "released": kev["dateReleased"]},
        "epss": {"score_date": max((s["date"] for s in epss.values()), default=None)},
        "records": len(records),
        "in_scope": sum(any(p["scope"] == "in" for p in r["products"]) for r in records),
        "cloud_only": sum(all(p["scope"] != "in" for p in r["products"]) for r in records),
    }
    (PROCESSED / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"   {len(records)} clean records in data/processed/cves.jsonl "
          f"({manifest['in_scope']} in scope, {manifest['cloud_only']} cloud-only)")
    print(f"Done in {time.time() - started:.0f} seconds")


if __name__ == "__main__":
    main()
