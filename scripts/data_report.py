"""Write a one-page report on the collected data: reports/data_report.md.

Run it with:  uv run scripts/data_report.py   (after scripts/collect.py)
"""

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROCESSED = ROOT / "data" / "processed"
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def table(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def pct(n, total):
    return f"{n} ({n / total:.0%})" if total else "0"


def main():
    manifest = json.loads((PROCESSED / "manifest.json").read_text())
    records = [json.loads(line) for line in open(PROCESSED / "cves.jsonl")]
    in_scope = [r for r in records if any(p["scope"] == "in" for p in r["products"])]
    n = len(in_scope)

    def severity(r):
        return (r["cvss"] or {}).get("severity") or "none"

    def version_sources(r):
        sources = {"NVD" if v["source"] == "NVD" else "vendor" for v in r["versions"] if v["status"] == "affected"}
        return {frozenset({"NVD", "vendor"}): "NVD's analysis and the vendor's list",
                frozenset({"NVD"}): "NVD's analysis only", frozenset({"vendor"}): "the vendor's list only",
                frozenset(): "only in the description text"}[frozenset(sources)]

    kev = [r for r in in_scope if r["exploited"]]
    recent = [r for r in in_scope if r["published"] >= "2024"]
    sev = Counter(severity(r) for r in in_scope)
    with_versions = sum(bool(r["versions"]) for r in in_scope)
    by_description = [r for r in records if r["matched_by"] == "description"]

    out = ["# CallGuard data report", "",
           f"Built from `data/processed/cves.jsonl`, collected on {manifest['collected_at']} (UTC).", "",
           table(["Source", "As of"], [
               ["NVD", f"newest change {manifest['nvd']['newest_change'][:16]} "
                       f"({manifest['nvd']['cves_scanned']:,} CVEs scanned)"],
               ["CISA KEV", f"catalog {manifest['kev']['catalog_version']}"],
               ["FIRST EPSS", f"scores dated {manifest['epss']['score_date']}"]]),
           "", "## Summary", "",
           table(["", "CVEs"], [
               ["In scope", n],
               ["Published since 2024", pct(len(recent), n)],
               ["Critical / High severity", f"{sev['CRITICAL']} / {sev['HIGH']}"],
               ["Listed in CISA KEV (known exploited)",
                f"{len(kev)}, of which {sum(r['exploited']['ransomware'] == 'Known' for r in kev)} "
                f"linked to ransomware"],
               ["With version data", pct(with_versions, n)],
               ["Matched to a product by description only", len(by_description)],
               ["Cloud products only (answered with the cloud message)", manifest["cloud_only"]]])]

    rows = []
    product_ids = {p["id"]: p for r in records for p in r["products"] if p["scope"] in ("in", "cloud")}
    for pid in sorted(product_ids, key=lambda i: ("XCAMSGV".index(i[0]) if i[0] in "XCAMSGV" else 9, int(i[1:]))):
        group = [r for r in records if any(p["id"] == pid for p in r["products"])]
        rows.append([product_ids[pid]["name"] + (" (cloud)" if product_ids[pid]["scope"] == "cloud" else ""),
                     len(group), sum(r["published"] >= "2024" for r in group),
                     sum(severity(r) == "CRITICAL" for r in group), sum(severity(r) == "HIGH" for r in group),
                     sum(bool(r["exploited"]) for r in group),
                     f"{sum(bool(r['versions']) for r in group) / len(group):.0%}"])
    rows.sort(key=lambda row: "(cloud)" in row[0])
    out += ["", "## By product", "",
            table(["Product", "CVEs", "Since 2024", "Critical", "High", "In KEV", "Version data"], rows)]

    out += ["", "## Known exploited (CISA KEV)", "",
            table(["CVE", "Product", "In KEV since", "Ransomware", "EPSS"],
                  [[r["id"], ", ".join(p["name"] for p in r["products"] if p["scope"] == "in"),
                    r["exploited"]["since"], r["exploited"]["ransomware"],
                    f"{r['epss']['score']:.0%}" if r["epss"] else "-"]
                   for r in sorted(kev, key=lambda r: r["exploited"]["since"], reverse=True)])]

    def watch_rows(candidates, limit):
        top = sorted((r for r in candidates if not r["exploited"] and r["epss"]),
                     key=lambda r: r["epss"]["score"], reverse=True)[:limit]
        return [[r["id"], r["published"][:4], ", ".join(p["name"] for p in r["products"] if p["scope"] == "in"),
                 f"{r['cvss']['score']} {severity(r)}" if r["cvss"] else "none", f"{r['epss']['score']:.1%}"]
                for r in top]

    header = ["CVE", "Year", "Product", "Severity", "EPSS"]
    out += ["", "## Watch list: highest exploit forecasts that are not in KEV", "",
            "EPSS predicts; KEV confirms. Old flaws with public attack code keep high forecasts for years, "
            "so recent ones are listed separately.", "",
            "**Published since 2024**", "", table(header, watch_rows(recent, 5)), "",
            "**All years**", "", table(header, watch_rows(in_scope, 5))]

    versions = Counter((r["cvss"] or {}).get("version") for r in in_scope)
    out += ["", "## Severity", "",
            table(["Severity", "CVEs"], [[s.title(), sev[s]] for s in SEVERITIES] + [["No score yet", sev["none"]]]),
            "", f"{versions.get('2.0', 0)} older CVEs only have a CVSS v2 score. That older system has no "
                "Critical level, so even a 10.0 is labelled High."]

    sources = Counter(version_sources(r) for r in in_scope)
    out += ["", "## Where version data comes from", "",
            table(["Source", "CVEs"], [[k, pct(v, n)] for k, v in sources.most_common()])]

    status = Counter(r["nvd_status"] for r in in_scope)
    out += ["", "## Data quality notes", "",
            f"- NVD's work status: " + ", ".join(f"{k} {v}" for k, v in status.most_common()) + ".",
            f"- {sev['none']} CVEs have no severity score yet.",
            f"- {len(by_description)} CVEs had no product data at all and were matched from their description: "
            + ", ".join(f"{r['id']} ({', '.join(p['name'] for p in r['products'])})" for r in by_description) + "."]

    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "data_report.md").write_text("\n".join(out) + "\n")
    print("Wrote reports/data_report.md")


if __name__ == "__main__":
    main()
