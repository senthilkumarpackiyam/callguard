"""Try CallGuard's search from the terminal: smart search, plus plain meaning and keyword search to compare.

Run it with:  uv run scripts/search.py "We run Asterisk 18.9.0. Are we exposed to any critical vulnerabilities?"
"""

import sys

from callguard.retrieve import Retriever


def line(rank, record, note=""):
    names = ", ".join(p["name"] for p in record["products"])
    severity = f"{record['cvss']['score']} {record['cvss']['severity']}" if record["cvss"] else "-"
    print(f"  {rank}. {record['id']:15} {severity:13} {'KEV' if record['exploited'] else '   '}  {names[:40]:40} {note}")


def main():
    question = " ".join(sys.argv[1:]) or "MiCollab path traversal"
    retriever = Retriever()
    hits, u = retriever.retrieve(question, k=5)
    print(f'Question: "{question}"')
    understood = [f"CVEs {u.cve_ids}" if u.cve_ids else "", f"products {[p.name for p in u.products]}" if u.products
                  else "", f"vendors {u.vendors}" if u.vendors else "", f"version {u.version}" if u.version else "",
                  f"severity {u.severity}" if u.severity else "", "exploited" if u.exploited else "",
                  "ransomware" if u.ransomware else "", "patch priority" if u.priority else "",
                  "newest first" if u.recent else ""]
    print("Understood:", ", ".join(x for x in understood if x) or "nothing specific")

    print("\nSmart search:")
    for rank, h in enumerate(hits, 1):
        check = f" | {h.version_check['status']}" if h.version_check else ""
        line(rank, h.record, f"({h.how}{check})")
    print("\nBy meaning only:")
    for rank, p in enumerate(retriever.searcher.by_meaning(question, limit=5), 1):
        line(rank, p.payload["record"])
    print("\nBy keywords only:")
    for rank, p in enumerate(retriever.searcher.by_keywords(question, limit=5), 1):
        line(rank, p.payload["record"])


if __name__ == "__main__":
    main()
