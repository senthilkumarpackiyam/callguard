"""Try CallGuard's search from the terminal: top results by meaning and by keywords, side by side.

Run it with:  uv run scripts/search.py "MiCollab path traversal"
"""

import sys

from callguard.index import Searcher


def show(title, points):
    print(f"\n{title}")
    for rank, point in enumerate(points, 1):
        r = point.payload["record"]
        names = ", ".join(p["name"] for p in r["products"])
        severity = f"{r['cvss']['score']} {r['cvss']['severity']}" if r["cvss"] else "-"
        print(f"  {rank}. {r['id']:15} {severity:13} {'KEV' if r['exploited'] else '   '}  {names[:48]}")


def main():
    question = " ".join(sys.argv[1:]) or "MiCollab path traversal"
    searcher = Searcher()
    print(f'Question: "{question}"')
    show("By meaning (embeddings):", searcher.by_meaning(question, limit=5))
    show("By keywords (BM25):", searcher.by_keywords(question, limit=5))


if __name__ == "__main__":
    main()
