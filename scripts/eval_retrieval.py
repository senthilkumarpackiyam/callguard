"""Phase 5: score search on the exam. For each answerable question with known CVEs, did the right CVEs
land in the top 5? Six setups, from the simplest search to the full smart search.

Run it with:  uv run scripts/eval_retrieval.py
Writes reports/retrieval_eval.md.
"""

import time
import tomllib
from pathlib import Path

from callguard.retrieve import Retriever

ROOT = Path(__file__).resolve().parent.parent
K = 5
MINILM, BGE = "Xenova/ms-marco-MiniLM-L-12-v2", "BAAI/bge-reranker-v2-m3-int8"
SETUPS = [
    ("Meaning only", lambda r, q: [p.payload["cve"] for p in r.searcher.by_meaning(q, K)]),
    ("Keywords only", lambda r, q: [p.payload["cve"] for p in r.searcher.by_keywords(q, K)]),
    ("Hybrid (RRF)", lambda r, q: [p.payload["cve"] for p in r.hybrid(q, K)]),
    ("Smart, no reranker", lambda r, q: [h.record["id"] for h in r.retrieve(q, K, reranker=None)[0]]),
    ("Smart + MiniLM reranker", lambda r, q: [h.record["id"] for h in r.retrieve(q, K, reranker=MINILM)[0]]),
    ("Smart + BGE reranker", lambda r, q: [h.record["id"] for h in r.retrieve(q, K, reranker=BGE)[0]]),
]


def table(header, rows):
    return "\n".join(["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
                     + ["| " + " | ".join(str(c) for c in row) + " |" for row in rows])


def main():
    questions = [q for q in tomllib.loads((ROOT / "eval" / "questions.toml").read_text())["question"] if q["cves"]]
    retriever = Retriever()
    print(f"Scoring {len(SETUPS)} setups on {len(questions)} questions (top {K})")

    started = time.time()  # embed every search text once up front, so timings below compare search alone
    for q in questions:
        retriever.searcher.embedder.embed_query(q["question"])
        retriever.retrieve(q["question"], K, reranker=None)  # also embeds "more like this" search texts
    embed_seconds = time.time() - started
    for model in (MINILM, BGE):
        retriever.reranker(model)  # load models before timing

    results = {}
    for name, run in SETUPS:
        rows = []
        for q in questions:
            t = time.time()
            top = run(retriever, q["question"])
            rows.append({"q": q, "top": top, "found": [c for c in q["cves"] if c in top],
                         "ms": (time.time() - t) * 1000})
        results[name] = rows
        n = len(rows)
        print(f"  {name:25} found all: {sum(len(r['found']) == len(r['q']['cves']) for r in rows)}/{n}  "
              f"share found: {sum(len(r['found']) / len(r['q']['cves']) for r in rows) / n:.0%}")

    def summary(rows):
        n = len(rows)
        return [f"{sum(bool(r['found']) for r in rows)}/{n}",
                f"{sum(len(r['found']) == len(r['q']['cves']) for r in rows)}/{n}",
                f"{sum(len(r['found']) / len(r['q']['cves']) for r in rows) / n:.0%}",
                f"{sum(r['ms'] for r in rows) / n:.0f} ms"]

    out = ["# Retrieval scores on the exam", "",
           f"{len(questions)} exam questions that have known CVEs (exact number, version, meaning, multi-step). "
           f"For each, did the expected CVEs appear in the top {K}? Freshness and should-refuse questions are "
           "scored in Phase 9.", "",
           f"Search texts were embedded once up front ({embed_seconds:.0f} s in total, mostly Nebius calls), "
           "so the times below are search and reranking only.", "",
           table(["Setup", "Found at least one", "Found all", "Share of expected CVEs found", "Average time"],
                 [[name, *summary(rows)] for name, rows in results.items()])]

    types = ["exact-id", "version", "meaning", "multi-step"]
    out += ["", "## By question type: share of expected CVEs found", "",
            table(["Setup", *types], [[name] + [
                f"{sum(len(r['found']) / len(r['q']['cves']) for r in rows if r['q']['type'] == t) / sum(r['q']['type'] == t for r in rows):.0%}"
                for t in types] for name, rows in results.items()])]

    names = [name for name, _ in SETUPS]
    out += ["", "## Question by question: expected CVEs found in the top 5", "",
            table(["Question", "Expected", *names],
                  [[f"{q['id']}: {q['question']}", len(q["cves"])]
                   + [len(results[name][i]["found"]) for name in names] for i, q in enumerate(questions)])]

    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "retrieval_eval.md").write_text("\n".join(out) + "\n")
    print("Wrote reports/retrieval_eval.md")


if __name__ == "__main__":
    main()
