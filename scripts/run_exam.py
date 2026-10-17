"""Phase 9, step 1: sit the exam. Run all 25 questions through the call flow in one setup and save every answer
with exactly what the model was shown, for grading (scripts/score_ragas.py) and the report (scripts/report_eval.py).

Run it with:  uv run scripts/run_exam.py --setup default
Setups: default (card chunks, no reranker), reranker (adds the MiniLM reranker), no-header (cards without
their header line), description (descriptions only). Writes eval/results/<setup>.jsonl.
"""

import argparse
import json
import tomllib
from datetime import date, timedelta
from pathlib import Path

from callguard.answer import Answerer
from callguard.graph import CallFlow
from callguard.index import Searcher
from callguard.retrieve import Retriever

ROOT = Path(__file__).resolve().parent.parent
SETUPS = {  # setup: (index collection, reranker, records per search question)
    "default": ("cves", None, 5),
    "reranker": ("cves", "Xenova/ms-marco-MiniLM-L-12-v2", 5),
    "no-header": ("cves_no_header", None, 5),
    "description": ("cves_description", None, 5),
    "more-records": ("cves", None, 8),
}
CISCO_CONTACT_CENTER = {"C4", "C6", "C7", "C8", "C9"}


def dynamic_expectation(q, retriever):
    """The right answer to a freshness question depends on the day: work it out from the data, now."""
    records = retriever.all_matching(None)
    in_scope = [r for r in records if any(p["scope"] == "in" for p in r["products"])]
    as_of = date.fromisoformat(retriever.as_of)
    if q["id"] == "F1":
        since = (as_of - timedelta(days=7)).isoformat()
        recent = sorted((r for r in in_scope if r["published"] >= since), key=lambda r: r["published"], reverse=True)
        if recent:
            return [r["id"] for r in recent], (f"As of {as_of}, {len(recent)} in-scope CVEs were published in the "
                                               f"past 7 days: " + ", ".join(r["id"] for r in recent) + ".")
        newest = max(in_scope, key=lambda r: r["published"])
        return [], (f"As of {as_of}, none were published in the past 7 days (since {since}). The newest is "
                    f"{newest['id']}, published {newest['published']}.")
    if q["id"] == "F2":
        newest = max((r for r in in_scope if {p["id"] for p in r["products"]} & CISCO_CONTACT_CENTER),
                     key=lambda r: r["published"])
        names = ", ".join(p["name"] for p in newest["products"])
        return [newest["id"]], f"As of {as_of}, it is {newest['id']} ({names}), published {newest['published']}."
    raise ValueError(f"no dynamic expectation for {q['id']}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--setup", default="default", choices=SETUPS)
    parser.add_argument("--repeat", type=int, default=0, help="an extra run for timing, saved as <setup>.run<N>.jsonl")
    args = parser.parse_args()
    name = f"{args.setup}.run{args.repeat}" if args.repeat else args.setup
    collection, reranker, search_k = SETUPS[args.setup]
    questions = tomllib.loads((ROOT / "eval" / "questions.toml").read_text())["question"]
    retriever = Retriever(searcher=Searcher(collection))
    flow = CallFlow(Answerer(retriever=retriever), reranker=reranker, search_k=search_k)

    out_dir = ROOT / "eval" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / f"{name}.jsonl", "w") as f:
        for q in questions:
            cves, reference = (dynamic_expectation(q, retriever) if q.get("dynamic") else (q["cves"], q["answer"]))
            state = flow.ask(q["question"])
            a = state["answer"]
            row = {"setup": args.setup, "id": q["id"], "type": q["type"], "expect": q["expect"],
                   "reason": q.get("reason"), "question": q["question"], "reference": reference,
                   "expected_cves": cves, "response": a.body, "answer": a.text, "contexts": a.contexts,
                   "retrieved": a.retrieved or [h.record["id"] for h in state.get("hits", [])],
                   "cited": a.cited, "unsupported": a.unsupported, "kind": a.kind, "refusal_reason": a.reason,
                   "route": state["route"], "rephrased": state.get("rephrased", 0), "seconds": a.seconds,
                   "tokens": a.tokens}
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            print(f"  {args.setup:11} {q['id']:3} {state['route']:12} {a.kind:8} {a.seconds:5.1f}s", flush=True)
    print(f"Wrote eval/results/{name}.jsonl")


if __name__ == "__main__":
    main()
