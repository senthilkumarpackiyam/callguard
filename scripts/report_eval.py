"""Phase 9, step 3: combine the exam answers (eval/results/<setup>.jsonl) and their RAGAS grades
(<setup>.ragas.json) into reports/evaluation.md, measured against the project's targets.

Run it with:  uv run scripts/report_eval.py
"""

import json
import re
import statistics
from pathlib import Path

from callguard.evaluate import p95, refusal_ok

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "eval" / "results"
FINAL = "more-records"
SETUPS = {"more-records": "**Final: card chunks, 8 records for search questions**",
          "default": "Card chunks, 5 records",
          "reranker": "Card chunks, 5 records + MiniLM reranker",
          "no-header": "Cards without the header line, 5 records",
          "description": "Description-only chunks, 5 records"}
TARGETS = {"faithfulness": 0.90, "refusals": 0.95, "p95": 6.0}
CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def table(header, rows):
    return "\n".join(["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
                     + ["| " + " | ".join(str(c) for c in row) + " |" for row in rows])


def mean(values):
    values = [v for v in values if v is not None]
    return statistics.mean(values) if values else None


def fmt(value, percent=True):
    return "–" if value is None else (f"{value:.0%}" if percent else f"{value:.2f}")


def load(name):
    rows = [json.loads(line) for line in open(RESULTS / f"{name}.jsonl")]
    grades_path = RESULTS / f"{name}.ragas.json"
    grades = json.loads(grades_path.read_text()) if grades_path.exists() else {}
    for r in rows:
        g = grades.get(r["id"], {})
        r["faithfulness"] = g.get("faithfulness")
        r["precision"] = g.get("llm_context_precision_with_reference")
        r["recall"] = g.get("context_recall")
        r["found"] = sum(c in r["retrieved"] for c in r["expected_cves"])
        r["cited_expected"] = sum(c in r["cited"] for c in r["expected_cves"])
        # Made-up citation: a CVE in the answer that was neither retrieved nor named inside any record shown
        shown = set(r["retrieved"]) | {c.upper() for block in r["contexts"] for c in CVE_ID.findall(block)}
        r["made_up"] = sorted({c.upper() for c in CVE_ID.findall(r["response"])} - shown)
        r["refusal_ok"] = refusal_ok(r["reason"], r["answer"]) if r["expect"] == "refuse" else None
        r["false_refusal"] = r["expect"] == "answer" and (
            r["kind"] == "refusal" or r["response"].lower().startswith("no matching cve"))
    return rows


def summary(rows):
    answerable = [r for r in rows if r["expect"] == "answer"]
    with_cves = [r for r in answerable if r["expected_cves"]]
    refusals = [r for r in rows if r["expect"] == "refuse"]
    seconds = [r["seconds"] for r in rows]
    expected = sum(len(r["expected_cves"]) for r in with_cves)
    return {
        "faithfulness": mean(r["faithfulness"] for r in rows),
        "faith_answerable": mean(r["faithfulness"] for r in answerable),
        "precision": mean(r["precision"] for r in answerable),
        "recall": mean(r["recall"] for r in answerable),
        "found": sum(r["found"] for r in with_cves) / expected,
        "cited": sum(r["cited_expected"] for r in with_cves) / expected,
        "refusals": sum(r["refusal_ok"] for r in refusals) / len(refusals),
        "refusals_text": f"{sum(r['refusal_ok'] for r in refusals)}/{len(refusals)}",
        "false_refusals": sum(r["false_refusal"] for r in answerable),
        "made_up": sum(len(r["made_up"]) for r in rows),
        "p50": statistics.median(seconds), "p95": p95(seconds),
    }


def main():
    results = {s: load(s) for s in SETUPS if (RESULTS / f"{s}.jsonl").exists()}
    sums = {s: summary(rows) for s, rows in results.items()}
    runs = [FINAL] + sorted(p.stem for p in RESULTS.glob(f"{FINAL}.run*.jsonl"))
    timing = {name: [r["seconds"] for r in load(name)] for name in runs}
    all_seconds = [s for values in timing.values() for s in values]
    f = sums[FINAL]
    verdict = lambda ok: "✅ met" if ok else "❌ missed"  # noqa: E731

    out = ["# CallGuard evaluation", "",
           "All 25 exam questions (`eval/questions.toml`) ran through the full call flow in five setups. RAGAS graded "
           "the answers with an AI judge (Qwen3-235B, a different model from the writer, DeepSeek-V4.1-Flash). "
           "Context precision and recall cover the 20 answerable questions. Faithfulness covers every answer the "
           "model wrote, and is also shown for the 20 answerable questions alone, because RAGAS marks refusal and "
           "safety wording (\"CallGuard can't see your systems\") as unsupported: it can't be found in any record.",
           "", "## Against the targets (final setup)", "",
           table(["Target", "Result", ""], [
               ["Faithfulness at least 90%",
                f"{fmt(f['faith_answerable'])} on the 20 answerable questions; {fmt(f['faithfulness'])} including the "
                f"3 refusals the model wrote", verdict(f["faith_answerable"] >= TARGETS["faithfulness"])],
               ["Correct refusals at least 95%", f"{f['refusals_text']} ({f['refusals']:.0%}), and no false refusals "
                f"on the {sum(r['expect'] == 'answer' for r in results[FINAL])} answerable questions",
                verdict(f["refusals"] >= TARGETS["refusals"] and f["false_refusals"] == 0)],
               ["p95 response time under 6 s",
                f"{p95(all_seconds):.1f} s over {len(all_seconds)} answers ({len(runs)} runs); p50 "
                f"{statistics.median(all_seconds):.1f} s", verdict(p95(all_seconds) < TARGETS["p95"])]]),
           "", "## All setups compared (one run of 25 questions each)", "",
           table(["Setup", "Faithfulness (answerable)", "Faithfulness (all written)", "Context precision",
                  "Context recall", "Expected CVEs found", "Expected CVEs cited", "Refusals safe",
                  "False refusals", "Made-up citations", "p50", "p95"],
                 [[SETUPS[s], fmt(m["faith_answerable"]), fmt(m["faithfulness"]), fmt(m["precision"]),
                   fmt(m["recall"]), fmt(m["found"]), fmt(m["cited"]), m["refusals_text"], m["false_refusals"],
                   m["made_up"], f"{m['p50']:.1f} s", f"{m['p95']:.1f} s"] for s, m in sums.items()]),
           "", "Differences of a few points between setups are within the judge's own noise: grading the same "
               "answer twice moved its faithfulness by 3 points. A single run's p95 is close to its slowest answer, "
               "so it swings with Nebius's speed (3.7 s to 7.4 s across runs); see the timing study below.",
           "", "## Timing study (final setup)", "",
           table(["Run", "Answers", "p50", "p95", "Slowest", "Over 6 s"],
                 [[name, len(v), f"{statistics.median(v):.1f} s", f"{p95(v):.1f} s", f"{max(v):.1f} s",
                   sum(x > 6 for x in v)] for name, v in timing.items()]
                 + [["**All runs**", len(all_seconds), f"{statistics.median(all_seconds):.1f} s",
                     f"{p95(all_seconds):.1f} s", f"{max(all_seconds):.1f} s", sum(x > 6 for x in all_seconds)]]),
           "", "## Final setup, question by question", "",
           table(["Question", "Faithfulness", "Precision", "Recall", "Expected CVEs found", "Cited", "Result", "Time"],
                 [[f"{r['id']}: {r['question']}", fmt(r["faithfulness"], False), fmt(r["precision"], False),
                   fmt(r["recall"], False),
                   f"{r['found']}/{len(r['expected_cves'])}" if r["expected_cves"] else "–",
                   f"{r['cited_expected']}/{len(r['expected_cves'])}" if r["expected_cves"] else "–",
                   r["kind"] + (" ✅" if r["refusal_ok"] else " ❌" if r["refusal_ok"] is False else ""),
                   f"{r['seconds']} s"] for r in results[FINAL]]),
           "", "The failure analysis is in `reports/failure_analysis.md`."]
    (ROOT / "reports" / "evaluation.md").write_text("\n".join(out) + "\n")
    for s, m in sums.items():
        print(f"{s:12} faithfulness answerable {fmt(m['faith_answerable'])} / all {fmt(m['faithfulness'])}  "
              f"precision {fmt(m['precision'])}  recall {fmt(m['recall'])}  found {fmt(m['found'])}  "
              f"refusals {m['refusals_text']}  made-up {m['made_up']}  p95 {m['p95']:.1f}s")
    print(f"timing over {len(all_seconds)} answers: p50 {statistics.median(all_seconds):.1f}s, "
          f"p95 {p95(all_seconds):.1f}s")
    print("Wrote reports/evaluation.md")


if __name__ == "__main__":
    main()
