"""Phase 6: compare Nebius chat models as CallGuard's "agent" on exam questions.

Every model gets exactly the same retrieved records, so only the writing differs. Quick automatic checks:
expected CVEs cited, citations not in the records, refusal wording, and speed. Phase 9 grades properly.

Run it with:  uv run scripts/compare_models.py
Writes reports/model_comparison.md, with every answer so you can read them.
"""

import statistics
import tomllib
from pathlib import Path

from callguard.answer import Answerer
from callguard.evaluate import refusal_ok
from callguard.retrieve import Retriever

ROOT = Path(__file__).resolve().parent.parent
MODELS = ["Qwen/Qwen3-235B-A22B-Instruct-2507", "Qwen/Qwen3-30B-A3B-Instruct-2507", "openai/gpt-oss-120b",
          "deepseek-ai/DeepSeek-V4.1-Flash"]
QUESTION_IDS = ["E1", "V3", "V4", "S2", "M2", "M3", "M4", "F1", "R1", "R4", "R5"]


def main():
    exam = {q["id"]: q for q in tomllib.loads((ROOT / "eval" / "questions.toml").read_text())["question"]}
    questions = [exam[i] for i in QUESTION_IDS]
    retriever = Retriever()
    retrieved = {q["id"]: retriever.retrieve(q["question"]) for q in questions}  # the same records for every model

    results = {}
    for model in MODELS:
        answerer = Answerer(model, retriever)
        rows = []
        for q in questions:
            a = answerer.answer(q["question"], retrieved=retrieved[q["id"]])
            covered = (sum(c in a.cited for c in q["cves"]) / len(q["cves"])) if q["cves"] else None
            rows.append({"q": q, "a": a, "covered": covered,
                         "refusal_ok": refusal_ok(q["reason"], a.text) if q["expect"] == "refuse" else None})
        results[model] = rows
        answered = [r["covered"] for r in rows if r["covered"] is not None]
        print(f"{model:40} expected CVEs cited: {statistics.mean(answered):.0%}  "
              f"refusals ok: {sum(bool(r['refusal_ok']) for r in rows)}/{sum(r['refusal_ok'] is not None for r in rows)}  "
              f"unsupported citations: {sum(len(r['a'].unsupported) for r in rows)}  "
              f"time: avg {statistics.mean(r['a'].seconds for r in rows):.1f}s, max {max(r['a'].seconds for r in rows):.1f}s")

    out = ["# Choosing CallGuard's answer model", "",
           "Each model got exactly the same question and the same retrieved records, so only the writing differs. "
           "The checks are quick and automatic; Phase 9 grades the answers properly.", "",
           "| Model | Expected CVEs cited | Refusals worded safely | Citations not in the records | "
           "Average time | Slowest | Average tokens |", "|---|---|---|---|---|---|---|"]
    for model, rows in results.items():
        answered = [r["covered"] for r in rows if r["covered"] is not None]
        refusals = [r["refusal_ok"] for r in rows if r["refusal_ok"] is not None]
        out.append(f"| {model} | {statistics.mean(answered):.0%} | {sum(refusals)}/{len(refusals)} | "
                   f"{sum(len(r['a'].unsupported) for r in rows)} | "
                   f"{statistics.mean(r['a'].seconds for r in rows):.1f} s | {max(r['a'].seconds for r in rows):.1f} s | "
                   f"{statistics.mean(r['a'].tokens for r in rows):.0f} |")
    for q in questions:
        out += ["", f"## {q['id']}: {q['question']}", "", f"**Reference answer:** {q['answer']}"]
        for model, rows in results.items():
            r = next(r for r in rows if r["q"]["id"] == q["id"])
            out += ["", f"### {model} ({r['a'].seconds} s)", "", r["a"].text]
    (ROOT / "reports" / "model_comparison.md").write_text("\n".join(out) + "\n")
    print("Wrote reports/model_comparison.md")


if __name__ == "__main__":
    main()
