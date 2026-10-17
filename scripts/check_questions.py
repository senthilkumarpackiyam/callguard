"""Check the exam (eval/questions.toml) against the data: structure, counts, and that every CVE exists.

Run it with:  uv run scripts/check_questions.py
"""

import json
import sys
import tomllib
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
QUESTIONS_PER_TYPE = {"exact-id": 4, "version": 5, "meaning": 5, "multi-step": 4, "freshness": 2, "refuse": 5}
REQUIRED = ("id", "type", "question", "expect", "cves", "answer", "tests")


def main():
    questions = tomllib.loads((ROOT / "eval" / "questions.toml").read_text())["question"]
    records = {r["id"]: r for r in (json.loads(line) for line in open(ROOT / "data" / "processed" / "cves.jsonl"))}
    problems = [f"{q.get('id', '?')}: missing {f}" for q in questions for f in REQUIRED if f not in q]
    problems += [f"duplicate id {i}" for i, n in Counter(q["id"] for q in questions).items() if n > 1]
    counts = Counter(q["type"] for q in questions)
    problems += [f"{t}: {counts[t]} questions, expected {want}" for t, want in QUESTIONS_PER_TYPE.items()
                 if counts[t] != want]

    for q in questions:
        if q["expect"] == "refuse" and not q.get("reason"):
            problems.append(f"{q['id']}: a refusal needs a reason")
        if q["type"] == "freshness" and not q.get("dynamic"):
            problems.append(f"{q['id']}: a freshness question needs a dynamic rule")
        for cve in q["cves"]:
            if cve not in records:
                problems.append(f"{q['id']}: {cve} is not in the data")
            elif cve not in q["answer"] and cve not in q["question"]:
                problems.append(f"{q['id']}: {cve} is expected but neither the question nor the answer names it")
        print(f"{q['id']:3} {q['type']:10} {q.get('reason', q['expect']):15} {len(q['cves'])} CVEs  {q['question']}")

    print("\nQuestions per type:", dict(counts))
    if problems:
        print("\nProblems:\n  " + "\n  ".join(problems))
        sys.exit(1)
    print("All checks passed: every expected CVE exists in the data and is named in its question or answer.")


if __name__ == "__main__":
    main()
