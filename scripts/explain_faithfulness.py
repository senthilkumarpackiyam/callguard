"""Phase 9 failure analysis: for answers RAGAS scored below 90% faithfulness, list each statement the records
don't support, and label it FACT (a claim about a CVE, product, version, score, date, exploitation or fix) or
GUIDANCE (a refusal, a safety caveat, advice, or a statement about CallGuard itself).

A FACT is a real problem. GUIDANCE is wording CallGuard is designed to add, which faithfulness scoring counts
against it because it can't be "found" in any record.

Run it with:  uv run scripts/explain_faithfulness.py default
Writes eval/results/<setup>.unsupported.json.
"""

import json
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

ROOT = Path(__file__).resolve().parent.parent
JUDGE = "Qwen/Qwen3-235B-A22B-Instruct-2507"
PROMPT = """You audit answers written by a CVE assistant. You get the records it was shown and its answer.
List every statement in the answer that the records do not support, and label each one:
- FACT: a factual claim about a vulnerability, product, version, score, date, exploitation or fix.
- GUIDANCE: a refusal, a caveat (for example "this does not mean it is safe"), advice (for example "check the \
vendor's advisories"), or a statement about the assistant itself (for example "CallGuard doesn't cover this").
Reply with JSON only: {"unsupported": [{"statement": "...", "type": "FACT" or "GUIDANCE", "why": "one short sentence"}]}
If everything is supported, reply {"unsupported": []}."""


def main():
    setup = (sys.argv[1:] or ["default"])[0]
    load_dotenv(ROOT / ".env")
    llm = OpenAI(base_url=os.getenv("NEBIUS_BASE_URL") or "https://api.tokenfactory.nebius.com/v1/",
                 api_key=os.environ["NEBIUS_API_KEY"], timeout=180, max_retries=3)
    rows = {json.loads(line)["id"]: json.loads(line) for line in open(ROOT / "eval" / "results" / f"{setup}.jsonl")}
    grades = json.loads((ROOT / "eval" / "results" / f"{setup}.ragas.json").read_text())
    findings = {}
    for qid, g in grades.items():
        if g.get("faithfulness") is None or g["faithfulness"] >= 0.9:
            continue
        r = rows[qid]
        response = llm.chat.completions.create(
            model=JUDGE, temperature=0, max_tokens=1500,
            messages=[{"role": "system", "content": PROMPT},
                      {"role": "user", "content": "Records:\n" + "\n---\n".join(r["contexts"])
                       + f"\n\nAnswer:\n{r['response']}"}])
        text = response.choices[0].message.content or ""
        try:
            items = json.loads(re.search(r"\{.*\}", text, re.S).group(0))["unsupported"]
        except (AttributeError, json.JSONDecodeError, KeyError):
            items = [{"statement": "(the audit reply couldn't be read)", "type": "UNKNOWN", "why": text[:200]}]
        findings[qid] = {"faithfulness": g["faithfulness"], "unsupported": items}
        facts = [i for i in items if i["type"] == "FACT"]
        print(f"{qid} faithfulness {g['faithfulness']:.2f}: {len(facts)} FACT, "
              f"{sum(i['type'] == 'GUIDANCE' for i in items)} GUIDANCE")
        for i in facts:
            print(f"     FACT: {i['statement'][:160]}  ({i['why'][:120]})")
    (ROOT / "eval" / "results" / f"{setup}.unsupported.json").write_text(json.dumps(findings, indent=1) + "\n")
    print(f"Wrote eval/results/{setup}.unsupported.json")


if __name__ == "__main__":
    main()
