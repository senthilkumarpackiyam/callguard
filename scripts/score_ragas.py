"""Phase 9, step 2: grade the exam answers with RAGAS, using an AI judge (Qwen3-235B, a different model from
the one that wrote the answers, so it isn't marking its own work).

- Faithfulness: are the answer's claims supported by the records the model was shown?
- Context precision: are the records found relevant to the question, with the relevant ones ranked first?
- Context recall: do the records found cover everything the reference answer says?

RAGAS needs older LangChain libraries than the app, so it runs in its own throwaway environment:

  uv run --no-project --with "ragas==0.4.3" --with "langchain-community<0.4" --with "langchain-openai<1" \
      --with python-dotenv python scripts/score_ragas.py eval/results/default.jsonl

Writes eval/results/<setup>.ragas.json next to each results file.
"""

import json
import os
import sys
import warnings
from pathlib import Path

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from ragas import EvaluationDataset, evaluate
from ragas.dataset_schema import SingleTurnSample
from ragas.llms import LangchainLLMWrapper
from ragas.metrics import Faithfulness, LLMContextPrecisionWithReference, LLMContextRecall
from ragas.run_config import RunConfig

warnings.filterwarnings("ignore")  # RAGAS announces upcoming API changes on every call
ROOT = Path(__file__).resolve().parent.parent
JUDGE = "Qwen/Qwen3-235B-A22B-Instruct-2507"


def score(path, judge):
    rows = [json.loads(line) for line in open(path)]
    graded = [r for r in rows if r["contexts"]]  # code-written refusals had no records to be faithful to
    answerable = [r for r in graded if r["expect"] == "answer"]
    config = RunConfig(max_workers=8, timeout=300, max_retries=5)

    def run(items, metrics):
        if not items:
            return {}
        dataset = EvaluationDataset(samples=[SingleTurnSample(
            user_input=r["question"], response=r["response"], retrieved_contexts=r["contexts"],
            reference=r["reference"]) for r in items])
        table = evaluate(dataset, metrics=metrics, run_config=config, show_progress=False,
                         raise_exceptions=False).to_pandas()
        return {r["id"]: {k: (None if table.iloc[i][k] != table.iloc[i][k] else float(table.iloc[i][k]))
                          for k in table.columns if k in ("faithfulness", "llm_context_precision_with_reference",
                                                          "context_recall")}
                for i, r in enumerate(items)}

    # Context precision and recall compare against the reference answer, so only for questions with real answers
    scores = run(answerable, [Faithfulness(llm=judge), LLMContextPrecisionWithReference(llm=judge),
                              LLMContextRecall(llm=judge)])
    scores.update(run([r for r in graded if r["expect"] != "answer"], [Faithfulness(llm=judge)]))
    out = Path(path).with_suffix(".ragas.json")
    out.write_text(json.dumps(scores, indent=1) + "\n")
    print(f"{path}: graded {len(scores)} answers -> {out}")


def main():
    load_dotenv(ROOT / ".env")
    judge = LangchainLLMWrapper(ChatOpenAI(
        model=JUDGE, temperature=0, timeout=180, max_retries=3,
        base_url=os.getenv("NEBIUS_BASE_URL") or "https://api.tokenfactory.nebius.com/v1/",
        api_key=os.environ["NEBIUS_API_KEY"]))
    for path in sys.argv[1:]:
        score(path, judge)


if __name__ == "__main__":
    main()
