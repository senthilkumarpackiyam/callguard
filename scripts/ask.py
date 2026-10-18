"""Ask CallGuard a question from the terminal. It runs the full call flow (Phase 7) and prints the answer,
the path the question took, and a link to replay it in LangSmith.

Run it with:  uv run scripts/ask.py "Is MiCollab 9.8.1.201 affected by CVE-2024-41713?"
"""

import os
import sys
import time
import warnings

from langchain_core.tracers.context import collect_runs
from langchain_core.tracers.langchain import wait_for_all_tracers
from langsmith import Client
from langsmith.utils import LangSmithNotFoundError

from callguard.graph import CallFlow


def trace_link(run_id):
    """The LangSmith page where this question can be replayed step by step (best effort)."""
    try:
        wait_for_all_tracers()
        client = Client()
        # read_run and get_run_url are deprecated but work until 2027-01-31; their replacements need more IDs
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            for _ in range(5):  # a very fast answer can be looked up before LangSmith has finished saving it
                try:
                    return client.get_run_url(run=client.read_run(run_id))
                except LangSmithNotFoundError:
                    time.sleep(1)
            return client.get_run_url(run=client.read_run(run_id))
    except Exception as e:  # tracing off, or not uploaded yet
        return f"(not available: {type(e).__name__})"


def main():
    question = " ".join(sys.argv[1:]) or "What is CVE-2024-41713, and are attackers using it?"
    with collect_runs() as runs:
        state = CallFlow().ask(question)
    a = state["answer"]
    print(f"Q: {question}\n\n{a.text}\n")
    steps = ["understand", "retrieve", "check"] if state["route"] != "out of scope" else ["understand"]
    if state.get("rephrased"):
        steps += [f"rephrase ({state['search_text']!r})", "retrieve", "check"]
    steps += ["write" if a.kind == "answer" else "refuse", "finish"]
    print(f"[path: {' → '.join(steps)}]")
    print(f"[route: {state['route']}; check: {state['check']['why'] if state.get('check') else 'not needed'}]")
    print(f"[{a.kind}" + (f" ({a.reason})" if a.reason else "") + f", {a.seconds} s, {a.tokens} tokens]")
    if a.unsupported:
        print(f"[warning: cited CVEs that were not in the records: {a.unsupported}]")
    if os.getenv("LANGSMITH_TRACING", "").lower() != "true":
        print("[LangSmith tracing is off: it's optional; add LANGSMITH_API_KEY to .env to record questions for replay]")
    elif runs.traced_runs:
        print(f"[replay in LangSmith: {trace_link(runs.traced_runs[0].id)}]")


if __name__ == "__main__":
    main()
