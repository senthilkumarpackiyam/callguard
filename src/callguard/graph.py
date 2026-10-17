"""CallGuard's call flow, built with LangGraph: an IVR-style flow for AI steps.

  understand ─► (product deliberately not covered) ───────────────────────────────► refuse ─► finish
      │
      └─► retrieve ─► check ─► (records fit) ───────────────────────────────────► write ──► finish
              ▲          │
              │          ├─► (don't fit, first try) ─► rephrase ─┐
              └──────────┼───────────────────────────────────────┘
                         ├─► (still don't fit) ─► write, told the records may not match
                         └─► (nothing found) ──► refuse

Every step is recorded in LangSmith when tracing is on, so any question can be replayed step by step.
"""

import json
import os
import re
import time
from typing import TypedDict

from dotenv import load_dotenv
from langgraph.graph import END, START, StateGraph
from langsmith.wrappers import wrap_openai
from openai import OpenAI

from callguard.answer import Answer, Answerer
from callguard.index import ROOT
from callguard.retrieve import Retriever
from callguard.understand import Understanding, understand

load_dotenv(ROOT / ".env")  # before anything traces: LangSmith reads its settings from the environment

K = 5
MAX_AFTER_REPHRASE = 8  # after a rephrase, keep the best of both searches: new results first
CHECK_MODEL = "Qwen/Qwen3-235B-A22B-Instruct-2507"  # quick and good at short JSON replies
CHECK_PROMPT = """You check search results for CallGuard, an assistant that answers questions about known \
vulnerabilities (CVEs) in contact-center and unified-communications products.

Given a question and the CVE records found, decide whether the records are the right ones to answer it.
- They fit if they are about what was asked, even when the honest answer is "none of them affects that version" \
or "none is confirmed".
- They don't fit only if better records probably exist: wrong product, or wrong kind of flaw.

Reply with JSON only:
{"fits": true or false, "why": "one short sentence", "better_search": "if they don't fit, a short search \
using the words CVE records use: product name plus flaw type (for example server-side request forgery, SQL \
injection, path traversal, authentication bypass); otherwise an empty string"}"""


class State(TypedDict, total=False):
    question: str
    started: float
    understanding: Understanding
    route: str          # lookup, priority, newest, search, cloud, or out of scope
    search_text: str    # a rephrased search, after a failed check
    rephrased: int      # how many times the search was rephrased (at most once)
    hits: list
    check: dict         # {"fits": bool, "why": str, "better_search": str}
    answer: Answer


class CallFlow:
    def __init__(self, answerer=None, use_check="open"):
        # When the check runs: True = every search, False = never, "open" = only open-ended searches that name no
        # product, vendor or CVE. On the exam, checking every search added time (p95 5.9 s -> 7.5 s) without finding
        # more, and raised a false alarm; filters already keep searches on topic when a product or vendor is named.
        self.use_check = use_check
        self.answerer = answerer or Answerer()
        self.retriever: Retriever = self.answerer.retriever
        self.checker = wrap_openai(OpenAI(base_url=os.getenv("NEBIUS_BASE_URL") or
                                          "https://api.tokenfactory.nebius.com/v1/",
                                          api_key=os.environ["NEBIUS_API_KEY"], max_retries=3, timeout=60))
        self.app = self.build()

    # ---------- the steps ----------

    def understand(self, state):
        u = understand(state["question"], self.retriever.products)
        scopes = {p.scope for p in u.products}
        route = ("out of scope" if u.products and scopes == {"out"} else
                 "cloud" if u.products and scopes == {"cloud"} else
                 "lookup" if u.cve_ids else "priority" if u.priority else "newest" if u.recent else "search")
        return {"understanding": u, "route": route, "rephrased": 0, "started": time.time()}

    def retrieve(self, state):
        hits, _ = self.retriever.retrieve(state["question"], K, u=state["understanding"],
                                          search_text=state.get("search_text"))
        if state.get("rephrased"):  # keep what the first search found too, new results first
            seen = {h.record["id"] for h in hits}
            hits = (hits + [h for h in state["hits"] if h.record["id"] not in seen])[:MAX_AFTER_REPHRASE]
        return {"hits": hits}

    def check(self, state):
        if not state["hits"]:
            return {"check": {"fits": False, "why": "nothing found", "better_search": ""}}
        if state["route"] in ("lookup", "priority", "newest"):
            return {"check": {"fits": True, "why": f"found by the {state['route']} rule", "better_search": ""}}
        u = state["understanding"]
        if not self.use_check or (self.use_check == "open" and (u.products or u.vendors or u.cve_ids)):
            return {"check": {"fits": True, "why": "not checked: filters keep this search on topic"
                              if self.use_check else "check switched off", "better_search": ""}}
        records = "\n".join(
            f"- {h.record['id']} | {', '.join(p['name'] for p in h.record['products'])} | "
            f"{h.record['description'][:300]}" for h in state["hits"])
        response = self.checker.chat.completions.create(
            model=CHECK_MODEL, temperature=0, max_tokens=200,
            messages=[{"role": "system", "content": CHECK_PROMPT},
                      {"role": "user", "content": f"Question: {state['question']}\n\nRecords found:\n{records}"}])
        text = response.choices[0].message.content or ""
        try:
            verdict = json.loads(re.search(r"\{.*\}", text, re.S).group(0))
        except (AttributeError, json.JSONDecodeError):
            verdict = {"fits": True, "why": "the check's reply couldn't be read, so the records are used as found"}
        return {"check": {"fits": bool(verdict.get("fits")), "why": verdict.get("why", ""),
                          "better_search": verdict.get("better_search", "")}}

    def rephrase(self, state):
        return {"search_text": state["check"]["better_search"], "rephrased": state["rephrased"] + 1}

    def write(self, state):
        c = state["check"]
        notes = [] if c["fits"] else [
            f"A check found that these records may not be the right ones ({c['why']}). Say what is missing, "
            "and don't stretch them to fit the question."]
        return {"answer": self.answerer.generate(state["question"], state["understanding"], state["hits"], notes)}

    def refuse(self, state):
        return {"answer": self.answerer.code_refusal(state["question"], state["understanding"],
                                                     state.get("hits", []))}

    def finish(self, state):
        return {"answer": self.answerer.finish(state["answer"], state["started"])}

    # ---------- the branches ----------

    @staticmethod
    def after_understand(state):
        return "refuse" if state["route"] == "out of scope" else "retrieve"

    @staticmethod
    def after_check(state):
        if state["check"]["fits"]:
            return "write"
        if not state["hits"]:
            return "refuse"
        if state["rephrased"] == 0 and state["check"]["better_search"]:
            return "rephrase"
        return "write"

    def build(self):
        g = StateGraph(State)
        for name in ("understand", "retrieve", "check", "rephrase", "write", "refuse", "finish"):
            g.add_node(name, getattr(self, name))
        g.add_edge(START, "understand")
        g.add_conditional_edges("understand", self.after_understand, ["refuse", "retrieve"])
        g.add_edge("retrieve", "check")
        g.add_conditional_edges("check", self.after_check, ["write", "rephrase", "refuse"])
        g.add_edge("rephrase", "retrieve")
        g.add_edge("write", "finish")
        g.add_edge("refuse", "finish")
        g.add_edge("finish", END)
        return g.compile()

    def ask(self, question):
        """Run one question through the flow. Returns the final state: answer, route, check, steps taken."""
        return self.app.invoke({"question": question},
                               config={"run_name": "CallGuard", "metadata": {"question": question}})
