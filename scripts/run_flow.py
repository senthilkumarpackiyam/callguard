"""Phase 7: run all 25 exam questions through the call flow, with and without the check step, to confirm every
question type flows end to end and to measure what the check (and its one rephrase) adds.

Run it with:  uv run scripts/run_flow.py
Writes reports/flow_check.md. Every run is also traced in LangSmith (project "callguard").
"""

import statistics
import tomllib
from pathlib import Path

from callguard.answer import Answerer
from callguard.evaluate import p95, refusal_ok
from callguard.graph import CallFlow

ROOT = Path(__file__).resolve().parent.parent


def table(header, rows):
    return "\n".join(["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
                     + ["| " + " | ".join(str(c) for c in row) + " |" for row in rows])


def main():
    questions = tomllib.loads((ROOT / "eval" / "questions.toml").read_text())["question"]
    answerer = Answerer()
    flows = {"check every search": CallFlow(answerer, use_check=True),
             "check open questions only (default)": CallFlow(answerer, use_check="open"),
             "no check": CallFlow(answerer, use_check=False)}

    results = {}
    for name, flow in flows.items():
        rows = []
        for q in questions:
            state = flow.ask(q["question"])
            a = state["answer"]
            found = [h.record["id"] for h in state.get("hits", [])]
            rows.append({"q": q, "route": state["route"], "rephrased": state.get("rephrased", 0),
                         "fits": state["check"]["fits"] if state.get("check") else None,
                         "kind": a.kind + (f" ({a.reason})" if a.reason else ""), "seconds": a.seconds,
                         "found": sum(c in found for c in q["cves"]), "cited": sum(c in a.cited for c in q["cves"]),
                         "refusal_ok": refusal_ok(q["reason"], a.text) if q["expect"] == "refuse" else None,
                         "unsupported": a.unsupported})
            print(f"  {name[:20]:20} {q['id']:3} {state['route']:12} rephrased={rows[-1]['rephrased']} "
                  f"{rows[-1]['kind']:22} {a.seconds:5.1f}s")
        results[name] = rows

    def summary(rows):
        scored = [r for r in rows if r["q"]["cves"]]
        refusals = [r for r in rows if r["refusal_ok"] is not None]
        seconds = [r["seconds"] for r in rows]
        return [f"{sum(r['found'] for r in scored) / sum(len(r['q']['cves']) for r in scored):.0%}",
                f"{sum(r['cited'] for r in scored) / sum(len(r['q']['cves']) for r in scored):.0%}",
                f"{sum(r['refusal_ok'] for r in refusals)}/{len(refusals)}",
                sum(len(r["unsupported"]) for r in rows),
                sum(r["fits"] is False for r in rows), sum(r["rephrased"] for r in rows),
                f"{statistics.mean(seconds):.1f} s", f"{p95(seconds):.1f} s"]

    default = "check open questions only (default)"
    flow_diagram = flows[default].app.get_graph().draw_mermaid()
    out = ["# The call flow on all 25 exam questions", "",
           "Every question ran through the LangGraph flow three times: checking every search (the check can rephrase "
           "the search once), checking only open-ended questions that name no product, vendor or CVE (the default), "
           "and with no check. Each run is traced in LangSmith, project `callguard`.", "",
           "```mermaid", flow_diagram.strip(), "```", "",
           table(["Flow", "Expected CVEs found", "Expected CVEs cited", "Refusals worded safely",
                  "Citations not in the records", "Check said 'doesn't fit'", "Rephrased", "Average time", "p95 time"],
                 [[name, *summary(rows)] for name, rows in results.items()]),
           "", "## Question by question (default flow)", "",
           table(["Question", "Route", "Check", "Rephrased", "Result", "Expected CVEs found", "Time"],
                 [[f"{r['q']['id']}: {r['q']['question']}", r["route"],
                   {True: "fits", False: "doesn't fit", None: "-"}[r["fits"]], "yes" if r["rephrased"] else "",
                   r["kind"], f"{r['found']}/{len(r['q']['cves'])}" if r["q"]["cves"] else "-", f"{r['seconds']} s"]
                  for r in results[default]])]
    (ROOT / "reports" / "flow_check.md").write_text("\n".join(out) + "\n")
    for name, rows in results.items():
        print(f"{name:36} " + " | ".join(str(x) for x in summary(rows)))
    print("Wrote reports/flow_check.md")


if __name__ == "__main__":
    main()
