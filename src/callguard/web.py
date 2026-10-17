"""CallGuard's website: a small FastAPI server for the page in web/, the live vulnerability list, downloads,
and the chat (answers are streamed piece by piece as they're written).

Start it with:  uv run scripts/serve.py   then open http://localhost:8000
"""

import json
import queue
import threading
import time
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from callguard.exports import cves_csv, cves_pdf, cves_xlsx, answer_pdf
from callguard.index import PROCESSED, ROOT
from callguard.products import load_products

WEB = ROOT / "web"
NVD_PAGE = "https://nvd.nist.gov/vuln/detail/{}"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

app = FastAPI(title="CallGuard", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=WEB / "static"), name="static")


class Data:
    """The clean records and the manifest, reloaded whenever a sync rewrites them."""

    def __init__(self):
        self.stamp = None
        self.products = [p for p in load_products() if p.scope in ("in", "cloud")]
        self.refresh()

    def refresh(self):
        stamp = (PROCESSED / "manifest.json").stat().st_mtime
        if stamp != self.stamp:
            self.manifest = json.loads((PROCESSED / "manifest.json").read_text())
            records = [json.loads(line) for line in open(PROCESSED / "cves.jsonl")]
            self.records = sorted(records, key=lambda r: (r["published"], r["id"]), reverse=True)
            self.by_id = {r["id"]: r for r in self.records}
            self.stamp = stamp
        return self


data = Data()
flow_lock = threading.Lock()  # one question at a time: the index can only be used by one reader at once
_flow = None


def flow():
    """The call flow, started on the first question (it opens the index and loads models)."""
    global _flow
    if _flow is None:
        from callguard.graph import CallFlow
        _flow = CallFlow()
    return _flow


def matching(vendor=None, product=None, severity=None, exploited=False, q=None):
    q = (q or "").strip().lower()

    def keep(r):
        if vendor and vendor not in {p["vendor"] for p in r["products"]}:
            return False
        if product and product not in {p["id"] for p in r["products"]}:
            return False
        if severity and ((r["cvss"] or {}).get("severity") or "NONE") != severity:
            return False
        if exploited and not r["exploited"]:
            return False
        if q and q not in (r["id"] + " " + r["description"] + " " +
                           " ".join(p["name"] for p in r["products"])).lower():
            return False
        return True

    return [r for r in data.refresh().records if keep(r)]


def filters_text(vendor, product, severity, exploited, q):
    names = {p.id: p.name for p in data.products}
    parts = [f"vendor {vendor}" if vendor else "", f"product {names.get(product, product)}" if product else "",
             f"severity {severity.title()}" if severity else "", "exploited only" if exploited else "",
             f'text "{q}"' if q else ""]
    return ", ".join(p for p in parts if p)


def summary(r):
    cvss = r["cvss"] or {}
    return {"id": r["id"], "published": r["published"], "products": [p["name"] for p in r["products"]],
            "vendors": sorted({p["vendor"] for p in r["products"]}), "severity": cvss.get("severity"),
            "score": cvss.get("score"), "exploited": bool(r["exploited"]),
            "ransomware": (r["exploited"] or {}).get("ransomware") == "Known",
            "epss": (r["epss"] or {}).get("score"), "summary": r["description"][:240]}


@app.get("/")
def home():
    return FileResponse(WEB / "index.html")


@app.get("/api/status")
def status():
    d = data.refresh()
    m = d.manifest
    in_scope = [p for p in d.products if p.scope == "in"]
    return {"as_of": m["collected_at"], "nvd_newest_change": m["nvd"]["newest_change"],
            "kev_catalog": m["kev"]["catalog_version"], "epss_date": m["epss"]["score_date"],
            "records": len(d.records), "exploited": sum(bool(r["exploited"]) for r in d.records),
            "ransomware": sum((r["exploited"] or {}).get("ransomware") == "Known" for r in d.records),
            "products_covered": len(in_scope), "vendors": sorted({p.vendor for p in d.products}),
            "products": [{"id": p.id, "name": p.name, "vendor": p.vendor, "scope": p.scope} for p in d.products]}


@app.get("/api/cves")
def list_cves(vendor: str | None = None, product: str | None = None, severity: str | None = None,
              exploited: bool = False, q: str | None = None, limit: int = Query(30, ge=1, le=200),
              offset: int = Query(0, ge=0)):
    rows = matching(vendor, product, severity, exploited, q)
    return {"total": len(rows), "items": [summary(r) for r in rows[offset:offset + limit]]}


@app.get("/api/cves/{cve_id}")
def cve_detail(cve_id: str):
    record = data.refresh().by_id.get(cve_id.upper())
    if not record:
        raise HTTPException(404, f"{cve_id} isn't in CallGuard's data")
    return {**record, "nvd_page": NVD_PAGE.format(record["id"])}


def download(content, media_type, name):
    return Response(content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/api/export/cves.{fmt}")
def export_cves(fmt: str, vendor: str | None = None, product: str | None = None, severity: str | None = None,
                exploited: bool = False, q: str | None = None):
    rows = matching(vendor, product, severity, exploited, q)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    described = filters_text(vendor, product, severity, exploited, q)
    if fmt == "csv":
        return download(cves_csv(rows), "text/csv", f"callguard-cves-{stamp}.csv")
    if fmt == "xlsx":
        return download(cves_xlsx(rows, data.manifest, described),
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        f"callguard-cves-{stamp}.xlsx")
    if fmt == "pdf":
        return download(cves_pdf(rows, data.manifest, described), "application/pdf", f"callguard-cves-{stamp}.pdf")
    raise HTTPException(404, "Use csv, xlsx or pdf")


class AnswerExport(BaseModel):
    question: str = Field(max_length=1000)
    text: str = Field(max_length=20000)


@app.post("/api/export/answer.pdf")
def export_answer(body: AnswerExport):
    m = data.refresh().manifest
    as_of = f"{m['collected_at'][:16].replace('T', ' ')} UTC"
    return download(answer_pdf(body.question, body.text, as_of), "application/pdf", "callguard-answer.pdf")


class Question(BaseModel):
    question: str = Field(min_length=3, max_length=500)


def event(name, payload):
    """One server-sent event: how the page receives the answer as it streams."""
    return f"event: {name}\ndata: {json.dumps(payload)}\n\n"


STATUS_FOR_ROUTE = {"lookup": "Opening the CVE records…", "priority": "Ranking by patch priority…",
                    "newest": "Finding the newest records…", "search": "Searching the records…",
                    "cloud": "Checking cloud-product records…", "out of scope": "Checking CallGuard's scope…"}


@app.post("/api/ask")
def ask(body: Question):
    # The answer is worked out in its own worker thread, which always releases the lock when it finishes, even if
    # the visitor closes the page halfway. (Holding the lock while sending would leave it held by an abandoned
    # answer forever, blocking every later question.) The page reads the worker's results through a queue.
    results = queue.Queue()

    def work():
        with flow_lock:
            try:
                for item in flow().app.stream({"question": body.question, "stream": True},
                                              stream_mode=["custom", "values"],
                                              config={"run_name": "CallGuard (website)",
                                                      "metadata": {"question": body.question}}):
                    results.put(item)
            except Exception as e:
                results.put(("error", e))
            finally:
                results.put(("end", None))

    threading.Thread(target=work, daemon=True).start()

    def events():
        started, final, said = time.time(), {}, set()
        while True:
            try:
                mode, chunk = results.get(timeout=180)
            except queue.Empty:
                mode, chunk = "error", TimeoutError("no reply within 3 minutes")
            if mode == "end":
                break
            if mode == "error":  # tell the page, rather than leaving it waiting
                yield event("error", {"text": f"Sorry, something went wrong ({type(chunk).__name__}). Please try again."})
                return
            if mode == "custom":
                yield event("token", {"text": chunk["token"]})
                continue
            final = chunk
            if "route" in chunk and "route" not in said:
                said.add("route")
                yield event("status", {"text": STATUS_FOR_ROUTE.get(chunk["route"], "Working…")})
            if chunk.get("rephrased") and "rephrased" not in said:
                said.add("rephrased")
                yield event("status", {"text": "Rephrasing the search…"})
            if "hits" in chunk and "hits" not in said and "answer" not in chunk:
                said.add("hits")
                yield event("status", {"text": f"Found {len(chunk['hits'])} records. Writing the answer…"})
        a = final["answer"]
        yield event("done", {"text": a.text, "kind": a.kind, "reason": a.reason, "cited": a.cited,
                             "route": final.get("route"), "seconds": round(time.time() - started, 1)})

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
