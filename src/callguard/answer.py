"""CallGuard's answers: the question and the CVE records found go in; a short, cited answer comes out,
or a safe refusal.

Code decides what it can: scope, versions, patch order, what's in the data, and the "data as of" line.
The language model writes the answer from the records it's given and cites each claim.
"""

import os
import time
import warnings
from dataclasses import dataclass, field
from datetime import date

from dotenv import load_dotenv
from langsmith.wrappers import wrap_openai
from openai import OpenAI

from callguard.index import ROOT
from callguard.retrieve import Retriever, priority_key
from callguard.understand import CVE_ID

# Chosen in Phase 6 (reports/model_comparison.md): as accurate as the best, all refusals safe, and fast.
# It reasons before writing, and that hidden reasoning counts toward MAX_TOKENS, hence the generous limit.
DEFAULT_MODEL = "deepseek-ai/DeepSeek-V4.1-Flash"
MAX_TOKENS = 4000
# Harmless: Nebius returns one response field in a shape the OpenAI library doesn't expect when tracing copies it
warnings.filterwarnings("ignore", message="Pydantic serializer warnings", category=UserWarning)
NVD_PAGE = "https://nvd.nist.gov/vuln/detail/{}"


def patch_order(hits):
    """The records' CVE numbers in patch-priority order, whatever order search found them in (a CVE named in the
    question comes first in the hits, but not necessarily first to patch). Ones that don't affect the version
    asked about are left out."""
    relevant = [h for h in hits if not (h.version_check and h.version_check["status"] == "not affected")]
    return [h.record["id"] for h in sorted(relevant, key=lambda h: priority_key(h.record), reverse=True)]

SYSTEM_PROMPT = """You are CallGuard, an assistant that answers questions about known security vulnerabilities (CVEs) \
in contact-center and unified-communications products, for Tier 2 support engineers and solution architects.

You get the question, facts that code has already worked out, and the CVE records CallGuard found. Rules:

1. Answer only from the records provided. Never add CVEs, versions, scores, dates, exploitation details, fixes or \
links that are not in them.
2. Cite every claim with its CVE number in square brackets, like [CVE-2024-41713]; write CVE numbers that way \
every time, not in bold. Cite only CVEs that appear in the records.
3. Start with a direct answer in one or two sentences. Then give short bullets, one per relevant CVE: what it is, \
severity, whether it is in CISA KEV (known exploited) and its ransomware status, affected versions, and the \
advisory or fix link.
4. Leave out records that don't match what was asked (another product, or a version check of "not affected"), \
unless mentioning them helps. Never present them as matches. If the question names specific CVEs, focus on those \
and on CVEs their records link to (for example, a chained flaw); bring in others only if they answer the question.
5. Version checks were done by code: use them as given. If a check says "unknown", say the versions appear only \
in the description and quote that part. If the sources disagree, say so.
6. If code gives a patch-priority order (known exploited first, then highest exploit forecast, then highest \
severity), keep that order and explain it briefly. Don't invent a different order.
7. "Unknown" ransomware use means not confirmed, not "no". Severity is not the same as risk: a known-exploited \
Low-severity flaw can matter more than an unexploited Critical one.
8. If no record matches the product or version asked about, say "No matching CVE in CallGuard's data", say plainly \
that this does not mean the product or version is safe, and point to the vendor's security advisories. Never imply \
that something is safe because no CVE was found.
9. If the question names a product CallGuard doesn't cover, say so and don't answer from other products' records. \
CallGuard covers: {products}.
10. If the question is about the user's own systems (for example, whether they have patched), say you can't see \
their systems, then give what would help them check: the affected versions and the fix.
11. Be brief and plain: about 150 words, more only for lists. No preamble. Don't add a "data as of" line or a list \
of sources; both are added automatically."""


@dataclass
class Answer:
    question: str
    text: str
    kind: str                      # "answer", or "refusal" when code declined without asking the model
    reason: str | None = None      # why it refused: out of scope, cloud, no records
    retrieved: list = field(default_factory=list)
    cited: list = field(default_factory=list)
    unsupported: list = field(default_factory=list)  # cited CVEs that weren't in the records: a red flag
    model: str | None = None
    seconds: float = 0.0
    tokens: int = 0
    body: str = ""                 # the answer as written, before code adds sources and "data as of"
    contexts: list = field(default_factory=list)  # exactly what the model was shown, record by record


class Answerer:
    def __init__(self, model=DEFAULT_MODEL, retriever=None):
        load_dotenv(ROOT / ".env")
        self.model = model
        self.retriever = retriever or Retriever()
        # wrap_openai records every model call in LangSmith (when tracing is on): prompt, answer, tokens, time
        self.llm = wrap_openai(OpenAI(base_url=os.getenv("NEBIUS_BASE_URL") or "https://api.tokenfactory.nebius.com/v1/",
                                      api_key=os.environ["NEBIUS_API_KEY"], max_retries=3, timeout=120))
        covered = [p.name for p in self.retriever.products if p.scope == "in"]
        self.system = SYSTEM_PROMPT.format(products="; ".join(covered))

    @property
    def as_of(self):
        """How fresh the data is, read each time, so a sync that just ran shows up in the next answer."""
        m = self.retriever.manifest
        when = m["collected_at"][:16].replace("T", " ")
        return (f"{when} UTC (NVD changes up to {m['nvd']['newest_change'][:10]}, "
                f"CISA KEV catalog {m['kev']['catalog_version']}, EPSS scores of {m['epss']['score_date']})")

    def finish(self, answer, started):
        """Add the parts code guarantees: sources with NVD links, and the data date."""
        sources = ", ".join(f"[{c}]({NVD_PAGE.format(c)})" for c in answer.cited)
        answer.body = answer.text.strip()
        answer.text = answer.body + (f"\n\nSources: {sources}" if sources else "") + \
            f"\n\n_Data as of {self.as_of}._"
        answer.seconds = round(time.time() - started, 2)
        return answer

    def answer(self, question, k=5, retrieved=None):
        """The whole answer in one straight line (Phase 6). Phase 7's call flow uses the same steps."""
        started = time.time()
        hits, u = retrieved or self.retriever.retrieve(question, k)
        return self.finish(self.code_refusal(question, u, hits) or self.generate(question, u, hits), started)

    def code_refusal(self, question, u, hits):
        """Refusals code can decide on its own: no model call, so no chance of a confident wrong answer.
        Returns an Answer, or None when the model should write the answer."""
        scopes = {p.scope for p in u.products}
        names = ", ".join(p.name for p in u.products)
        if u.products and scopes == {"out"}:
            return Answer(question, (
                f"CallGuard doesn't cover {names}; it was deliberately left out of scope, so it has no records to "
                f"check. For {names}, see {u.products[0].vendor}'s security advisories."), "refusal", "out of scope")
        if u.products and scopes == {"cloud"} and not hits:
            vendor = u.products[0].vendor
            return Answer(question, (
                f"No matching CVE in CallGuard's data for {names}. It's a cloud service that {vendor} patches "
                f"itself, and cloud services rarely get CVEs, so this does not mean it's free of vulnerabilities. "
                f"Check {vendor}'s security bulletins or trust center."), "refusal", "cloud")
        if not hits:
            return Answer(question, (
                "No matching CVE in CallGuard's data. This does not mean the product or version is safe; check the "
                "vendor's security advisories."), "refusal", "no records")
        return None

    def generate(self, question, u, hits, extra_notes=(), on_token=None):
        """Have the model write the answer from the records, with the facts code has worked out.
        on_token, if given, receives the answer piece by piece as it's written (for the website)."""
        notes = [f"Products named: {', '.join(f'{p.name} ({p.scope})' for p in u.products)}" if u.products else "",
                 f"Version asked about: {u.version}" if u.version else "",
                 "The question is about the user's own systems, which CallGuard can't see." if u.internal else "",
                 "Patch-priority order worked out by code (known exploited first, then highest exploit forecast, "
                 "then highest severity): " + ", ".join(patch_order(hits)) if u.priority else "",
                 f"No CVEs in CallGuard's data were published in the past {u.recent_days} days (since "
                 f"{u.window_start}). The records below are the newest overall." if u.window_empty else "",
                 "Records are listed newest first." if u.recent and not u.window_empty else "", *extra_notes]
        blocks = ["\n".join(filter(None, [f"[{i}] {h.record['text']}",
                                          f"Version check by code: {h.version_check['status']}: "
                                          f"{h.version_check['because']}" if h.version_check else "",
                                          f"Found by: {h.how}"]))
                  for i, h in enumerate(hits, 1)]
        records = "\n---\n".join(blocks)
        prompt = (f"Question: {question}\n\nToday's date: {date.today().isoformat()}. "
                  f"CallGuard's data was collected on {self.retriever.as_of}.\n\n"
                  "What code has worked out:\n" + ("\n".join(f"- {n}" for n in notes if n) or "- nothing extra")
                  + f"\n\nCVE records found:\n{records}")

        messages = [{"role": "system", "content": self.system}, {"role": "user", "content": prompt}]
        if on_token:
            text, finish_reason, tokens = self.stream(messages, on_token)
        else:
            response = self.llm.chat.completions.create(model=self.model, temperature=0.1, max_tokens=MAX_TOKENS,
                                                        messages=messages)
            text, finish_reason = (response.choices[0].message.content or "").strip(), response.choices[0].finish_reason
            tokens = response.usage.total_tokens
        if finish_reason == "length":  # never show a cut-off answer without saying so
            cut = "\n\n(This answer was cut short. Ask about fewer CVEs at a time for the full details.)"
            text += cut
            if on_token:
                on_token(cut)
        retrieved_ids = [h.record["id"] for h in hits]
        # A CVE is supported if it was retrieved or is named inside a record (e.g. CISA's "chained with" note)
        mentioned = {c.upper() for block in blocks for c in CVE_ID.findall(block)}
        cited = list(dict.fromkeys(c.upper() for c in CVE_ID.findall(text)))
        return Answer(question, text, "answer", retrieved=retrieved_ids,
                      cited=[c for c in cited if c in retrieved_ids],
                      unsupported=[c for c in cited if c not in retrieved_ids and c not in mentioned],
                      model=self.model, tokens=tokens, contexts=blocks)

    def stream(self, messages, on_token):
        """Ask the model with streaming on, passing each new piece of the answer to on_token as it arrives.
        A reasoning model thinks first, silently; only the written answer is passed on."""
        parts, finish_reason, tokens = [], None, 0
        for chunk in self.llm.chat.completions.create(model=self.model, temperature=0.1, max_tokens=MAX_TOKENS,
                                                      messages=messages, stream=True,
                                                      stream_options={"include_usage": True}):
            if chunk.usage:
                tokens = chunk.usage.total_tokens
            if not chunk.choices:
                continue
            piece = chunk.choices[0].delta.content
            if piece:
                if not parts:
                    piece = piece.lstrip()
                parts.append(piece)
                on_token(piece)
            finish_reason = chunk.choices[0].finish_reason or finish_reason
        return "".join(parts).strip(), finish_reason, tokens
