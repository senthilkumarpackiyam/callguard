"""Read a question for the facts code can act on: CVE numbers, products, vendors, a version, severity,
and whether it asks about exploitation, ransomware, priorities or recent changes.
(Phase 7's router can hand harder questions to the AI; these rules cover the common, checkable cases.)"""

import re
from dataclasses import dataclass, field

CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
# A version may end a sentence ("... 9.8.2.0."), so only a following letter or ".digit" means it continues
VERSION = re.compile(r"(?<![\w.-])(?:\d+(?:\.\d+)+(?:\(\d+\))?(?:[A-Za-z]{1,3}\d*[A-Za-z]?)?|\d+SU\d+[a-z]?)"
                     r"(?!\w|\.\d)", re.I)
EXPLOITED = re.compile(r"exploit|\bkev\b|in the wild|attackers? (are )?using|used in attacks|ransomware", re.I)
RANSOMWARE = re.compile(r"ransomware", re.I)
PRIORITY = re.compile(r"\b(patch|fix|remediate|address|upgrade)\b.{0,30}\bfirst\b|\bprioriti|\bmost urgent\b"
                      r"|\buntil last\b", re.I)
RECENT = re.compile(r"\b(newest|latest|most recent|recently|past \d+ days|last \d+ days|this week)\b", re.I)
WINDOW = [(re.compile(r"\b(?:past|last)\s+(\d+)\s+days?\b", re.I), None),
          (re.compile(r"\b(?:past|last|this)\s+week\b", re.I), 7),
          (re.compile(r"\b(?:past|last|this)\s+month\b", re.I), 30)]
# Questions about the user's own systems ("Have we patched ...?"), which CallGuard can't see
INTERNAL = re.compile(r"\b(have|has|did)\s+(we|our|my|they)\b.{0,60}\b(patch(ed)?|appl(y|ied)|install(ed)?|fix(ed)?|"
                      r"update(d)?|upgrade(d)?)\b|\bour patch (status|level)\b", re.I)
SEVERITY = [(re.compile(r"\bcritical\b", re.I), "CRITICAL"), (re.compile(r"\bhigh[- ]severity\b", re.I), "HIGH")]


@dataclass
class Understanding:
    question: str
    cve_ids: list = field(default_factory=list)
    products: list = field(default_factory=list)   # Product objects named in the question, any scope
    vendors: list = field(default_factory=list)    # vendors named without a specific product
    version: str | None = None
    severity: str | None = None
    exploited: bool = False
    ransomware: bool = False
    priority: bool = False
    recent: bool = False
    recent_days: int | None = None  # "past 7 days" -> 7
    internal: bool = False          # asks about the user's own systems
    window_start: str | None = None  # set by retrieval: the first day of the "past N days" window
    window_empty: bool = False       # set by retrieval: nothing was published in that window


def find_products(question, products):
    """Products named in the question, by name, nickname or keyword. Longer names win, so
    'Unified CM IM and Presence' counts as IM & Presence, not also as Unified CM."""
    candidates = []
    for p in products:
        for term in {p.name, *p.aka, *p.keywords}:
            for m in re.finditer(rf"(?<!\w){re.escape(term)}(?!\w)", question, re.I):
                candidates.append((m.end() - m.start(), m.start(), m.end(), p))
    taken, found = [], []
    for _, start, end, p in sorted(candidates, key=lambda c: -c[0]):
        if all(end <= s or start >= e for s, e in taken):
            taken.append((start, end))
            if p not in found:
                found.append(p)
    return found


def find_vendors(question, products, named):
    vendors = {}
    for p in products:
        for name in {p.vendor, *p.vendor_names}:
            vendors.setdefault(name.lower(), p.vendor)
    covered = {p.vendor for p in named}
    found = []
    for name, vendor in vendors.items():
        if re.search(rf"(?<!\w){re.escape(name)}(?!\w)", question, re.I) and vendor not in covered | set(found):
            found.append(vendor)
    return found


def window_days(question):
    for pattern, days in WINDOW:
        m = pattern.search(question)
        if m:
            return days or int(m.group(1))
    return None


def understand(question, products):
    named = find_products(question, products)
    without_ids = CVE_ID.sub(" ", question)
    versions = VERSION.findall(without_ids)
    days = window_days(question)
    return Understanding(
        question=question,
        cve_ids=list(dict.fromkeys(c.upper() for c in CVE_ID.findall(question))),
        products=named,
        vendors=find_vendors(question, products, named),
        version=versions[0] if versions else None,
        severity=next((level for pattern, level in SEVERITY if pattern.search(question)), None),
        exploited=bool(EXPLOITED.search(question)),
        ransomware=bool(RANSOMWARE.search(question)),
        priority=bool(PRIORITY.search(question)),
        recent=bool(RECENT.search(question)) or days is not None,
        recent_days=days,
        internal=bool(INTERNAL.search(question)),
    )
