"""Smart search: exact lookup, filters, hybrid search, reranking and version checks, in that order.

Like a good agent's routine:
1. A CVE number in the question? Open that record directly, plus any CVE it mentions (e.g. a chained flaw).
2. Products, vendors, severity or exploitation named? Search only within those, like skills-based routing.
3. "What first?" or "what's newest?" Rank by rule: exploited, then forecast, then severity; or newest first.
4. Otherwise, hybrid search (meaning and keywords merged with RRF), then a reranker rereads the top 20.
5. A version named? The version checker marks each CVE affected, not affected or unknown.
"""

from dataclasses import dataclass

from fastembed.rerank.cross_encoder import TextCrossEncoder
from qdrant_client import models

from callguard.index import COLLECTION, INDEX_DIR, Searcher, point_id
from callguard.products import load_products
from callguard.understand import CVE_ID, understand
from callguard.versions import check

# No reranker by default: on the exam, both rerankers matched plain smart search (96% of expected CVEs found)
# while adding 0.8 s (MiniLM) or 6.7 s (BGE) per question. See reports/retrieval_eval.md; Phase 9 re-tests this.
DEFAULT_RERANKER = None
CANDIDATES = 20
VERSION_ORDER = {"affected": 0, "unknown": 1, "not affected": 2}


@dataclass
class Hit:
    record: dict
    how: str  # exact lookup, mentioned in CVE-…, search, patch-priority rule, newest first
    version_check: dict | None = None


def priority_key(record):
    """Patch order: known exploited first, then highest exploit forecast, then highest severity."""
    return (record["exploited"] is not None, (record["epss"] or {}).get("score", 0.0),
            (record["cvss"] or {}).get("score", 0.0))


def any_of(key, values):
    return models.FieldCondition(key=key, match=models.MatchAny(any=list(values)))


def equals(key, value):
    return models.FieldCondition(key=key, match=models.MatchValue(value=value))


def filter_levels(u, scope):
    """Filters from the question, strictest first. Each later level drops the most specific condition,
    so one over-narrow filter never leaves a question with nothing."""
    base = ([any_of("products", scope)] if scope else [any_of("vendors", u.vendors)] if u.vendors
            else [equals("scope", "in")])
    with_severity = base + ([equals("severity", u.severity)] if u.severity else [])
    levels = []
    if u.ransomware:
        levels.append(with_severity + [equals("ransomware", "Known")])
    if u.exploited or u.ransomware:
        levels.append(with_severity + [equals("kev", True)])
    levels += [with_severity, base]
    unique = []
    for level in levels:
        if level not in unique:
            unique.append(level)
    return [models.Filter(must=level) for level in unique]


class Retriever:
    def __init__(self, searcher=None):
        self.searcher = searcher or Searcher()
        self.client = self.searcher.client
        self.products = load_products()
        self.rerankers = {}

    def reranker(self, name):
        if name not in self.rerankers:
            self.rerankers[name] = TextCrossEncoder(name, cache_dir=str(INDEX_DIR / "models"))
        return self.rerankers[name]

    def lookup(self, cve_id):
        points = self.client.retrieve(COLLECTION, ids=[point_id(cve_id)], with_payload=True)
        return points[0].payload["record"] if points else None

    def hybrid(self, question, limit=CANDIDATES, query_filter=None):
        """Ask both searches for their top results and merge the two lists with RRF."""
        dense = self.searcher.embedder.embed_query(question)
        sparse = next(iter(self.searcher.bm25.query_embed(question)))
        keywords = models.SparseVector(indices=sparse.indices.tolist(), values=sparse.values.tolist())
        return self.client.query_points(
            COLLECTION,
            prefetch=[models.Prefetch(query=dense, using="meaning", limit=limit, filter=query_filter),
                      models.Prefetch(query=keywords, using="keywords", limit=limit, filter=query_filter)],
            query=models.FusionQuery(fusion=models.Fusion.RRF), limit=limit, with_payload=True).points

    def rerank(self, question, points, model):
        scores = list(self.reranker(model).rerank(question, [p.payload["chunk"] for p in points]))
        return [p for _, p in sorted(zip(scores, points), key=lambda pair: -pair[0])]

    def all_matching(self, query_filter):
        points, _ = self.client.scroll(COLLECTION, scroll_filter=query_filter, limit=2000, with_payload=True)
        return [p.payload["record"] for p in points]

    def retrieve(self, question, k=5, reranker=DEFAULT_RERANKER):
        """Return (the top k hits, what the question was understood to ask)."""
        u = understand(question, self.products)
        hits, seen = [], set()

        def add(record, how):
            if record and record["id"] not in seen:
                seen.add(record["id"])
                hits.append(Hit(record, how))

        # 1. CVE numbers: open them directly, plus CVEs their records mention
        for cve in u.cve_ids:
            record = self.lookup(cve)
            add(record, "exact lookup")
            for other in CVE_ID.findall(record["text"]) if record else []:
                add(self.lookup(other.upper()), f"mentioned in {cve}")

        # 2. Where to look: the products named, or else the products of the CVEs named
        scope = [p.id for p in u.products if p.scope in ("in", "cloud")]
        if not scope and not u.vendors:
            scope = sorted({p["id"] for h in hits for p in h.record["products"] if p["scope"] == "in"})

        # "More like this": a question that only names a CVE says nothing about what the flaw is,
        # so search with the named CVEs' descriptions too, to surface look-alikes (same bug, later version)
        search_text = "\n".join([question] + [h.record["description"] for h in hits if h.how == "exact lookup"])

        # 3-4. Rank by rule, or search and rerank; relax the filters only if nothing matches
        found = []
        for query_filter in filter_levels(u, scope):
            if u.priority or u.recent:
                records = sorted(self.all_matching(query_filter), reverse=True,
                                 key=priority_key if u.priority else (lambda r: r["published"]))
                found = [(r, "patch-priority rule" if u.priority else "newest first") for r in records]
            else:
                points = self.hybrid(search_text, CANDIDATES, query_filter)
                if reranker and points:
                    points = self.rerank(question, points, reranker)
                found = [(p.payload["record"], "search") for p in points]
            if found:
                break
        for record, how in found:
            add(record, how)

        # 5. A version named: affected first, then unknown, then not affected (exact lookups stay on top)
        if u.version:
            named = [p.id for p in u.products] or None
            for h in hits:
                h.version_check = check(h.record, u.version, named)
            hits = ([h for h in hits if h.how == "exact lookup"]
                    + sorted((h for h in hits if h.how != "exact lookup"),
                             key=lambda h: VERSION_ORDER[h.version_check["status"]]))
        return hits[:k], u
