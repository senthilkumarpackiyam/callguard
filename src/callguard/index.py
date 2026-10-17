"""CallGuard's search index: clean CVE records stored in Qdrant, searchable two ways.

- meaning:  Qwen3-Embedding-8B (on Nebius) turns text into 4,096 numbers; similar meanings land close together
- keywords: BM25 scores exact words, giving rare words (a CVE number, a build like 12.6(2)ES3) more weight
"""

import hashlib
import json
import os
import time
import uuid
from pathlib import Path

import numpy as np
from dotenv import load_dotenv
from fastembed import SparseTextEmbedding
from openai import OpenAI
from qdrant_client import QdrantClient, models

from callguard.clean import versions_text

ROOT = Path(__file__).resolve().parents[2]
INDEX_DIR = ROOT / "data" / "index"
COLLECTION = "cves"
EMBEDDING_MODEL = "Qwen/Qwen3-Embedding-8B"
# Qwen3 embeddings work best when questions (not documents) carry a one-line task description
QUERY_TASK = ("Given a question about security vulnerabilities in contact-center and unified-communications "
              "products, retrieve the CVE records that answer it")


def chunk_text(record, variant="card"):
    """The text we embed for one CVE. Fast-changing facts (EPSS, last update) and links stay out of it,
    so a daily score change doesn't mean re-embedding, and URLs don't blur the meaning."""
    if variant == "description":
        return record["description"]
    names = ", ".join(p["name"] for p in record["products"])
    severity = f"CVSS {record['cvss']['score']} {record['cvss']['severity']}" if record["cvss"] else "no severity score"
    lines = [f"{record['id']} | {names} | {severity} | CISA KEV: {'listed' if record['exploited'] else 'not listed'}",
             record["description"],
             f"Affected versions: {versions_text(record)}"]
    if record["cwe"]:
        lines.append(f"Weakness: {', '.join(record['cwe'])}")
    if record["exploited"]:
        lines.append(f"Exploited in the wild since {record['exploited']['since']}; "
                     f"ransomware use: {record['exploited']['ransomware']}")
        if record["exploited"].get("summary"):
            lines.append(record["exploited"]["summary"])
    return "\n".join(lines)


def payload(record):
    """Filter tags stored next to each CVE, plus the full record for answering later."""
    return {
        "cve": record["id"],
        "products": [p["id"] for p in record["products"]],
        "vendors": sorted({p["vendor"] for p in record["products"]}),
        "scope": sorted({p["scope"] for p in record["products"]}),
        "published": record["published"],
        "year": int(record["published"][:4]),
        "severity": (record["cvss"] or {}).get("severity"),
        "cvss": (record["cvss"] or {}).get("score"),
        "kev": record["exploited"] is not None,
        "ransomware": (record["exploited"] or {}).get("ransomware"),
        "epss": (record["epss"] or {}).get("score"),
        "cwe": record["cwe"],
        "record": record,
    }


def point_id(cve_id):
    """The same CVE always gets the same ID, so updating a record replaces it instead of duplicating it."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, cve_id))


class Embedder:
    """Calls Nebius for meaning vectors, keeping every result on disk so the same text is never paid for twice."""

    def __init__(self):
        load_dotenv(ROOT / ".env")
        self.client = OpenAI(base_url=os.getenv("NEBIUS_BASE_URL") or "https://api.tokenfactory.nebius.com/v1/",
                             api_key=os.environ["NEBIUS_API_KEY"], max_retries=5, timeout=180)
        self.cache_file = INDEX_DIR / "embedding_cache.npz"
        self.cache = {}
        if self.cache_file.exists():
            saved = np.load(self.cache_file)
            self.cache = dict(zip(saved["keys"].tolist(), saved["vectors"]))
        self.tokens_used = 0

    @staticmethod
    def key(text):
        return hashlib.sha256(f"{EMBEDDING_MODEL}\n{text}".encode()).hexdigest()

    def embed(self, texts, batch=32, on_batch=None):
        missing = list(dict.fromkeys(t for t in texts if self.key(t) not in self.cache))
        for i in range(0, len(missing), batch):
            part = missing[i:i + batch]
            response = self.client.embeddings.create(model=EMBEDDING_MODEL, input=part)
            self.tokens_used += response.usage.prompt_tokens
            for text, item in zip(part, response.data):
                self.cache[self.key(text)] = np.asarray(item.embedding, dtype=np.float32)
            if on_batch:
                on_batch(min(i + batch, len(missing)), len(missing))
        if missing:
            self.save()
        return [self.cache[self.key(t)] for t in texts], len(texts) - len(missing)

    def embed_query(self, question):
        text = f"Instruct: {QUERY_TASK}\nQuery: {question}"
        if self.key(text) not in self.cache:  # asked before? reuse it
            response = self.client.embeddings.create(model=EMBEDDING_MODEL, input=[text])
            self.tokens_used += response.usage.prompt_tokens
            self.cache[self.key(text)] = np.asarray(response.data[0].embedding, dtype=np.float32)
            self.save()
        return self.cache[self.key(text)].tolist()

    def save(self):
        INDEX_DIR.mkdir(parents=True, exist_ok=True)
        keys = list(self.cache)
        np.savez(self.cache_file, keys=np.array(keys), vectors=np.stack([self.cache[k] for k in keys]))


def keyword_model():
    return SparseTextEmbedding("Qdrant/bm25", cache_dir=str(INDEX_DIR / "models"))


def open_index():
    return QdrantClient(path=str(INDEX_DIR / "qdrant"))


def build(records, variant="card", progress=print):
    """(Re)create the collection from clean records; returns a short summary."""
    started = time.time()
    texts = [chunk_text(r, variant) for r in records]
    embedder = Embedder()
    vectors, reused = embedder.embed(texts, on_batch=lambda done, total: progress(f"   meaning: {done} of {total}"))
    keywords = list(keyword_model().embed(texts))

    client = open_index()
    if client.collection_exists(COLLECTION):
        client.delete_collection(COLLECTION)
    client.create_collection(
        COLLECTION,
        vectors_config={"meaning": models.VectorParams(size=len(vectors[0]), distance=models.Distance.COSINE)},
        sparse_vectors_config={"keywords": models.SparseVectorParams(modifier=models.Modifier.IDF)},
    )
    points = [models.PointStruct(
        id=point_id(r["id"]),
        vector={"meaning": v.tolist(),
                "keywords": models.SparseVector(indices=k.indices.tolist(), values=k.values.tolist())},
        payload={**payload(r), "chunk": t})
        for r, t, v, k in zip(records, texts, vectors, keywords)]
    for i in range(0, len(points), 64):
        client.upsert(COLLECTION, points[i:i + 64])
    count = client.count(COLLECTION).count
    client.close()
    (INDEX_DIR / "index_info.json").write_text(json.dumps(
        {"variant": variant, "model": EMBEDDING_MODEL, "points": count}, indent=2) + "\n")
    return {"points": count, "embedded_now": len(texts) - reused, "reused": reused,
            "tokens": embedder.tokens_used, "seconds": round(time.time() - started)}


class Searcher:
    """Search the index by meaning or by keywords (Phase 5 combines them)."""

    def __init__(self):
        self.client = open_index()
        self.embedder = Embedder()
        self.bm25 = keyword_model()

    def by_meaning(self, question, limit=10, query_filter=None):
        return self.client.query_points(COLLECTION, query=self.embedder.embed_query(question), using="meaning",
                                        limit=limit, query_filter=query_filter, with_payload=True).points

    def by_keywords(self, question, limit=10, query_filter=None):
        sparse = next(iter(self.bm25.query_embed(question)))
        return self.client.query_points(
            COLLECTION, query=models.SparseVector(indices=sparse.indices.tolist(), values=sparse.values.tolist()),
            using="keywords", limit=limit, query_filter=query_filter, with_payload=True).points
