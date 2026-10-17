"""Phase 4: build CallGuard's search index from the clean records.

Run it with:  uv run scripts/build_index.py
Embeddings are saved in data/index/, so a rebuild only pays for new or changed records.
"""

import json
from pathlib import Path

from callguard.index import build

ROOT = Path(__file__).resolve().parent.parent


def main():
    records = [json.loads(line) for line in open(ROOT / "data" / "processed" / "cves.jsonl")]
    print(f"Indexing {len(records)} CVE records")
    summary = build(records, progress=lambda message: print(message, flush=True))
    print(f"Done: {summary['points']} records searchable. {summary['embedded_now']} embedded now "
          f"({summary['tokens']:,} tokens), {summary['reused']} reused from the cache, "
          f"in {summary['seconds']} seconds")


if __name__ == "__main__":
    main()
