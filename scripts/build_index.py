"""Phase 4: build CallGuard's search index from the clean records.

Run it with:  uv run scripts/build_index.py
Experiments (Phase 9) build other chunk designs side by side, leaving the main index alone:
              uv run scripts/build_index.py --variant description --collection cves_description
Embeddings are saved in data/index/, so a rebuild only pays for new or changed text.
"""

import argparse
import json
from pathlib import Path

from callguard.index import COLLECTION, build

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", default="card", choices=["card", "card-no-header", "description"])
    parser.add_argument("--collection", default=COLLECTION)
    args = parser.parse_args()
    records = [json.loads(line) for line in open(ROOT / "data" / "processed" / "cves.jsonl")]
    print(f"Indexing {len(records)} CVE records as '{args.variant}' chunks into '{args.collection}'")
    summary = build(records, args.variant, progress=lambda message: print(message, flush=True),
                    collection=args.collection)
    print(f"Done: {summary['points']} records searchable. {summary['embedded_now']} embedded now "
          f"({summary['tokens']:,} tokens), {summary['reused']} reused from the cache, "
          f"in {summary['seconds']} seconds")


if __name__ == "__main__":
    main()
