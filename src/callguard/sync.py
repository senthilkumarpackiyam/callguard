"""Keep CallGuard's data fresh by fetching only what changed since the last sync (an "upsert", not a rebuild).

- NVD: every CVE changed since the last sync, asked for by time window (NVD allows at most 120 days per request).
  Each one is added, updated, or removed (rejected, or no longer about our products).
- CISA KEV and FIRST EPSS: small, so fetched in full and applied to every record.
- The index: changes are queued, then applied by whichever program opens the index next. Only one program can
  have it open at a time, so if the chat app has it open, the app applies them before its next answer.
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

from callguard.clean import clean_record, exploitation, render_text
from callguard.index import PROCESSED, ROOT, Embedder, add_pending, apply_pending, keyword_model, open_index
from callguard.products import load_products, match_products
from callguard.sources import Sources, changed_query

RAW_UPDATES = ROOT / "data" / "raw" / "nvd_updates"
MAX_WINDOW = timedelta(days=120)  # NVD's limit for one changed-since request


def utc(text):
    """Read an ISO time; NVD's times carry no zone, and they're UTC."""
    t = datetime.fromisoformat(text)
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def windows(start, end, size=MAX_WINDOW):
    """Split [start, end) into back-to-back windows no longer than `size`."""
    while start < end:
        yield start, min(start + size, end)
        start += size


def write_atomically(path, text):
    """Write to a temporary file, then swap it in, so a program reading at that moment never sees half a file."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text)
    os.replace(temporary, path)


def sync(log=print):
    started = time.time()
    load_dotenv(ROOT / ".env")
    manifest = json.loads((PROCESSED / "manifest.json").read_text())
    records = {r["id"]: r for r in (json.loads(line) for line in open(PROCESSED / "cves.jsonl"))}
    products = load_products()
    sources = Sources(os.getenv("NVD_API_KEY"))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    since = utc(manifest["nvd"].get("synced_through") or manifest["nvd"]["newest_change"])

    # 1. NVD: everything changed since the last sync
    changed = {}
    RAW_UPDATES.mkdir(parents=True, exist_ok=True)
    for start, end in windows(since, now):
        for first, _, page in sources.nvd_pages(changed_query(start, end)):
            (RAW_UPDATES / f"{start:%Y%m%dT%H%M%S}_{first}.json").write_text(json.dumps(page))
            for v in page["vulnerabilities"]:
                changed[v["cve"]["id"]] = v["cve"]
    log(f"NVD: {len(changed)} CVEs changed anywhere since {since:%Y-%m-%d %H:%M} UTC")

    # 2. Add, update or remove each changed CVE that concerns our products
    kev = sources.kev_catalog()
    kev_by_id = {k["cveID"]: k for k in kev["vulnerabilities"]}
    added, updated, removed = [], [], []
    for cve_id, cve in changed.items():
        found, matched_by = match_products(cve, products)
        if cve.get("vulnStatus") != "Rejected" and any(p.scope in ("in", "cloud") for p in found):
            (updated if cve_id in records else added).append(cve_id)
            records[cve_id] = clean_record(cve, found, matched_by, kev_by_id.get(cve_id),
                                           (records.get(cve_id) or {}).get("epss"))
        elif cve_id in records:
            removed.append(cve_id)
            del records[cve_id]
    log(f"   ours: {len(added)} new, {len(updated)} updated, {len(removed)} removed")

    # 3. KEV and EPSS for every record
    kev_changes = []
    for cve_id, record in records.items():
        exploited = exploitation(kev_by_id.get(cve_id))
        if exploited != record["exploited"]:
            record["exploited"] = exploited
            kev_changes.append(cve_id)
    epss = sources.epss_scores(records)
    epss_changes = [cve_id for cve_id, record in records.items()
                    if epss.get(cve_id) and epss[cve_id] != record["epss"]]
    for cve_id in epss_changes:
        records[cve_id]["epss"] = epss[cve_id]
    for cve_id in set(kev_changes) | set(epss_changes):
        records[cve_id]["text"] = render_text(records[cve_id])
    log(f"CISA KEV catalog {kev['catalogVersion']}: {len(kev_changes)} of our records changed "
        f"{kev_changes if kev_changes else ''}".rstrip())
    log(f"EPSS: {len(epss_changes)} scores changed")

    # 4. Save the records, the manifest ("data as of") and a line in the sync log
    write_atomically(PROCESSED / "cves.jsonl",
                     "".join(json.dumps(records[i], ensure_ascii=False) + "\n" for i in sorted(records)))
    newest = max([manifest["nvd"]["newest_change"], *(c["lastModified"] for c in changed.values())])
    manifest.update({
        "collected_at": now.isoformat(),
        "records": len(records),
        "in_scope": sum(any(p["scope"] == "in" for p in r["products"]) for r in records.values()),
        "cloud_only": sum(all(p["scope"] != "in" for p in r["products"]) for r in records.values()),
        "kev": {"catalog_version": kev["catalogVersion"], "released": kev["dateReleased"]},
        "epss": {"score_date": max((s["date"] for s in epss.values()), default=manifest["epss"]["score_date"])},
    })
    manifest["nvd"].update({"synced_through": now.isoformat(), "newest_change": newest})
    entry = {"at": now.isoformat(), "since": since.isoformat(), "nvd_changed": len(changed), "added": added,
             "updated": updated, "removed": removed, "kev_changes": kev_changes, "epss_changes": len(epss_changes)}
    with open(PROCESSED / "sync_log.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")

    # 5. The index: queue the changes, then apply them now if no other program has the index open
    add_pending(upsert_ids=added + updated + kev_changes + epss_changes, delete_ids=removed)
    write_atomically(PROCESSED / "manifest.json", json.dumps(manifest, indent=2) + "\n")  # last: signals "done"
    try:
        client = open_index()
    except RuntimeError as e:
        if "already accessed" not in str(e):
            raise
        log("Index: open in another program (the chat app?), which will apply the changes before its next answer")
    else:
        changed_entries = apply_pending(client, Embedder(), keyword_model())
        client.close()
        log(f"Index: {changed_entries} entries updated")
    entry["seconds"] = round(time.time() - started)
    log(f"Done in {entry['seconds']} seconds. Data as of {now:%Y-%m-%d %H:%M} UTC")
    return entry
