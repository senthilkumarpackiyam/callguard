"""Phase 8: bring CallGuard's data up to date: only what changed since the last sync.

Run it with:  uv run scripts/sync.py
The scheduled job (scripts/schedule_sync.py) runs this every 2 hours.
"""

from datetime import datetime

from callguard.sync import sync

if __name__ == "__main__":
    print(f"--- CallGuard sync, {datetime.now():%Y-%m-%d %H:%M} local time ---", flush=True)
    sync(log=lambda message: print(message, flush=True))
