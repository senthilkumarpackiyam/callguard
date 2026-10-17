"""Run the sync on its own every 2 hours, using macOS's built-in scheduler (launchd).

Turn it on:   uv run scripts/schedule_sync.py on
Check it:     uv run scripts/schedule_sync.py status
Turn it off:  uv run scripts/schedule_sync.py off

The schedule lives in ~/Library/LaunchAgents/com.callguard.sync.plist, and each run's output goes to
~/Library/Logs/callguard-sync.log. The Mac must be on for it to run; a run missed during sleep happens after waking.
"""

import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LABEL = "com.callguard.sync"
PLIST = Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"
LOG = Path.home() / "Library" / "Logs" / "callguard-sync.log"
EVERY_SECONDS = 2 * 60 * 60  # NVD asks automated tools to sync no more often than every two hours
DOMAIN = f"gui/{os.getuid()}"


def turn_on():
    uv = shutil.which("uv") or str(Path.home() / ".local" / "bin" / "uv")
    PLIST.parent.mkdir(parents=True, exist_ok=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    turn_off(quiet=True)
    PLIST.write_bytes(plistlib.dumps({
        "Label": LABEL,
        "ProgramArguments": [uv, "run", "--project", str(ROOT), "scripts/sync.py"],
        "WorkingDirectory": str(ROOT),
        "StartInterval": EVERY_SECONDS,
        "RunAtLoad": True,  # also run once right away
        "StandardOutPath": str(LOG),
        "StandardErrorPath": str(LOG),
        "EnvironmentVariables": {"PATH": f"{Path(uv).parent}:/usr/bin:/bin:/usr/sbin:/sbin",
                                 "HOME": str(Path.home())},
    }))
    subprocess.run(["launchctl", "bootstrap", DOMAIN, str(PLIST)], check=True)
    print(f"Sync scheduled every 2 hours, starting now. Log: {LOG}")


def turn_off(quiet=False):
    subprocess.run(["launchctl", "bootout", f"{DOMAIN}/{LABEL}"], capture_output=True)
    PLIST.unlink(missing_ok=True)
    if not quiet:
        print("Sync schedule removed.")


def status():
    r = subprocess.run(["launchctl", "print", f"{DOMAIN}/{LABEL}"], capture_output=True, text=True)
    if r.returncode != 0:
        print("Not scheduled.")
        return
    for line in r.stdout.splitlines():
        if any(key in line for key in ("state =", "last exit code", "runs =", "run interval")):
            print(line.strip())
    if LOG.exists():
        print("--- last lines of the log ---\n" + "\n".join(LOG.read_text().splitlines()[-8:]))


if __name__ == "__main__":
    {"on": turn_on, "off": turn_off, "status": status}[(sys.argv[1:] or ["status"])[0]]()
