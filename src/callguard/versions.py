"""Is a given version affected? Decided in plain code, not by the AI, because version names are tricky:
the data holds 12.6(2)ES3, 14SU2, 9.8.1.201, R6.4.0.4006 and "< 17.0.9", among others."""

import re

PART = re.compile(r"\d+|[a-z]+")
NO_VERSION = ("", "0", "*", "-", "n/a", "unspecified")
BOUND = re.compile(r"^(<=|>=|<|>|=)?\s*(.+)$")


def parse(version):
    """Split a version into comparable parts: '12.6(2)ES3' -> (12, 6, 2, 'es', 3).
    A leading R or v is dropped (R6.4.0 = 6.4.0), and so are trailing zeros (16.0 = 16)."""
    text = str(version).replace("\\/", "/").strip().lower()
    if "/" in text:  # garbled forms like '9.8-SP1-/9.8.1.5/': keep the plain dotted number inside
        numbers = re.findall(r"\d+(?:\.\d+){2,}", text)
        text = max(numbers, key=len) if numbers else text
    text = re.sub(r"^[rv](?=\d)", "", text)
    parts = [int(p) if p.isdigit() else p for p in PART.findall(text)]
    while parts and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def compare(a, b):
    """Return -1, 0 or 1. At the same position, numbers sort before letters (14.0 < 14SU2), and a version
    sorts before a longer one that only adds parts (14 < 14SU1, 5.1.0 < 5.1.0.SP6)."""
    for x, y in zip(a, b):
        if x == y:
            continue
        if isinstance(x, int) != isinstance(y, int):
            return -1 if isinstance(x, int) else 1
        return -1 if x < y else 1
    return (len(a) > len(b)) - (len(a) < len(b))


def in_range(v, start=None, start_inclusive=True, end=None, end_inclusive=False):
    if start is not None:
        c = compare(v, parse(start))
        if c < 0 or (c == 0 and not start_inclusive):
            return False
    if end is not None:
        c = compare(v, parse(end))
        if c > 0 or (c == 0 and not end_inclusive):
            return False
    return True


def has_wildcard(text):
    return bool(re.search(r"(^|[.\s])x\b|\*", str(text).lower()))


def entry_matches(entry, v):
    """True if one version entry covers version v, False if it clearly doesn't, None if we can't tell."""
    if entry["source"] == "NVD":
        start = entry.get("versionStartIncluding") or entry.get("versionStartExcluding")
        end = entry.get("versionEndIncluding") or entry.get("versionEndExcluding")
        if start or end:
            return in_range(v, start, "versionStartIncluding" in entry, end, "versionEndIncluding" in entry)
        if entry["range"] == "all versions":
            return None  # no range given, so we can't confirm either way
        return compare(v, parse(entry["range"])) == 0

    first = str(entry.get("version", "")).strip()
    if entry.get("lessThan") or entry.get("lessThanOrEqual"):
        end = entry.get("lessThanOrEqual") or entry.get("lessThan")
        start = None if first in NO_VERSION else first
        if end == "*":
            end = None
        if has_wildcard(end or "") or has_wildcard(start or ""):
            return None
        return in_range(v, start, True, end, "lessThanOrEqual" in entry)
    if first in NO_VERSION or has_wildcard(first):
        return None
    if re.match(r"^[<>=]", first):  # a range written inside the text, e.g. ">= 17.0.2.36, < 17.0.3"
        result = True
        for part in first.split(","):
            op, value = BOUND.match(part.strip()).groups()
            c = compare(v, parse(value))
            result &= {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "=": c == 0, None: c == 0}[op]
        return result
    return compare(v, parse(first)) == 0


def check(record, version, product_ids=None):
    """Is `version` affected by this CVE? Returns {"status": affected | not affected | unknown, "because": ...}."""
    v = parse(version)
    entries = [e for e in record["versions"]
               if e["status"] == "affected" and (not product_ids or e["product"] in product_ids)]
    if not entries:
        return {"status": "unknown", "because": "no structured version data; the description may say more"}
    outcomes = [(e, entry_matches(e, v)) for e in entries]
    matched = [e for e, outcome in outcomes if outcome]
    if matched:
        because = f"{version} is covered by '{matched[0]['range']}' ({matched[0]['source']})"
        # Sources can disagree. We stay cautious (affected) but say so, rather than silently picking one
        sources_matched = {e["source"] for e in matched}
        excluded_by = sorted({e["source"] for e, outcome in outcomes if outcome is False} - sources_matched)
        if excluded_by:
            because += f"; but {', '.join(excluded_by)} lists versions that exclude it, so the sources disagree"
        return {"status": "affected", "because": because}
    if any(outcome is False for _, outcome in outcomes):
        ranges = sorted({e["range"] for e, outcome in outcomes if outcome is False})
        shown = "; ".join(ranges[:4]) + (f"; and {len(ranges) - 4} more" if len(ranges) > 4 else "")
        return {"status": "not affected", "because": f"{version} is outside every listed version: {shown}"}
    return {"status": "unknown", "because": "the listed versions can't be compared automatically"}
