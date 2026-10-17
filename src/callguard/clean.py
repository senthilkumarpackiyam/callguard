"""Turn raw NVD records, plus KEV and EPSS data, into clean CallGuard records."""

from callguard.products import english_description

# Organizations that some fields name by ID or email
SOURCE_NAMES = {
    "134c704f-9b21-4f2e-91b3-4a467353bcc0": "CISA (ADP)",
    "nvd@nist.gov": "NVD",
    "cve@mitre.org": "MITRE",
    "psirt@cisco.com": "Cisco",
    "security-advisories@github.com": "GitHub",
}
# CVSS 3.1 first so scores are comparable across CVEs; NVD's own score before others'
CVSS_PREFERENCE = ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"]
# Link types worth keeping, most useful first
LINK_TAGS = ["Vendor Advisory", "Patch", "Mitigation", "Release Notes", "Third Party Advisory", "Exploit"]
NO_VERSION = ("", "0", "*", "-", "n/a", "unspecified")
MAX_VERSIONS_IN_TEXT = 12


def pick_cvss(cve):
    metrics = cve.get("metrics", {})
    for key in CVSS_PREFERENCE:
        for entry in sorted(metrics.get(key, []), key=lambda e: e.get("type") != "Primary"):
            data = entry.get("cvssData", {})
            if "baseScore" in data:
                return {"score": data["baseScore"],
                        "severity": data.get("baseSeverity") or entry.get("baseSeverity"),
                        "version": data.get("version"),
                        "vector": data.get("vectorString"),
                        "source": SOURCE_NAMES.get(entry["source"], entry["source"])}
    return None


def weaknesses(cve):
    return sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if d["value"].startswith("CWE-")})


def ssvc(cve):
    """CISA's quick triage: is it being exploited, can attacks be automated, how bad is the impact."""
    for entry in cve.get("metrics", {}).get("ssvcV203", []):
        options = {k: v for o in entry.get("ssvcData", {}).get("options", []) for k, v in o.items()}
        return {"exploitation": options.get("exploitation"), "automatable": options.get("automatable"),
                "technical_impact": options.get("technicalImpact")}
    return None


def cpe_range(match):
    """Readable version range for one of NVD's CPE matches."""
    parts = [p.replace("\\", "") for p in match["criteria"].split(":")]
    start = (f"from {match['versionStartIncluding']}" if "versionStartIncluding" in match
             else f"after {match['versionStartExcluding']}" if "versionStartExcluding" in match else "")
    end = (f"up to and including {match['versionEndIncluding']}" if "versionEndIncluding" in match
           else f"before {match['versionEndExcluding']}" if "versionEndExcluding" in match else "")
    if start or end:
        return " ".join(filter(None, (start, end)))
    if parts[5] in NO_VERSION:
        return "all versions"
    return parts[5] if len(parts) < 7 or parts[6] in ("*", "-") else f"{parts[5]} {parts[6]}"


def vendor_range(version):
    """Readable version range for one entry in the vendor's own list."""
    first = str(version.get("version", "")).strip()
    if version.get("lessThan") == "*":
        text = f"{first} and later"
    elif version.get("lessThan"):
        text = (f"before {version['lessThan']}" if first in NO_VERSION
                else f"from {first}, before {version['lessThan']}")
    elif version.get("lessThanOrEqual"):
        text = (f"up to and including {version['lessThanOrEqual']}" if first in NO_VERSION
                else f"from {first} up to and including {version['lessThanOrEqual']}")
    else:
        text = first or "unspecified"
    return text


def affected_versions(cve, products):
    """Version ranges per product, from NVD's analysis (CPE) and from the vendor's own list."""
    found, seen = [], set()

    def add(item):
        key = (item["product"], item["source"], item["status"], item["range"])
        if key not in seen:
            seen.add(key)
            found.append(item)

    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match["criteria"].split(":")
                product = next((p for p in products if p.owns_cpe(f"{parts[3]}:{parts[4]}".lower())), None)
                if match.get("vulnerable") and product:
                    add({"product": product.id, "source": "NVD", "status": "affected", "range": cpe_range(match),
                         **{k: v for k, v in match.items() if k.startswith("version")}})
    for source in cve.get("affected", []):
        for entry in source.get("affectedData", []):
            vendor, name = str(entry.get("vendor", "")).lower(), str(entry.get("product", "")).lower()
            product = next((p for p in products if p.owns_entry(vendor, name)), None)
            for version in entry.get("versions", []) if product else []:
                add({"product": product.id, "source": SOURCE_NAMES.get(source["source"], source["source"]),
                     "status": version.get("status", "affected"), "range": vendor_range(version),
                     **{k: version[k] for k in ("version", "lessThan", "lessThanOrEqual", "versionType")
                        if k in version}})
    return found


def exploitation(kev_entry):
    if not kev_entry:
        return None
    return {"since": kev_entry["dateAdded"], "federal_due_date": kev_entry.get("dueDate"),
            "required_action": kev_entry.get("requiredAction"),
            "ransomware": kev_entry.get("knownRansomwareCampaignUse"),
            "forensic_triage": kev_entry.get("forensicTriage"), "name": kev_entry.get("vulnerabilityName"),
            "summary": kev_entry.get("shortDescription")}  # CISA's own words, e.g. which flaws get chained


def useful_links(cve, limit=6):
    """Advisory and fix links first; untagged records keep their first few links."""
    tagged = [(min(LINK_TAGS.index(t) for t in tags), ref["url"], tags)
              for ref in cve.get("references", [])
              if (tags := [t for t in ref.get("tags", []) if t in LINK_TAGS])]
    if not tagged:
        return [{"url": ref["url"], "tags": []} for ref in cve.get("references", [])[:3]]
    links, seen = [], set()
    for _, url, tags in sorted(tagged, key=lambda t: t[0]):
        if url not in seen:
            seen.add(url)
            links.append({"url": url, "tags": tags})
    return links[:limit]


def clean_record(cve, products, matched_by, kev_entry=None, epss=None):
    record = {
        "id": cve["id"],
        "published": cve["published"][:10],
        "last_modified": cve["lastModified"][:10],
        "nvd_status": cve.get("vulnStatus"),
        "products": [{"id": p.id, "name": p.name, "vendor": p.vendor, "scope": p.scope} for p in products],
        "matched_by": matched_by,
        "description": english_description(cve),
        "cvss": pick_cvss(cve),
        "cwe": weaknesses(cve),
        "versions": affected_versions(cve, products),
        "exploited": exploitation(kev_entry),
        "ssvc": ssvc(cve),
        "epss": epss,
        "links": useful_links(cve),
    }
    record["text"] = render_text(record)
    return record


def versions_text(record):
    names = {p["id"]: p["name"] for p in record["products"]}
    ranges = {}
    for v in record["versions"]:
        if v["status"] == "affected" and v["range"] not in ranges.setdefault(v["product"], []):
            ranges[v["product"]].append(v["range"])
    parts = []
    for product_id, items in ranges.items():
        more = len(items) - MAX_VERSIONS_IN_TEXT
        parts.append(f"{names[product_id]}: {', '.join(items[:MAX_VERSIONS_IN_TEXT])}"
                     + (f" and {more} more" if more > 0 else ""))
    return "; ".join(parts) or "not in the structured data; see the description"


def render_text(r):
    """A readable card for one CVE: what people, and later the AI, will read."""
    names = ", ".join(p["name"] for p in r["products"])
    severity = f"CVSS {r['cvss']['score']} {r['cvss']['severity']}" if r["cvss"] else "no severity score yet"
    lines = [f"{r['id']} | {names} | {severity} | CISA KEV: {'listed' if r['exploited'] else 'not listed'}",
             f"Published {r['published']}, last updated {r['last_modified']} (NVD status: {r['nvd_status']})",
             "", r["description"], "",
             f"Affected versions: {versions_text(r)}"]
    if r["cwe"]:
        lines.append(f"Weakness: {', '.join(r['cwe'])}")
    if r["exploited"]:
        e = r["exploited"]
        lines.append(f"Exploitation: in CISA KEV since {e['since']}; ransomware use: {e['ransomware']}; "
                     f"required action: {e['required_action']}")
        if e.get("summary"):
            lines.append(f"CISA's summary: {e['summary']}")
    if r["epss"]:
        lines.append(f"Exploit forecast (EPSS, {r['epss']['date']}): {r['epss']['score']:.1%} chance of "
                     f"exploitation in the next 30 days")
    if r["links"]:
        lines.append("Advisories and fixes: " + "; ".join(
            link["url"] + (f" ({', '.join(link['tags'])})" if link["tags"] else "") for link in r["links"]))
    return "\n".join(lines)
