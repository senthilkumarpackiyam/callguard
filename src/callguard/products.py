"""CallGuard's product list: load config/products.toml and match CVE records to products."""

import html
import re
import tomllib
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

PRODUCTS_FILE = Path(__file__).resolve().parents[2] / "config" / "products.toml"


@dataclass(frozen=True)
class Product:
    id: str
    name: str
    vendor: str
    scope: str  # "in", "cloud" or "out"
    aka: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    vendor_names: tuple[str, ...] = ()
    cpe: tuple[str, ...] = ()
    affected: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()

    def owns_cpe(self, cpe_name):
        """True if an NVD product name ("vendor:product") belongs to this product."""
        return any(fnmatchcase(cpe_name, pattern) for pattern in self.cpe)

    def owns_entry(self, vendor, product):
        """True if a vendor-list entry (vendor, product), both lowercase, belongs to this product."""
        if any(text in product for text in self.exclude):
            return False
        for pattern in self.affected:
            want_vendor, _, want_product = (part.strip() for part in pattern.partition("|"))
            if want_vendor in vendor and want_product in product:
                return True
        return False

    def mentioned_in(self, text):
        """True if a description names this product's vendor and one of its keywords, as whole words."""
        vendors = self.vendor_names or (self.vendor,)
        return any(v in text for v in vendors) and any(
            re.search(rf"(?<!\w){re.escape(k)}(?!\w)", text) for k in self.keywords)


def load_products(path=PRODUCTS_FILE):
    with open(path, "rb") as f:
        entries = tomllib.load(f)["product"]
    return [Product(**{k: tuple(v) if isinstance(v, list) else v for k, v in e.items()}) for e in entries]


def product_names(cve):
    """Return a CVE record's NVD product names ("vendor:product") and vendor-list entries ((vendor, product))."""
    cpe_names = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    parts = match["criteria"].split(":")
                    cpe_names.add(f"{parts[3]}:{parts[4]}".lower())
    vendor_entries = set()
    for source in cve.get("affected", []):
        for entry in source.get("affectedData", []):
            vendor = str(entry.get("vendor", "")).strip().lower()
            product = str(entry.get("product", "")).strip().lower()
            if vendor not in ("", "n/a") and product not in ("", "n/a"):
                vendor_entries.add((vendor, product))
    return cpe_names, vendor_entries


WEB_CODE = re.compile(r"&(?:#\d+|#x[0-9a-f]+|[a-z]+\d*);", re.IGNORECASE)  # complete codes only, e.g. "&amp;"


def english_description(cve):
    # Some NVD texts carry web codes such as "&amp;" (for "&"); turn them back into the characters they stand for.
    # Only complete codes are decoded, so a web address like "?a=1&para=2" is left alone.
    text = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return WEB_CODE.sub(lambda code: html.unescape(code.group()), text).replace("\xa0", " ")


def match_products(cve, products):
    """Return (products the CVE affects, how we know): "product data", "description" or "none".

    The description is only used when the record has no product data at all.
    """
    cpe_names, vendor_entries = product_names(cve)
    if cpe_names or vendor_entries:
        found = [p for p in products
                 if any(p.owns_cpe(n) for n in cpe_names) or any(p.owns_entry(v, n) for v, n in vendor_entries)]
        return found, "product data" if found else "none"
    text = english_description(cve)
    found = [p for p in products if p.mentioned_in(text)]
    return found, "description" if found else "none"
