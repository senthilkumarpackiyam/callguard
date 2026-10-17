"""CallGuard's product list: load config/products.toml and match CVE records to products."""

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
    cpe: tuple[str, ...] = ()
    affected: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()

    def matches(self, cpe_names, vendor_entries):
        """True if any of a CVE's product names belongs to this product."""
        if any(fnmatchcase(name, pattern) for name in cpe_names for pattern in self.cpe):
            return True
        for vendor, product in vendor_entries:
            if any(text in product for text in self.exclude):
                continue
            for pattern in self.affected:
                want_vendor, _, want_product = (part.strip() for part in pattern.partition("|"))
                if want_vendor in vendor and want_product in product:
                    return True
        return False


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


def match_products(cve, products):
    """Return the products a CVE record affects."""
    cpe_names, vendor_entries = product_names(cve)
    return [p for p in products if p.matches(cpe_names, vendor_entries)]
