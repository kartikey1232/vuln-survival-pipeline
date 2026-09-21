"""
Vendor-name normalization.

`generic_normalize` is the ONLY normalization ever applied to
canonical.cpe_product.vendor_normalized. CPE vendor segments (e.g.
"ueberauth", "microsoft") are already short lowercase slugs for every CVE,
KEV-listed or not — normalizing them is a pure string-cleanup operation
(strip legal suffixes/punctuation) with no dependency on any KEV-derived
lookup table. Keeping it that way matters: canonical.cpe_product exists for
every CVE in canonical.cve, while KEV vendor names only exist for the
positive class (KEV-listed CVEs). If vendor_normalized for the *same*
vendor came out differently depending on whether that vendor happened to
also appear in KEV, a downstream feature keyed on vendor_normalized would
be leaking the label.

config/vendor_aliases.yaml is a SEPARATE, KEV-specific translation table:
KEV's `vendorProject` field is a display name ("Hewlett Packard (HP)",
"D-Link and TRENDnet") that often doesn't match any CPE vendor slug at
all — it exists purely to let something that reads KEV rows (e.g. a
future vendor_historical_kev_rate feature) resolve a KEV vendor name onto
the same vendor_normalized bucket used by cpe_product, via
`normalize_kev_vendor`. It is never applied to CPE data.
"""

from __future__ import annotations

import re

import yaml

from config.config_schema import Config

_LEGAL_SUFFIXES = [
    ", inc.", ", inc", " inc.", " inc",
    ", llc", " llc",
    ", ltd.", ", ltd", " ltd.", " ltd",
    " corporation", " corp.", " corp",
    " incorporated",
    " co.", " company",
    " gmbh", " ag", " se", " s.a.", " sa",
]


def generic_normalize(raw: str) -> str:
    """Lowercase, strip a trailing legal suffix (at most one), strip
    punctuation, collapse whitespace/underscores to single spaces."""
    s = raw.strip().lower()
    for suffix in _LEGAL_SUFFIXES:
        if s.endswith(suffix):
            s = s[: -len(suffix)].strip()
            break
    s = re.sub(r"[.,!]", "", s)
    s = re.sub(r"[_\s]+", " ", s).strip()
    return s


def load_kev_vendor_aliases(cfg: Config) -> dict[str, str]:
    path = cfg.cleaning.vendor_alias_map_path
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text()) or {}
    return {str(k).strip().lower(): str(v).strip().lower() for k, v in raw.items()}


def normalize_kev_vendor(raw: str, aliases: dict[str, str]) -> str:
    """Resolve a KEV `vendorProject` display string onto the vendor_normalized
    namespace used by canonical.cpe_product. Alias lookup first (exact,
    lowercased); falls back to generic_normalize for anything not in the
    table — which for a display name like "Hewlett Packard (HP)" will NOT
    reliably match the real CPE slug ("hp"), which is exactly why explicit
    aliases exist for cases like that."""
    lowered = raw.strip().lower()
    if lowered in aliases:
        return aliases[lowered]
    return generic_normalize(raw)
