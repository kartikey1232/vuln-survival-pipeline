"""
Shared CVE-ID validation, built from config.cleaning.cve_id_regex (the
single source of truth for what counts as a well-formed CVE ID across
every clean_*.py script) instead of each script hardcoding its own pattern.
"""

from __future__ import annotations

import re
from functools import lru_cache

from config.config_schema import Config


@lru_cache(maxsize=1)
def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def cve_id_pattern(cfg: Config) -> re.Pattern[str]:
    return _compiled(cfg.cleaning.cve_id_regex)


def is_valid_cve_id(cve_id: str, cfg: Config) -> bool:
    return bool(cve_id_pattern(cfg).fullmatch(cve_id.strip()))


def find_cve_ids(text: str, cfg: Config) -> set[str]:
    """Extracts every well-formed CVE ID substring from free text (e.g. the
    semicolon-separated ExploitDB `codes` column). Uses the same pattern as
    `is_valid_cve_id` but without the anchors, so it matches embedded
    occurrences rather than requiring the whole string to be one CVE ID."""
    anchored = cfg.cleaning.cve_id_regex
    unanchored = anchored.lstrip("^").rstrip("$")
    return set(re.findall(unanchored, text))
