"""
CVE-ID regex edge cases, against the live config.cleaning.cve_id_regex
(not a hardcoded copy) so these tests fail if config.yaml's pattern ever
drifts from what the clean scripts actually rely on.
"""

from __future__ import annotations

import pytest

from config.config_schema import get_config
from scripts.common.cve_id import find_cve_ids, is_valid_cve_id

VALID_CVE_IDS = [
    "CVE-1999-0001",  # earliest CVE year, 4-digit sequence
    "CVE-2026-13362",  # 5-digit sequence
    "CVE-2021-123456",  # 6-digit sequence (post-2014 unbounded length)
    "CVE-2021-1234567",  # 7-digit sequence
]

INVALID_CVE_IDS = [
    "",
    "CVE-2026-123",  # sequence too short (must be >= 4 digits)
    "cve-2026-13362",  # lowercase prefix
    "CVE-26-13362",  # 2-digit year
    "CVE-2026-",  # missing sequence
    "CVE-2026-13362a",  # trailing junk
    "NVD-CWE-noinfo",  # a real value NVD puts in weaknesses[].description — not a CVE
    "CVE_2026_13362",  # wrong separator
    "CVE-2026-13362;OSVDB-58726",  # a whole ExploitDB `codes` field, not a bare ID
]


@pytest.mark.parametrize("cve_id", VALID_CVE_IDS)
def test_valid_cve_ids_accepted(cve_id: str) -> None:
    assert is_valid_cve_id(cve_id, get_config())


@pytest.mark.parametrize("cve_id", INVALID_CVE_IDS)
def test_invalid_cve_ids_rejected(cve_id: str) -> None:
    assert not is_valid_cve_id(cve_id, get_config())


def test_is_valid_cve_id_strips_surrounding_whitespace_before_matching() -> None:
    # is_valid_cve_id strips before matching (staging rows can carry
    # incidental whitespace); find_cve_ids does NOT strip embedded ids,
    # by design — see test_find_cve_ids_ignores_embedded_whitespace below.
    assert is_valid_cve_id("  CVE-2026-13362  ", get_config())


def test_find_cve_ids_extracts_from_semicolon_separated_codes_field() -> None:
    codes = "CVE-2009-3699;OSVDB-58726"
    assert find_cve_ids(codes, get_config()) == {"CVE-2009-3699"}


def test_find_cve_ids_extracts_multiple_embedded_ids() -> None:
    codes = "CVE-2021-1234;CVE-2021-5678;EDB-ID-12345"
    assert find_cve_ids(codes, get_config()) == {"CVE-2021-1234", "CVE-2021-5678"}


def test_find_cve_ids_returns_empty_set_for_no_match() -> None:
    assert find_cve_ids("OSVDB-58726;metasploit", get_config()) == set()


def test_find_cve_ids_ignores_embedded_whitespace() -> None:
    # A CVE ID with an internal space is not well-formed and must not match.
    assert find_cve_ids("CVE- 2026-13362", get_config()) == set()


def test_find_cve_ids_is_case_sensitive() -> None:
    assert find_cve_ids("cve-2026-13362", get_config()) == set()
