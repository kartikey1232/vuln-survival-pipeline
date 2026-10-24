"""
Feature values must not depend on surrogate ids. A BIGSERIAL column
(cvss_metric_id, cpe_product_id, staging_id, ...) is ordered by insertion
history, so a feature that sorts on one, or picks "the first row" in the
order Postgres happens to return, can change when the same data is
re-ingested in a different order.

Two guards:
- static: no feature-path module mentions a surrogate-id column in code
  (SQL text or pandas column names), so it can neither select, sort nor
  filter on one. The surrogate set is read from database/schema.sql, so a
  new BIGSERIAL column is covered without editing this test.
- behavioural: every "pick one row per CVE" step gives the same answer
  under any input row order, including ties.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from scripts.features.build_landmark_dataset import pick_own_cna_cvss, pick_primary_vendor

ROOT = Path(__file__).resolve().parents[2]
FEATURE_PATH_MODULES = [
    ROOT / "scripts" / "features" / "build_landmark_dataset.py",
    ROOT / "scripts" / "features" / "build_holdout_cohort.py",
]
PREFERENCE = ["3.1", "3.0", "4.0", "2.0"]


def surrogate_id_columns() -> set[str]:
    schema = (ROOT / "database" / "schema.sql").read_text()
    return set(re.findall(r"^\s*(\w+)\s+(?:BIG)?SERIAL\b", schema, flags=re.MULTILINE | re.IGNORECASE))


def code_strings(source: str) -> list[tuple[int, str]]:
    """Every string literal in `source` except docstrings (prose may name a
    surrogate id to explain why it is not used), with its line number."""
    tree = ast.parse(source)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
    return [(n.lineno, n.value) for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings]


def surrogate_references(source: str, surrogates: set[str]) -> list[tuple[int, str]]:
    pattern = re.compile(r"\b(" + "|".join(sorted(surrogates)) + r")\b")
    return [(line, m.group(1)) for line, s in code_strings(source) for m in pattern.finditer(s)]


def test_surrogate_id_set_is_read_from_schema():
    assert {"cvss_metric_id", "cpe_product_id", "staging_id", "manifest_id"} <= surrogate_id_columns()


@pytest.mark.parametrize("module", FEATURE_PATH_MODULES, ids=lambda p: p.name)
def test_feature_path_never_references_a_surrogate_id(module):
    refs = surrogate_references(module.read_text(), surrogate_id_columns())
    assert not refs, f"{module.name} references surrogate ids (line, column): {refs}"


def test_static_check_catches_a_surrogate_sort():
    """The check itself must fail on the pattern it exists for (the
    primary-vendor pick before 2026-10-24 sorted on cpe_product_id)."""
    bad = ('cpe = pd.read_sql("SELECT cpe_product_id, cve_id, vendor_normalized FROM canonical.cpe_product", e)\n'
           'first = cpe.sort_values("cpe_product_id").groupby("cve_id").first()\n')
    assert {c for _, c in surrogate_references(bad, surrogate_id_columns())} == {"cpe_product_id"}
    doc_only = 'def f():\n    """sorted on cpe_product_id before"""\n    return 1\n'
    assert surrogate_references(doc_only, surrogate_id_columns()) == []


def _permutations(df: pd.DataFrame, n: int = 25):
    rng = np.random.default_rng(20260922)
    for _ in range(n):
        yield df.iloc[rng.permutation(len(df))].reset_index(drop=True)


def test_own_cna_cvss_pick_is_independent_of_row_order():
    cvss = pd.DataFrame({
        "cve_id": ["CVE-A", "CVE-A", "CVE-A", "CVE-B", "CVE-B", "CVE-C"],
        "cvss_version": ["3.1", "3.1", "2.0", "4.0", "3.0", "3.1"],
        # CVE-A: two 3.1 metrics that disagree (a tie on version)
        "cvss_base_score": [9.8, 7.5, 5.0, 8.0, 6.1, np.nan],
        "attack_vector": ["NETWORK", "LOCAL", "NETWORK", "NETWORK", "ADJACENT_NETWORK", "NETWORK"],
        "attack_complexity": ["LOW"] * 6, "privileges_required": ["NONE"] * 6, "user_interaction": ["NONE"] * 6,
        "confidentiality_impact": ["HIGH"] * 6, "integrity_impact": ["HIGH"] * 6, "availability_impact": ["HIGH"] * 6,
    })
    results = [pick_own_cna_cvss(p, PREFERENCE).sort_values("cve_id").reset_index(drop=True)
               for p in _permutations(cvss)]
    for r in results[1:]:
        pd.testing.assert_frame_equal(r, results[0])
    a = results[0].set_index("cve_id")
    assert a.loc["CVE-A", "cvss_version"] == "3.1" and a.loc["CVE-B", "cvss_version"] == "3.0"


def test_primary_vendor_pick_is_independent_of_row_order():
    cpe = pd.DataFrame({
        "cve_id": ["CVE-A", "CVE-A", "CVE-A", "CVE-B", "CVE-B"],
        "vendor_normalized": ["zyxel", "apache", "apache", "microsoft", None],
        "product_normalized": ["nas", "tomcat", "httpd", "windows", "x"],
    })
    results = [pick_primary_vendor(p).sort_values("cve_id").reset_index(drop=True) for p in _permutations(cpe)]
    for r in results[1:]:
        pd.testing.assert_frame_equal(r, results[0])
    assert results[0].set_index("cve_id")["primary_vendor"].to_dict() == {"CVE-A": "apache", "CVE-B": "microsoft"}
