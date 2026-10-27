"""
`vsp results` (scripts/results/): prints the committed corrected-labels
record, hardcodes no number, never touches the database or network, and
`--check` catches output that disagrees with the record.
"""

from __future__ import annotations

import ast
import io
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from scripts.cli import app
from scripts.results import check, render
from scripts.results.record import BUDGETS, RECORD_PATH, Diff, load

ROOT = Path(__file__).resolve().parents[2]
PKG = ROOT / "scripts" / "results"
FORMATTING_MODULE = PKG / "render.py"
COMMAND_MODULES = sorted(PKG.glob("*.py"))
# Outside the formatting code: 0 is the null of a paired difference, 1 and 2
# make a half-unit rounding tolerance, 100 converts a printed percentage.
STRUCTURAL_INTS = {0, 1, 2, 100}
NUMBER_IN_TEXT = re.compile(r"\d{1,3}(?:,\d{3})+|\d+\.\d+|\d{3,}")


def _docstring_ids(tree: ast.AST) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def literals(source: str) -> tuple[list, list]:
    """(numeric literals, number-like text in string literals), each as
    (line, value). Docstrings are prose and are skipped."""
    tree = ast.parse(source)
    docs = _docstring_ids(tree)
    nums, texts = [], []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or id(node) in docs or isinstance(node.value, bool):
            continue
        if isinstance(node.value, (int, float, complex)):
            nums.append((node.lineno, node.value))
        elif isinstance(node.value, str):
            texts += [(node.lineno, m) for m in NUMBER_IN_TEXT.findall(node.value)]
    return nums, texts


def test_formatting_code_has_no_numeric_literal_but_budget_thresholds():
    nums, texts = literals(FORMATTING_MODULE.read_text())
    assert [(ln, v) for ln, v in nums if v not in BUDGETS] == []
    assert texts == []


@pytest.mark.parametrize("module", COMMAND_MODULES, ids=lambda p: p.name)
def test_no_command_module_hardcodes_a_number(module):
    nums, texts = literals(module.read_text())
    assert [(ln, v) for ln, v in nums if not (isinstance(v, int) and v in STRUCTURAL_INTS | set(BUDGETS))] == []
    assert texts == []


def test_literal_scan_catches_a_hardcoded_result():
    planted = 'def f(x):\n    """C-index 0.850 here is prose."""\n    return [x, 0.850, "0.116", "178,756", 20260922, 5]\n'
    nums, texts = literals(planted)
    assert [v for _, v in nums if v not in BUDGETS] == [0.850, 20260922]
    assert [t for _, t in texts] == ["0.116", "178,756"]


# --- the record and its output -----------------------------------------------------


@pytest.fixture(scope="module")
def rec() -> dict:
    return load()


def test_check_passes_on_the_committed_record():
    assert check.run_check() == []


def test_record_is_the_corrected_labels_record(rec):
    prov = rec["provenance"]
    assert rec["labels"] == prov["labels"] == "corrected"
    assert re.fullmatch(r"[0-9a-f]{40}", prov["git_commit"])
    doc = (ROOT / "docs" / "results_corrected_labels.md").read_text()
    assert prov["git_commit"] in doc  # the doc was generated from this record


def _text(blocks) -> str:
    buf = io.StringIO()
    render.emit(Console(file=buf, width=400, no_color=True), blocks)
    return buf.getvalue()


def test_default_output_has_header_every_section_in_order_and_footer(rec):
    blocks = render.build(rec)
    keys = [b.key for b in blocks if isinstance(b, render.Line)]
    assert keys == ["header", "legend", *[f"section.{s}" for s in render.SECTIONS], "footer"]
    assert list(render.SECTIONS) == ["headline", "models", "budget", "rolling", "blindspot", "negatives", "fuzzy",
                                     "sensitivity"]
    out = _text(blocks)
    pop, prov = rec["population"], rec["provenance"]
    head = out.splitlines()[0]
    for s in [*pop["publication_window"], pop["observation_cutoff"], f"{pop['n_rows']:,}", f"{pop['n_events']:,}",
              f"{pop['n_event_cves']:,}"]:
        assert s in head
    assert out.rstrip().splitlines()[-1].startswith("Source: corrected-labels record")
    assert prov["git_commit"] in out.rstrip().splitlines()[-1]


def test_sections_are_selectable_and_keep_their_order(rec):
    blocks = render.build(rec, ["sensitivity", "headline"])
    assert [b.key for b in blocks if isinstance(b, render.Line)] == [
        "header", "legend", "section.headline", "section.sensitivity", "footer"]
    assert {b.key for b in blocks if isinstance(b, render.Table)} == {"headline", "sensitivity"}
    with pytest.raises(ValueError, match="unknown section"):
        render.build(rec, ["nope"])


def test_mark_requires_the_interval_to_exclude_zero_strictly():
    for d, marked in [(Diff(0.1, 0.0, 0.2), False), (Diff(-0.1, -0.2, 0.0), False), (Diff(0.1, -0.01, 0.2), False),
                      (Diff(0.1, 1e-12, 0.2), True), (Diff(-0.1, -0.2, -1e-12), True)]:
        assert d.significant is marked
        assert (render.MARK in render.dif(d)) is marked
    assert Diff(0.1, 0.0, 0.2).verdict().startswith("not supported")
    assert Diff(0.1, 0.01, 0.2).verdict() == "supported"
    assert Diff(-0.1, -0.2, -0.01).verdict().startswith("contradicted")


def test_a_bound_of_exactly_zero_in_the_record_prints_unmarked(rec, tmp_path):
    r = json.loads(json.dumps(rec))
    d = r["headline"]["paired_vs_epss"]["Cox"]["cindex"]
    d["ci_lower"] = 0.0
    p = tmp_path / "rec.json"
    p.write_text(json.dumps(r))
    row = next(b for b in render.build(load(p), ["headline"]) if isinstance(b, render.Table)).rows[0]
    assert row[0] == "C-index" and render.MARK not in row[-1] and "+0.000" in row[-1]
    assert check.run_check(p, ["headline"]) == []


# --- --check catches disagreement ---------------------------------------------------


def test_check_catches_a_printed_value_that_does_not_match_the_file(rec, tmp_path, monkeypatch):
    """The check re-reads the file: a value printed from a stale or altered
    in-memory record is caught."""
    p = tmp_path / "copy.json"
    p.write_text(json.dumps(rec))
    real_load = check.load

    def stale_load(path):
        r = real_load(path)
        r["budget_equivalence"]["effort_ratio_10pct"]["point"] += 0.1
        return r

    monkeypatch.setattr(check, "load", stale_load)
    problems = check.run_check(p)
    assert len(problems) == 1 and problems[0].startswith("budget / 10% / Effort ratio")


@pytest.mark.parametrize("bug, where", [
    # every paired difference marked, significant or not
    (lambda m: m.setattr(render, "dif", lambda d: f"{d.point:+.3f} ({d.lo:+.3f}, {d.hi:+.3f}) ✓"), "wrongly shown"),
    # a row silently dropped
    (lambda m: m.setattr(render, "SUBSETS", render.SUBSETS[:-1]), "expected but not printed"),
    # each metric printed under the other's label
    (lambda m: m.setattr(render, "NEGATIVE_METRICS", [("ΔC-index", "recall_10pct"), ("ΔRecall@10%", "cindex")]),
     "does not round"),
    # an interval bound printed in the wrong slot
    (lambda m: m.setattr(render, "ratio", lambda e: f"{e.point:.2f}× ({e.hi:.2f}–{e.lo:.2f}×)"), "does not round"),
])
def test_check_catches_formatting_bugs(monkeypatch, bug, where):
    bug(monkeypatch)
    problems = check.run_check()
    assert problems and any(where in p for p in problems), problems


def test_check_catches_swapped_columns(rec, monkeypatch):
    real = render.headline
    n_rows = len(real(rec)[0].rows)

    def swapped(r):
        t = real(r)[0]
        t.rows = [[row[0], row[2], row[1], row[3]] for row in t.rows]  # Cox and EPSS columns swapped
        return [t]

    monkeypatch.setitem(render.SECTIONS, "headline", swapped)
    problems = check.run_check(sections=["headline"])
    assert len(problems) == 2 * n_rows and all(p.startswith("headline / ") for p in problems), problems


# --- the command: no database, no network, fast --------------------------------------


def test_cli_prints_selected_section_and_check_exits_zero():
    runner = CliRunner()
    out = runner.invoke(app, ["results", "--section", "budget"])
    assert out.exit_code == 0, out.output
    assert "Budget equivalence" in out.output and "Rolling origin" not in out.output
    assert runner.invoke(app, ["results", "--check"]).exit_code == 0
    bad = runner.invoke(app, ["results", "--section", "nope"])
    assert bad.exit_code != 0


def test_runs_without_database_network_or_heavy_imports():
    """A fresh interpreter with sockets disabled and no DB settings: the
    command still prints, and never imports the DB, config or data stack."""
    code = (
        "import socket, sys\n"
        "def refuse(*a, **k): raise OSError('network disabled in this test')\n"
        "socket.socket.connect = refuse; socket.create_connection = refuse\n"
        "from scripts.results.cli import main\n"
        "main()\n"
        "main(check=True)\n"
        "heavy = [m for m in ('sqlalchemy', 'psycopg', 'pandas', 'numpy', 'httpx', 'database.engine',\n"
        "                     'config.config_schema') if m in sys.modules]\n"
        "assert not heavy, heavy\n"
    )
    env = {"PATH": "", "HOME": str(ROOT), "PYTHONPATH": str(ROOT)}
    proc = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True,
                          timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr
    assert "Source: corrected-labels record" in proc.stdout
    assert "every printed value matches" in proc.stdout


def test_renders_in_well_under_a_second():
    start = time.perf_counter()
    blocks = render.build(load(RECORD_PATH))
    _text(blocks)
    assert time.perf_counter() - start < 1
