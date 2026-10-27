"""
`vsp results --check`: verifies that everything `vsp results` prints agrees
with the record it claims to come from.

Renders the selected sections exactly as `vsp results` does, then re-reads
the record file and checks every printed value against it, through a
mapping written here independently of render.py (display label -> JSON
path). It checks:

- every table cell has an expected source, and every expected cell was
  printed (no silent extra or missing value);
- every number in a cell rounds, at the precision printed, from the
  record's value (percentages scaled), and in the right slot (point,
  interval bounds);
- each ✓ is present exactly when the interval excludes zero strictly, and
  each verdict follows from the interval;
- the header, legend and footer state the record's own population,
  interval settings, file and commit;
- each cell's text appears in the console output.

Returns a list of problems; empty means the output matches the record.
"""

from __future__ import annotations

import io
import json
import re
from decimal import Decimal
from itertools import chain
from pathlib import Path

from rich.console import Console

from scripts.results.record import RECORD_DOC, RECORD_PATH, RECORD_RELPATH, load
from scripts.results.render import Line, Table, build, emit

MARK = "✓"
NUM = r"([+-]?[\d,]+(?:\.\d+)?%?)"
SHAPES = {  # kind -> (pattern, JSON keys of the slots it fills)
    "est": (rf"{NUM} \({NUM}–{NUM}\)", ("point", "ci_lower", "ci_upper")),
    "ratio": (rf"{NUM}× \({NUM}–{NUM}×\)", ("point", "ci_lower", "ci_upper")),
    "days": (rf"{NUM} days \({NUM}–{NUM}\)", ("point", "ci_lower", "ci_upper")),
    "diff": (rf"{NUM} \({NUM}, {NUM}\)(?: {MARK})?", ("point_diff", "ci_lower", "ci_upper")),
    "int": (NUM, (None,)),
}
NA = "— (by definition)"
VERDICTS = {"spans": "not supported: interval spans zero", "above": "supported",
            "below": "contradicted: significantly worse"}


def _close(printed: str, source) -> bool:
    """Does `printed` (as displayed) round from `source`?"""
    pct = printed.endswith("%")
    p = Decimal(printed.rstrip("%").replace(",", ""))
    s = Decimal(source) * (100 if pct else 1)
    places = -p.as_tuple().exponent
    return abs(p - s) <= Decimal(1).scaleb(-places) / 2


def _node(rec: dict, path: tuple):
    for k in path:
        rec = rec[k]
    return rec


def expectations(rec: dict) -> dict:
    """(table key, row label, column header) -> (kind, JSON path) for every
    cell `vsp results` should print. Written from the record's layout, not
    from render.py."""
    E: dict = {}
    budgets = ["1pct", "5pct", "10pct"]
    metric_cols = ["C-index", "Recall@1%", "Recall@5%", "Recall@10%"]
    metric_paths = [("cindex",)] + [("recall_at_budget", b) for b in budgets]
    diff_keys = ["cindex"] + [f"recall_{b}" for b in budgets]
    blind = "Blind-spot catch @10%"

    for col, mp, dk in zip(metric_cols, metric_paths, diff_keys):
        E["headline", col, "Cox"] = ("est", ("headline", "metrics", "Cox", *mp))
        E["headline", col, "EPSS alone"] = ("est", ("headline", "metrics", "EPSS-alone", *mp))
        E["headline", col, "Δ Cox − EPSS"] = ("diff", ("headline", "paired_vs_epss", "Cox", dk))
        for m in ["Cox", "RSF", "XGBoost-AFT", "EPSS-alone"]:
            E["models.rankings", m, col] = ("est", ("headline", "metrics", m, *mp))
            if m != "EPSS-alone":
                E["models.paired", m, f"Δ{col}"] = ("diff", ("headline", "paired_vs_epss", m, dk))
        for m in ["Fuzzy", "Cox", "Linear blend", "EPSS"]:
            E["fuzzy.rankings", m, col] = ("est", ("fuzzy", "metrics", m, *mp))
            if m != "Fuzzy":
                E["fuzzy.paired", m, f"Δ{col}"] = ("diff", ("fuzzy", "paired_fuzzy_minus_reference", m, dk))
    for m in ["Cox", "RSF", "XGBoost-AFT"]:
        E["models.rankings", m, blind] = ("est", ("headline", "blind_spot_catch_rate_10pct", m))
    E["models.rankings", "EPSS-alone", blind] = ("text", NA)
    for m in ["Fuzzy", "Cox", "Linear blend"]:
        E["fuzzy.rankings", m, blind] = ("est", ("fuzzy", "blind_spot_catch_rate_10pct", "per_model", m))
    E["fuzzy.rankings", "EPSS", blind] = ("text", NA)
    for m in ["Cox", "Linear blend"]:
        E["fuzzy.paired", m, f"Δ{blind}"] = ("diff", ("fuzzy", "blind_spot_catch_rate_10pct", f"paired_fuzzy_minus_{m}"))
    E["fuzzy.paired", "EPSS", f"Δ{blind}"] = ("text", NA)

    for b in budgets:
        row = b.replace("pct", "%")
        E["budget", row, "Cox recall"] = ("est", ("budget_equivalence", f"cox_recall_{b}"))
        E["budget", row, "EPSS recall, same budget"] = ("est", ("budget_equivalence", f"epss_recall_{b}"))
        E["budget", row, "EPSS budget to match Cox"] = ("est", ("budget_equivalence", f"epss_budget_to_match_{b}"))
        E["budget", row, "Effort ratio (EPSS ÷ Cox)"] = ("ratio", ("budget_equivalence", f"effort_ratio_{b}"))

    for cutoff, fold in rec["rolling_origin"].items():
        start, end = fold["test_window"]
        E["rolling", cutoff, "Test window"] = ("text", f"[{start}, {end})")
        E["rolling", cutoff, "Test events (CVEs)"] = ("events", ("rolling_origin", cutoff, "test"))
        E["rolling", cutoff, "Cox C-index"] = ("est", ("rolling_origin", cutoff, "Cox", "cindex"))
        E["rolling", cutoff, "EPSS C-index"] = ("est", ("rolling_origin", cutoff, "EPSS-alone", "cindex"))
        E["rolling", cutoff, "ΔC-index"] = ("diff", ("rolling_origin", cutoff, "paired_cox_minus_epss", "cindex"))
        E["rolling", cutoff, "ΔRecall@10%"] = ("diff", ("rolling_origin", cutoff, "paired_cox_minus_epss", "recall_10pct"))

    stats = ("lead_time", "stats")
    for row, key in [("Both Cox and EPSS", "n_both"), ("Cox only", "n_cox_only"), ("EPSS only", "n_epss_only"),
                     ("Neither", "n_neither")]:
        E["blindspot.catch", row, "Listed CVEs"] = ("est", (*stats, key))
    E["blindspot.catch", "All KEV-listed test CVEs", "Listed CVEs"] = ("int", ("lead_time", "n_listed_cves"))
    for row, kind, key in [("EPSS blind spots", "est", "blind_n"), ("Blind spots Cox recovers", "est", "blind_cox_caught"),
                           ("Recovery rate", "est", "blind_cox_catch_rate"),
                           ("Median lead before listing, recovered blind spots", "days", "blind_cox_lead_median"),
                           ("Median Cox lead over EPSS, where both flag", "days", "both_median")]:
        E["blindspot.lead", row, "Value"] = (kind, (*stats, key))

    level = f"Δ ({rec['provenance']['ci_level'] * 100:.0f}% interval)"
    for claim, path, contrast in [
        ("H1: EPSS trajectory features improve Cox", ("cox_trajectory_ablation", "paired_a_minus_b"),
         "full − no trajectory"),
        ("H1: EPSS trajectory features improve XGBoost-AFT", ("xgb_trajectory_ablation", "paired_a_minus_b"),
         "full − no trajectory"),
        ("RQ4: the fuzzy layer ranks better than Cox", ("fuzzy", "paired_fuzzy_minus_reference", "Cox"),
         "fuzzy − Cox"),
        ("RQ4: the fuzzy layer ranks better than a linear blend",
         ("fuzzy", "paired_fuzzy_minus_reference", "Linear blend"), "fuzzy − linear blend"),
        ("EPSS-removal ablation: EPSS features improve Cox", ("cox_trajectory_ablation", "paired_a_minus_c"),
         "full − no EPSS"),
    ]:
        for metric, key in [("ΔC-index", "cindex"), ("ΔRecall@10%", "recall_10pct")]:
            row = (claim, f"{metric} ({contrast})")  # negatives rows are keyed by claim + metric
            E["negatives", row, level] = ("diff", (*path, key))
            E["negatives", row, "Verdict"] = ("verdict", (*path, key))

    for key, row in [("baseline", "Default test set"), ("a_with_transition_rows", "+ EPSS version-transition rows"),
                     ("b_excluding_vulncheck_cna", "− VulnCheck-CNA CVEs"),
                     ("c_cna_cvss_present", "CNA CVSS score present only")]:
        E["sensitivity", row, "Rows"] = ("int", ("sensitivity", key, "n_rows"))
        E["sensitivity", row, "Events"] = ("int", ("sensitivity", key, "n_events"))
        E["sensitivity", row, "Cox C-index"] = ("est", ("sensitivity", key, "Cox", "cindex"))
        E["sensitivity", row, "ΔC-index vs EPSS"] = ("diff", ("sensitivity", key, "paired_cox_minus_epss", "cindex"))
        E["sensitivity", row, "ΔRecall@10% vs EPSS"] = (
            "diff", ("sensitivity", key, "paired_cox_minus_epss", "recall_10pct"))
    return E


def _verify_cell(cell: str, kind: str, src, rec: dict) -> str | None:
    if kind == "text":
        return None if cell == src else f"expected {src!r}"
    node = _node(rec, src)
    if kind == "verdict":
        lo, hi = node["ci_lower"], node["ci_upper"]
        want = VERDICTS["above" if lo > 0 else "below" if hi < 0 else "spans"]
        return None if cell == want else f"verdict should be {want!r} (interval {lo}, {hi})"
    if kind == "events":
        m = re.fullmatch(rf"{NUM} \({NUM}\)", cell)
        if not m:
            return "not 'events (CVEs)'"
        ok = _close(m[1], node["n_events"]) and _close(m[2], node["n_event_cves"])
        return None if ok else f"record has {node['n_events']} ({node['n_event_cves']})"
    pattern, slots = SHAPES[kind]
    m = re.fullmatch(pattern, cell)
    if not m:
        return f"does not have the shape of a {kind}"
    for printed, slot in zip(m.groups(), slots):
        value = node if slot is None else node[slot]
        if not _close(printed, value):
            return f"{printed} does not round from the record's {slot or 'value'} {value}"
    if kind == "diff":
        excludes = node["ci_lower"] > 0 or node["ci_upper"] < 0
        if (MARK in cell) != excludes:
            return f"{MARK} {'missing' if excludes else 'wrongly shown'}: interval ({node['ci_lower']}, {node['ci_upper']})"
    return None


def _verify_line(line: Line, rec: dict) -> list[str]:
    pop, prov = rec["population"], rec["provenance"]
    if line.key == "header":
        m = re.search(rf"published (\S+) to (\S+) · labels observed to (\S+) · {NUM} landmark rows · {NUM} KEV "
                      rf"events · {NUM} distinct KEV-listed CVEs", line.text)
        if not m:
            return ["header: unrecognised"]
        start, end, cutoff, *counts = m.groups()
        want = [*pop["publication_window"], pop["observation_cutoff"]]
        bad = [f"header: {a} != {b}" for a, b in zip([start, end, cutoff], want) if a != b]
        bad += [f"header: {p} != {pop[k]}" for p, k in zip(counts, ["n_rows", "n_events", "n_event_cves"])
                if not _close(p, pop[k])]
        return bad
    if line.key == "legend":
        m = re.search(rf"{NUM} interval excludes zero .* Intervals: {NUM} whole-CVE bootstrap resamples, seed {NUM}\.",
                      line.text)
        if not m:
            return ["legend: unrecognised"]
        level, resamples, seed = m.groups()
        ok = _close(level, prov["ci_level"]) and _close(resamples, prov["n_resamples"]) and _close(seed, prov["seed"])
        return [] if ok else ["legend: interval level, resamples or seed differ from the record"]
    if line.key == "footer":
        want = (f"record {RECORD_RELPATH} ({RECORD_DOC}), generated at commit {prov['git_commit']} "
                f"({prov['generated_at_utc']})")
        return [] if want in line.text else [f"footer does not name {want!r}"]
    return []


def run_check(path: Path = RECORD_PATH, sections: list[str] | None = None) -> list[str]:
    blocks = build(load(path), sections)
    width = sum(len(b.text) if isinstance(b, Line) else sum(map(len, chain(b.columns, *b.rows)))
                for b in blocks)  # wide enough that nothing wraps
    buf = io.StringIO()
    emit(Console(file=buf, width=width, no_color=True, highlight=False, emoji=False), blocks)
    printed = buf.getvalue()

    rec = json.loads(Path(path).read_text())  # re-read: check against the file, not the rendered object
    expected = expectations(rec)
    problems, seen = [], set()
    for b in blocks:
        if isinstance(b, Line):
            problems += _verify_line(b, rec)
            continue
        for row in b.rows:
            label = (row[0], row[1]) if b.key == "negatives" else row[0]
            cells = row[2:] if b.key == "negatives" else row[1:]
            cols = b.columns[2:] if b.key == "negatives" else b.columns[1:]
            for col, cell in zip(cols, cells):
                key = (b.key, label, col)
                where = f"{b.key} / {label} / {col}: {cell!r}"
                if key not in expected:
                    problems.append(f"{where}: printed but has no expected source")
                    continue
                seen.add(key)
                err = _verify_cell(cell, *expected[key], rec)
                if err:
                    problems.append(f"{where}: {err}")
                if cell not in printed:
                    problems.append(f"{where}: not in the printed output")
    printed_tables = {b.key for b in blocks if isinstance(b, Table)}
    problems += [f"{k[0]} / {k[1]} / {k[2]}: expected but not printed" for k in expected
                 if k[0] in printed_tables and k not in seen]
    tables_of = {"headline": ["headline"], "models": ["models.rankings", "models.paired"], "budget": ["budget"],
                 "rolling": ["rolling"], "blindspot": ["blindspot.catch", "blindspot.lead"],
                 "negatives": ["negatives"], "fuzzy": ["fuzzy.rankings", "fuzzy.paired"],
                 "sensitivity": ["sensitivity"]}
    for name in sections or tables_of:
        problems += [f"section {name}: table {t} not printed" for t in tables_of[name] if t not in printed_tables]
    return problems
