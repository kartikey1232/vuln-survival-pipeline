"""
Formats the corrected-labels record as terminal tables (`vsp results`).

Formatting only: every value is read from the record through
scripts/results/record.py. This module contains no numeric literal except
the budget thresholds (tests/test_results/test_results_command.py enforces
it); precision lives in format specs.

build() returns plain blocks (lines and tables of strings) so that
`vsp results --check` (scripts/results/check.py) can verify exactly what is
printed; emit() turns them into rich output.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from rich import box
from rich.console import Console
from rich.table import Table as RichTable
from rich.text import Text

from scripts.results.record import (
    BUDGETS,
    RECORD_DOC,
    RECORD_RELPATH,
    Diff,
    Estimate,
    diff,
    estimate,
    get,
)

MARK = "✓"
NOT_APPLICABLE = "— (by definition)"
ACCENT = "cyan"


@dataclass
class Line:
    key: str
    text: str
    style: str = ""


@dataclass
class Table:
    key: str
    title: str
    columns: list[str]
    rows: list[list[str]] = field(default_factory=list)
    caption: str = ""


# --- value formats ---------------------------------------------------------------


def est(e: Estimate, spec: str = ".3f") -> str:
    return f"{e.point:{spec}} ({e.lo:{spec}}–{e.hi:{spec}})"


def pct(e: Estimate) -> str:
    return est(e, ".1%")


def count(e: Estimate) -> str:
    return est(e, ",.0f")


def ratio(e: Estimate) -> str:
    return f"{e.point:.2f}× ({e.lo:.2f}–{e.hi:.2f}×)"


def days(e: Estimate) -> str:
    return f"{e.point:.0f} days ({e.lo:.0f}–{e.hi:.0f})"


def dif(d: Diff) -> str:
    text = f"{d.point:+.3f} ({d.lo:+.3f}, {d.hi:+.3f})"
    return f"{text} {MARK}" if d.significant else text


def recall_key(b: int) -> str:
    return f"{b}pct"


RECALL_LABELS = [f"Recall@{b}%" for b in BUDGETS]
METRICS = [("C-index", ("cindex",), "cindex")] + [
    (label, ("recall_at_budget", recall_key(b)), f"recall_{recall_key(b)}") for label, b in zip(RECALL_LABELS, BUDGETS)
]
BLIND_SPOT = "Blind-spot catch @10%"


# --- header / footer ---------------------------------------------------------------


def header(rec: dict) -> list[Line]:
    pop, prov = get(rec, "population"), get(rec, "provenance")
    start, end = pop["publication_window"]
    test_set = (f"Test set: CVEs published {start} to {end} · labels observed to {pop['observation_cutoff']} · "
                f"{pop['n_rows']:,} landmark rows · {pop['n_events']:,} KEV events · "
                f"{pop['n_event_cves']:,} distinct KEV-listed CVEs")
    legend = (f"{MARK} = paired difference whose {prov['ci_level']:.0%} interval excludes zero "
              f"(a bound of exactly zero does not count). Intervals: {prov['n_resamples']:,} whole-CVE "
              f"bootstrap resamples, seed {prov['seed']}.")
    return [Line("header", test_set, "bold"), Line("legend", legend, "dim")]


def footer(rec: dict) -> Line:
    prov = get(rec, "provenance")
    return Line("footer", f"Source: corrected-labels record {RECORD_RELPATH} ({RECORD_DOC}), "
                          f"generated at commit {prov['git_commit']} ({prov['generated_at_utc']})", "dim")


# --- sections ----------------------------------------------------------------------


def headline(rec: dict) -> list:
    t = Table("headline", "Cox vs EPSS alone", ["Metric", "Cox", "EPSS alone", "Δ Cox − EPSS"])
    for label, path, dkey in METRICS:
        t.rows.append([label, est(estimate(rec, "headline", "metrics", "Cox", *path)),
                       est(estimate(rec, "headline", "metrics", "EPSS-alone", *path)),
                       dif(diff(rec, "headline", "paired_vs_epss", "Cox", dkey))])
    return [t]


MODELS = ["Cox", "RSF", "XGBoost-AFT", "EPSS-alone"]


def models(rec: dict) -> list:
    t = Table("models.rankings", "All four rankings", ["Ranking", *[m for m, _, _ in METRICS], BLIND_SPOT],
              caption="Blind-spot catch: share of KEV events outside EPSS's top 10% that the ranking puts in "
                      "its own top 10%.")
    for m in MODELS:
        cells = [est(estimate(rec, "headline", "metrics", m, *path)) for _, path, _ in METRICS]
        blind = (NOT_APPLICABLE if m == "EPSS-alone"
                 else est(estimate(rec, "headline", "blind_spot_catch_rate_10pct", m)))
        t.rows.append([m, *cells, blind])
    p = Table("models.paired", "Paired difference vs EPSS alone", ["Model", *[f"Δ{m}" for m, _, _ in METRICS]])
    for m in MODELS:
        if m != "EPSS-alone":
            p.rows.append([m, *[dif(diff(rec, "headline", "paired_vs_epss", m, dkey)) for _, _, dkey in METRICS]])
    return [t, p]


def budget(rec: dict) -> list:
    t = Table("budget", "Budget equivalence: the EPSS-alone alert budget needed to match Cox's recall",
              ["Cox budget", "Cox recall", "EPSS recall, same budget", "EPSS budget to match Cox",
               "Effort ratio (EPSS ÷ Cox)"])
    for b in BUDGETS:
        k = recall_key(b)
        t.rows.append([f"{b}%", est(estimate(rec, "budget_equivalence", f"cox_recall_{k}")),
                       est(estimate(rec, "budget_equivalence", f"epss_recall_{k}")),
                       pct(estimate(rec, "budget_equivalence", f"epss_budget_to_match_{k}")),
                       ratio(estimate(rec, "budget_equivalence", f"effort_ratio_{k}"))])
    return [t]


def rolling(rec: dict) -> list:
    t = Table("rolling", "Rolling origin: Cox refit at each cutoff, tested on the next window",
              ["Train cutoff", "Test window", "Test events (CVEs)", "Cox C-index", "EPSS C-index", "ΔC-index",
               "ΔRecall@10%"],
              caption="Test window is half-open: published on or after its start and before its end.")
    for cutoff, fold in get(rec, "rolling_origin").items():
        start, end = fold["test_window"]
        t.rows.append([cutoff, f"[{start}, {end})", f"{fold['test']['n_events']:,} ({fold['test']['n_event_cves']:,})",
                       est(estimate(rec, "rolling_origin", cutoff, "Cox", "cindex")),
                       est(estimate(rec, "rolling_origin", cutoff, "EPSS-alone", "cindex")),
                       dif(diff(rec, "rolling_origin", cutoff, "paired_cox_minus_epss", "cindex")),
                       dif(diff(rec, "rolling_origin", cutoff, "paired_cox_minus_epss", "recall_10pct"))])
    return [t]


def blindspot(rec: dict) -> list:
    def s(key):
        return estimate(rec, "lead_time", "stats", key)

    c = Table("blindspot.catch", "Who flags the KEV-listed test CVEs", ["Flagged by", "Listed CVEs"],
              caption="Flagged: in the top 10% of a landmark's rows.")
    for label, key in [("Both Cox and EPSS", "n_both"), ("Cox only", "n_cox_only"), ("EPSS only", "n_epss_only"),
                       ("Neither", "n_neither")]:
        c.rows.append([label, count(s(key))])
    c.rows.append(["All KEV-listed test CVEs", f"{get(rec, 'lead_time', 'n_listed_cves'):,}"])
    lead = Table("blindspot.lead", "Blind spots and lead time", ["Measure", "Value"],
                 caption="Blind spot: a listed CVE that EPSS never flags.\nLead: days from first flag to KEV listing.")
    lead.rows += [
        ["EPSS blind spots", count(s("blind_n"))],
        ["Blind spots Cox recovers", count(s("blind_cox_caught"))],
        ["Recovery rate", pct(s("blind_cox_catch_rate"))],
        ["Median lead before listing, recovered blind spots", days(s("blind_cox_lead_median"))],
        ["Median Cox lead over EPSS, where both flag", days(s("both_median"))],
    ]
    return [c, lead]


NEGATIVE_CLAIMS = [
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
]
NEGATIVE_METRICS = [("ΔC-index", "cindex"), ("ΔRecall@10%", "recall_10pct")]


def negatives(rec: dict) -> list:
    level = get(rec, "provenance", "ci_level")
    t = Table("negatives", "Negative results", ["Claim", "Metric", f"Δ ({level:.0%} interval)", "Verdict"])
    for claim, path, contrast in NEGATIVE_CLAIMS:
        for label, key in NEGATIVE_METRICS:
            d = diff(rec, *path, key)
            t.rows.append([claim, f"{label} ({contrast})", dif(d), d.verdict()])
    return [t]


FUZZY_RANKINGS = ["Fuzzy", "Cox", "Linear blend", "EPSS"]


def fuzzy(rec: dict) -> list:
    t = Table("fuzzy.rankings", "Fuzzy layer against Cox, the linear blend and EPSS",
              ["Ranking", *[m for m, _, _ in METRICS], BLIND_SPOT])
    for m in FUZZY_RANKINGS:
        cells = [est(estimate(rec, "fuzzy", "metrics", m, *path)) for _, path, _ in METRICS]
        blind = (NOT_APPLICABLE if m == "EPSS"
                 else est(estimate(rec, "fuzzy", "blind_spot_catch_rate_10pct", "per_model", m)))
        t.rows.append([m, *cells, blind])
    p = Table("fuzzy.paired", "Paired difference: fuzzy minus each reference",
              ["Fuzzy minus", *[f"Δ{m}" for m, _, _ in METRICS], f"Δ{BLIND_SPOT}"])
    for m in FUZZY_RANKINGS:
        if m == "Fuzzy":
            continue
        cells = [dif(diff(rec, "fuzzy", "paired_fuzzy_minus_reference", m, dkey)) for _, _, dkey in METRICS]
        blind = (NOT_APPLICABLE if m == "EPSS"
                 else dif(diff(rec, "fuzzy", "blind_spot_catch_rate_10pct", f"paired_fuzzy_minus_{m}")))
        p.rows.append([m, *cells, blind])
    return [t, p]


SUBSETS = [
    ("baseline", "Default test set"),
    ("a_with_transition_rows", "+ EPSS version-transition rows"),
    ("b_excluding_vulncheck_cna", "− VulnCheck-CNA CVEs"),
    ("c_cna_cvss_present", "CNA CVSS score present only"),
]


def sensitivity(rec: dict) -> list:
    t = Table("sensitivity", "Sensitivity: Cox vs EPSS alone on four test subsets",
              ["Test subset", "Rows", "Events", "Cox C-index", "ΔC-index vs EPSS", "ΔRecall@10% vs EPSS"])
    for key, label in SUBSETS:
        sub = get(rec, "sensitivity", key)
        t.rows.append([label, f"{sub['n_rows']:,}", f"{sub['n_events']:,}",
                       est(estimate(rec, "sensitivity", key, "Cox", "cindex")),
                       dif(diff(rec, "sensitivity", key, "paired_cox_minus_epss", "cindex")),
                       dif(diff(rec, "sensitivity", key, "paired_cox_minus_epss", "recall_10pct"))])
    return [t]


SECTIONS = {  # printed in this order
    "headline": headline,
    "models": models,
    "budget": budget,
    "rolling": rolling,
    "blindspot": blindspot,
    "negatives": negatives,
    "fuzzy": fuzzy,
    "sensitivity": sensitivity,
}


def build(rec: dict, sections: list[str] | None = None) -> list:
    """Header, then each selected section (all, in order, by default), then
    the provenance footer."""
    names = list(SECTIONS) if not sections else sections
    unknown = [n for n in names if n not in SECTIONS]
    if unknown:
        raise ValueError(f"unknown section(s) {unknown}; choose from {list(SECTIONS)}")
    blocks: list = header(rec)
    for name, fn in SECTIONS.items():  # always in the fixed order
        if name in names:
            blocks.append(Line(f"section.{name}", name, f"bold {ACCENT}"))
            blocks += fn(rec)
    blocks.append(footer(rec))
    return blocks


def emit(console: Console, blocks: list) -> None:
    for b in blocks:
        if isinstance(b, Line):
            if b.key.startswith("section."):
                console.rule(Text(b.text, style=b.style), align="left", style=ACCENT)
            else:
                console.print(Text(b.text, style=b.style))
            continue
        t = RichTable(title=b.title, caption=b.caption or None, box=box.SIMPLE_HEAD, header_style="bold",
                      title_style="bold", title_justify="left", caption_justify="left", caption_style="dim")
        for i, col in enumerate(b.columns):
            t.add_column(col, justify="right" if i else "left", no_wrap=bool(i))
        for row in b.rows:
            cells = []
            for cell in row:
                text = Text(cell)
                text.highlight_words([MARK], style="bold green")
                cells.append(text)
            t.add_row(*cells)
        console.print(t)
