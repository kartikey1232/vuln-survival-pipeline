"""
Fuzzy ranking layer: Mamdani min-max inference with centroid
defuzzification (scikit-fuzzy's control module) over four inputs, giving a
0-100 'priority' plus each rule's firing strength per row (what the
dashboard shows as the explanation).

Inputs (all from data/training/cox_risk_pct.parquet, see risk_percentile.py):
- cox_risk     = cox_risk_pct, frozen Cox's percentile vs. the training
                 reference of its own landmark
- epss         = epss_pct_now
- cvss         = CNA-supplied CVSS base score; plus a crisp cvss_missing
                 input. Every rule that mentions cvss also requires
                 cvss_missing=no, so a missing score can never fire a
                 severity rule (in either direction), and missing rows get
                 their own rule (R16) in place of the VeryLow rule (R06):
                 unknown severity is neither cut nor boosted.
- blindspot    = cox_risk - epss. Its zero point does NOT mean agreement:
                 the two percentiles use different reference populations
                 (training landmark rows vs. every CVE EPSS scores that day),
                 so the median validation blindspot is about +0.24. Its sets
                 are anchored on validation quantiles like the others.

Membership cut-offs come from VALIDATION quantiles (`fit_cutoffs`) and are
frozen into models/fuzzy_config.json by scripts/fuzzy/design.py. This module
only turns a config into a scorer; it never looks at labels.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import skfuzzy as fuzz
from skfuzzy import control as ctrl

# Validation quantiles anchoring the four sets of cox_risk and epss. Spacing
# narrows towards the top (30 -> 25 -> 10 quantile points between adjacent
# set peaks), where the patching budget is spent.
LEVEL_QUANTILES = (0.30, 0.60, 0.85, 0.95)
BLINDSPOT_QUANTILES = (0.10, 0.50, 0.90)
# Standard CVSS severity bands. Ramps are 0.1 wide, below each boundary, so
# every real (one-decimal) score belongs fully to exactly its NVD band:
# 3.9 Low, 4.0 Medium, 6.9 Medium, 7.0 High, 8.9 High, 9.0 Critical.
CVSS_BANDS = {
    "Low": [0.0, 0.0, 3.9, 4.0],
    "Medium": [3.9, 4.0, 6.9, 7.0],
    "High": [6.9, 7.0, 8.9, 9.0],
    "Critical": [8.9, 9.0, 10.0, 10.0],
}
PRIORITY_SETS = {
    "VeryLow": ("trap", [0, 0, 10, 30]),
    "Low": ("tri", [10, 30, 50]),
    "Medium": ("tri", [30, 50, 70]),
    "High": ("tri", [50, 70, 90]),
    "Critical": ("trap", [70, 90, 100, 100]),
}

# (id, text, antecedent builder, consequent term). `v` is the dict of
# skfuzzy variables built in `build_system`; every cvss rule also requires
# cvss_missing = no.
#
# Monotonicity in cox_risk. Centroid defuzzification with max aggregation
# is not monotone just because the rules are; the grid tests found three
# ways this rule base broke it, each fixed here:
# 1. Two rules on adjacent cox_risk levels (High, VeryHigh) with the same
#    consequent: its activation is max(fading, rising), which dips to 0.5
#    where they cross. Rules meaning "this level or above" use the
#    cumulative terms AtLeastMedium / AtLeastHigh (exactly the sum of the
#    sets at and above that level), which never fall as cox_risk rises.
# 2. A backbone High rule that fades as cox_risk reaches VeryHigh, while
#    Critical is already held up by an EPSS-capped rule (R04/R11): mass
#    leaves High without Critical rising.
# 3. High still rising after an EPSS-capped Critical rule has hit its cap,
#    with the centroid already above High's peak (70). So R09 fires from
#    cox_risk Medium upward, and High saturates before any capped Critical
#    rule (all on AtLeastHigh) starts to rise.
# Within each cox_risk ramp, mass then only moves up the priority scale.
# Rules whose firing falls as cox_risk rises have a bottom consequent
# (R06, R07) or are bounded by a rule with the same consequent.
RULES = [
    ("R01", "IF cox_risk is VeryHigh THEN priority is Critical",
     lambda v: v["cox_risk"]["VeryHigh"], "Critical"),
    ("R02", "IF cox_risk is High AND epss is Low THEN priority is High",
     lambda v: v["cox_risk"]["High"] & v["epss"]["Low"], "High"),
    ("R03", "IF blindspot is ModelHigher AND cvss is Critical THEN priority is Critical",
     lambda v: v["blindspot"]["ModelHigher"] & v["cvss"]["Critical"] & v["cvss_missing"]["no"], "Critical"),
    ("R04", "IF cox_risk is High or above AND epss is High THEN priority is Critical",
     lambda v: v["cox_risk"]["AtLeastHigh"] & v["epss"]["High"], "Critical"),
    ("R05", "IF cox_risk is Medium or above AND cvss is Critical THEN priority is High",
     lambda v: v["cox_risk"]["AtLeastMedium"] & v["cvss"]["Critical"] & v["cvss_missing"]["no"], "High"),
    ("R06", "IF cox_risk is Low AND epss is Low AND cvss is not Critical THEN priority is VeryLow",
     lambda v: v["cox_risk"]["Low"] & v["epss"]["Low"] & ~v["cvss"]["Critical"] & v["cvss_missing"]["no"], "VeryLow"),
    ("R07", "IF cox_risk is Low THEN priority is Low",
     lambda v: v["cox_risk"]["Low"], "Low"),
    ("R08", "IF cox_risk is Medium THEN priority is Medium",
     lambda v: v["cox_risk"]["Medium"], "Medium"),
    ("R09", "IF cox_risk is Medium or above THEN priority is High",
     lambda v: v["cox_risk"]["AtLeastMedium"], "High"),
    ("R10", "IF epss is VeryHigh THEN priority is High",
     lambda v: v["epss"]["VeryHigh"], "High"),
    ("R11", "IF cox_risk is High or above AND epss is VeryHigh THEN priority is Critical",
     lambda v: v["cox_risk"]["AtLeastHigh"] & v["epss"]["VeryHigh"], "Critical"),
    ("R12", "IF cox_risk is Medium or above AND epss is High THEN priority is High",
     lambda v: v["cox_risk"]["AtLeastMedium"] & v["epss"]["High"], "High"),
    ("R13", "IF epss is High THEN priority is Medium",
     lambda v: v["epss"]["High"], "Medium"),
    ("R14", "IF cox_risk is High or above AND cvss is Critical THEN priority is Critical",
     lambda v: v["cox_risk"]["AtLeastHigh"] & v["cvss"]["Critical"] & v["cvss_missing"]["no"], "Critical"),
    ("R15", "IF blindspot is Agrees AND cox_risk is Medium AND epss is Medium THEN priority is Medium",
     lambda v: v["blindspot"]["Agrees"] & v["cox_risk"]["Medium"] & v["epss"]["Medium"], "Medium"),
    ("R16", "IF cvss is Missing AND cox_risk is Low AND epss is Low THEN priority is Low",
     lambda v: v["cvss_missing"]["yes"] & v["cox_risk"]["Low"] & v["epss"]["Low"], "Low"),
    ("R17", "IF blindspot is EPSSHigher AND cox_risk is Low THEN priority is Low",
     lambda v: v["blindspot"]["EPSSHigher"] & v["cox_risk"]["Low"], "Low"),
]
# Fire only for explanation: each is bounded by a backbone rule with the
# same consequent (R02 <= R09, R15 <= R08, R16 <= R07, R17 <= R07), so under
# max aggregation they never change priority. R02 is the thesis rule; it
# is what the dashboard shows for a row the model ranks above EPSS, but
# its effect on the score is carried by R09.
EXPLANATION_ONLY_RULES = {"R02", "R15", "R16", "R17"}
RULE_IDS = [r[0] for r in RULES]
CVSS_RULES = {"R03", "R05", "R06", "R14"}  # require a CNA score (cvss_missing = no)
MISSING_RULES = {"R16"}


def _strictly_increasing(name: str, points) -> list[float]:
    points = [float(p) for p in points]
    if any(b <= a for a, b in zip(points, points[1:])):
        raise ValueError(f"{name}: validation anchors not strictly increasing: {points}")
    return points


def level_sets(a: float, b: float, c: float, d: float, lo: float = 0.0, hi: float = 1.0) -> dict:
    """Four sets anchored at a < b < c < d, adjacent sets crossing at 0.5,
    memberships summing to 1 everywhere on [lo, hi], plus two cumulative
    terms."""
    return {
        "Low": ("trap", [lo, lo, a, b]),
        "Medium": ("tri", [a, b, c]),
        "High": ("tri", [b, c, d]),
        "VeryHigh": ("trap", [c, d, hi, hi]),
        # Cumulative "this level or above" terms: exactly Medium + High +
        # VeryHigh and High + VeryHigh. See the monotonicity note on RULES.
        "AtLeastMedium": ("trap", [a, b, hi, hi]),
        "AtLeastHigh": ("trap", [b, c, hi, hi]),
    }


def fit_cutoffs(val: pd.DataFrame) -> dict:
    """Membership-function definitions from VALIDATION-row quantiles. Pure
    function of the input distributions — no labels."""
    inputs = model_inputs(val)
    quantiles = {}
    sets = {}
    for name in ("cox_risk", "epss"):
        q = np.quantile(inputs[name], LEVEL_QUANTILES)
        quantiles[name] = dict(zip(map(str, LEVEL_QUANTILES), q.tolist()))
        sets[name] = level_sets(*_strictly_increasing(name, q))
    q_bs = _strictly_increasing("blindspot", np.quantile(inputs["blindspot"], BLINDSPOT_QUANTILES))
    quantiles["blindspot"] = dict(zip(map(str, BLINDSPOT_QUANTILES), q_bs))
    sets["blindspot"] = {
        "EPSSHigher": ("trap", [-1.0, -1.0, q_bs[0], q_bs[1]]),
        "Agrees": ("tri", q_bs),
        "ModelHigher": ("trap", [q_bs[1], q_bs[2], 1.0, 1.0]),
    }
    sets["cvss"] = {k: ("trap", v) for k, v in CVSS_BANDS.items()}
    sets["priority"] = PRIORITY_SETS
    return {"validation_quantiles": quantiles, "membership_functions": sets,
            "rule_weights": {rid: 1.0 for rid in RULE_IDS}}


def model_inputs(df: pd.DataFrame) -> dict[str, np.ndarray]:
    cox = df["cox_risk_pct"].to_numpy(dtype=float)
    epss = df["epss_pct_now"].to_numpy(dtype=float)
    missing = df["cvss_cna_missing"].to_numpy(dtype=bool)
    cvss = df["cvss_base_score"].to_numpy(dtype=float)
    if np.isnan(cvss[~missing]).any() or np.isnan(cox).any() or np.isnan(epss).any():
        raise ValueError("NaN in a fuzzy input that is not a flagged missing CVSS score")
    # The fill value is inert: every cvss rule also requires cvss_missing=no
    # (tests/test_fuzzy/test_fuzzy_layer.py checks this).
    return {"cox_risk": cox, "epss": epss, "cvss": np.where(missing, 0.0, cvss),
            "cvss_missing": missing.astype(float), "blindspot": cox - epss}


def _mf(universe, kind, points):
    return fuzz.trapmf(universe, points) if kind == "trap" else fuzz.trimf(universe, points)


def _universe(lo, hi, n, sets):
    anchors = [p for _, pts in sets.values() for p in pts]
    return np.union1d(np.linspace(lo, hi, n), anchors)


def build_system(config: dict) -> tuple[ctrl.ControlSystem, dict]:
    mfs = config["membership_functions"]
    v = {
        "cox_risk": ctrl.Antecedent(_universe(0, 1, 1001, mfs["cox_risk"]), "cox_risk"),
        "epss": ctrl.Antecedent(_universe(0, 1, 1001, mfs["epss"]), "epss"),
        "cvss": ctrl.Antecedent(_universe(0, 10, 1001, mfs["cvss"]), "cvss"),
        "blindspot": ctrl.Antecedent(_universe(-1, 1, 2001, mfs["blindspot"]), "blindspot"),
        "cvss_missing": ctrl.Antecedent(np.array([0.0, 1.0]), "cvss_missing"),
        "priority": ctrl.Consequent(_universe(0, 100, 1001, mfs["priority"]), "priority", defuzzify_method="centroid"),
    }
    for name in ("cox_risk", "epss", "cvss", "blindspot", "priority"):
        for term, (kind, points) in mfs[name].items():
            v[name][term] = _mf(v[name].universe, kind, points)
    v["cvss_missing"]["no"] = np.array([1.0, 0.0])
    v["cvss_missing"]["yes"] = np.array([0.0, 1.0])

    weights = config["rule_weights"]
    rules = [ctrl.Rule(antecedent(v), v["priority"][term] % weights[rid], label=rid)
             for rid, _, antecedent, term in RULES]
    return ctrl.ControlSystem(rules), v


class _RecordingSimulation(ctrl.ControlSystemSimulation):
    """In array mode skfuzzy clears each rule's aggregate_firing at the end
    of compute(); keep a copy as each rule is evaluated."""

    def compute_rule(self, rule):
        super().compute_rule(rule)
        self.firing[rule.label] = np.array(rule.aggregate_firing[self], dtype=float, copy=True)


def score(inputs: dict[str, np.ndarray], config: dict, *, chunk_size: int = 20000) -> tuple[np.ndarray, pd.DataFrame]:
    """priority (0-100) and a rows x rules DataFrame of firing strengths
    (antecedent degree, before rule weight)."""
    system, _ = build_system(config)
    n = len(inputs["cox_risk"])
    priority = np.empty(n)
    firing = np.empty((n, len(RULE_IDS)))
    for start in range(0, n, chunk_size):
        sl = slice(start, min(start + chunk_size, n))
        sim = _RecordingSimulation(system, cache=False)
        sim.firing = {}
        for name, values in inputs.items():
            sim.input[name] = np.asarray(values[sl], dtype=float)
        sim.compute()
        priority[sl] = sim.output["priority"]
        firing[sl] = np.column_stack([sim.firing[rid] for rid in RULE_IDS])
    return priority, pd.DataFrame(firing, columns=RULE_IDS)


def worst_cox_monotonicity_step(config: dict, *, cox_points: int = 1001, epss_points: int = 101,
                                cvss_cases=((2.0, False), (5.5, False), (8.0, False), (9.5, False), (0.0, True))) -> float:
    """Most negative priority step as cox_risk rises on a dense grid (epss x
    CVSS band x missing held fixed, blindspot derived). >= 0 means monotone
    on that grid. Centroid defuzzification is not monotone by construction,
    so a config has to be checked, not assumed."""
    cox, epss = np.linspace(0, 1, cox_points), np.linspace(0, 1, epss_points)
    e, x = (a.ravel() for a in np.meshgrid(epss, cox, indexing="ij"))
    worst = np.inf
    for cvss, missing in cvss_cases:
        priority, _ = score({"cox_risk": x, "epss": e, "cvss": np.full(len(x), cvss),
                             "cvss_missing": np.full(len(x), float(missing)), "blindspot": x - e}, config)
        worst = min(worst, float(np.diff(priority.reshape(len(epss), len(cox)), axis=1).min()))
    return worst


def ranking_score(priority: np.ndarray, cox_risk: np.ndarray, epss: np.ndarray) -> np.ndarray:
    """Total order for budget-based ranking: priority first, ties broken by
    cox_risk then epss. Centroid output has large tied plateaus (wherever
    every firing set is saturated), including at the top, and recall at a
    budget that cuts through a tie block would otherwise depend on row
    order. Returns ranks (higher = higher priority)."""
    order = np.lexsort((epss, cox_risk, np.round(priority, 9)))
    ranks = np.empty(len(order), dtype=float)
    ranks[order] = np.arange(len(order))
    return ranks


def tie_summary(priority: np.ndarray, budget: float = 0.10) -> dict:
    """How much of the top `budget` ordering comes from the tie-break."""
    p = np.round(priority, 9)
    n_top = max(1, int(np.ceil(len(p) * budget)))
    top = np.sort(p)[::-1][:n_top]
    counts = pd.Series(p).value_counts()
    return {
        "share_rows_in_tie_blocks": float((pd.Series(p).map(counts) > 1).mean()),
        f"distinct_priorities_in_top_{int(budget * 100)}pct": int(len(np.unique(top))),
        f"rows_in_top_{int(budget * 100)}pct": n_top,
        "largest_tie_blocks": {f"{k:.4f}": int(c) for k, c in counts.iloc[:3].items()},
    }


def explanation_strings(firing: pd.DataFrame, min_strength: float = 1e-6) -> list[str]:
    """'R09=0.83; R02=0.62; ...' per row, strongest first, fired rules only."""
    values = firing.to_numpy()
    order = np.argsort(-values, axis=1)
    out = []
    for row, idx in zip(values, order):
        out.append("; ".join(f"{RULE_IDS[j]}={row[j]:.3f}" for j in idx if row[j] > min_strength))
    return out
