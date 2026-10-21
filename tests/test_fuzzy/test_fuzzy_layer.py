"""
Tests for the fuzzy rule base (scripts/fuzzy/fuzzy_layer.py), run on the
frozen validation-fitted config in models/fuzzy_config.json AND on a
synthetic config with different anchors, so a pass reflects the rule
structure, not one lucky set of cut-offs. Grids, not single examples.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import skfuzzy as fuzz

from scripts.fuzzy import fuzzy_layer as fl

FROZEN_CONFIG = Path(__file__).resolve().parents[2] / "models" / "fuzzy_config.json"

COX_GRID = np.linspace(0, 1, 101)
EPSS_GRID = np.array([0.0, 0.02, 0.08, 0.10, 0.13, 0.16, 0.2, 0.27, 0.35, 0.42, 0.6, 0.9, 1.0])
# One score per NVD band plus both sides of the Critical boundary (the
# bands are crisp on one-decimal scores, so more values per band add nothing).
CVSS_PRESENT = np.array([2.0, 5.5, 8.8, 9.0, 9.8])


def _synthetic_config():
    rng = np.random.default_rng(0)
    n = 5000
    df = pd.DataFrame({
        "cox_risk_pct": rng.beta(1.2, 2.5, n), "epss_pct_now": rng.beta(0.8, 4.0, n),
        "cvss_base_score": rng.choice([5.0, 7.5, 9.8], n), "cvss_cna_missing": False,
    })
    return fl.fit_cutoffs(df)


def _configs():
    out = [pytest.param(_synthetic_config(), id="synthetic")]
    if FROZEN_CONFIG.exists():
        out.append(pytest.param(json.loads(FROZEN_CONFIG.read_text()), id="frozen"))
    return out


def _grid(cvss_values, missing, cox=COX_GRID, epss=EPSS_GRID):
    """cox varies fastest, so rows reshape to (n_epss * n_cvss, n_cox)."""
    e, c, x = np.meshgrid(epss, cvss_values, cox, indexing="ij")
    e, c, x = e.ravel(), c.ravel(), x.ravel()
    return {"cox_risk": x, "epss": e, "cvss": c, "cvss_missing": np.full(len(x), float(missing)),
            "blindspot": x - e}


def _all_rows_grid():
    present, missing = _grid(CVSS_PRESENT, False), _grid(np.array([0.0]), True)
    return {k: np.concatenate([present[k], missing[k]]) for k in present}


@pytest.mark.parametrize("config", _configs())
def test_raising_cox_risk_never_lowers_priority(config):
    """Every (epss, cvss, missing) combination, cox_risk swept 0 -> 1. The
    derived blindspot moves with cox_risk, as it does in real data."""
    for cvss_values, missing in [(CVSS_PRESENT, False), (np.array([0.0]), True)]:
        priority, _ = fl.score(_grid(cvss_values, missing), config)
        steps = np.diff(priority.reshape(-1, len(COX_GRID)), axis=1)
        assert steps.min() >= -1e-9, f"priority drops by {-steps.min():.4g} as cox_risk rises (missing={missing})"


@pytest.mark.skipif(not FROZEN_CONFIG.exists(), reason="models/fuzzy_config.json not built")
def test_frozen_config_is_monotone_in_cox_risk_on_a_dense_grid():
    """The coarse grid above missed dips of 0.003 points during design;
    cox_risk step 0.001 found them. design.py runs this at 101 epss values
    before writing the config; 11 here keeps the suite fast."""
    config = json.loads(FROZEN_CONFIG.read_text())
    assert config["monotonicity_check"]["worst_step"] >= -1e-9
    assert fl.worst_cox_monotonicity_step(config, epss_points=11,
                                          cvss_cases=((5.5, False), (9.5, False), (0.0, True))) >= -1e-9


@pytest.mark.parametrize("config", _configs())
def test_explanation_only_rules_never_change_priority(config):
    from skfuzzy import control as ctrl

    grid = _all_rows_grid()
    priority, firing = fl.score(grid, config)
    assert (firing[sorted(fl.EXPLANATION_ONLY_RULES)].to_numpy() > 0).any(axis=0).all()

    reduced = [(rid, text, ant, term) for rid, text, ant, term in fl.RULES if rid not in fl.EXPLANATION_ONLY_RULES]
    system, v = fl.build_system(config)
    rules = [ctrl.Rule(ant(v), v["priority"][term], label=rid) for rid, _, ant, term in reduced]
    sim = ctrl.ControlSystemSimulation(ctrl.ControlSystem(rules), cache=False)
    for k, values in grid.items():
        sim.input[k] = values
    sim.compute()
    np.testing.assert_allclose(sim.output["priority"], priority, atol=1e-9)


@pytest.mark.parametrize("config", _configs())
def test_raising_cox_risk_never_lowers_priority_with_blindspot_held_fixed(config):
    """Stricter: blindspot is held at fixed values too, as if it were an
    independent input."""
    rows = []
    for bs, epss, cvss, missing in itertools.product([-0.5, 0.0, 0.24, 0.6, 1.0], EPSS_GRID[::3],
                                                     [0.0, 5.5, 9.8], [False, True]):
        rows.append(pd.DataFrame({"cox_risk": COX_GRID, "epss": epss, "cvss": cvss,
                                  "cvss_missing": float(missing), "blindspot": bs}))
    grid = pd.concat(rows, ignore_index=True)
    priority, _ = fl.score({k: grid[k].to_numpy() for k in grid}, config)
    steps = np.diff(priority.reshape(-1, len(COX_GRID)), axis=1)
    assert steps.min() >= -1e-9


@pytest.mark.parametrize("config", _configs())
def test_some_rule_fires_for_every_input_combination(config):
    """Every combination on a grid over all five inputs, blindspot included
    as if independent (so unrealistic corners are covered too)."""
    axes = [np.linspace(0, 1, 11), np.linspace(0, 1, 11), np.array([0.0, 3.95, 5.5, 8.0, 8.95, 10.0]),
            np.array([0.0, 1.0]), np.linspace(-1, 1, 11)]
    x, e, c, m, b = (a.ravel() for a in np.meshgrid(*axes, indexing="ij"))
    _, firing = fl.score({"cox_risk": x, "epss": e, "cvss": c, "cvss_missing": m, "blindspot": b}, config)
    assert firing.to_numpy().max(axis=1).min() > 0
    # Low and AtLeastMedium partition [0, 1], so the two cox-only backbone
    # rules R07 and R09 alone always sum to 1.
    np.testing.assert_allclose(firing[["R07", "R09"]].sum(axis=1), 1.0, atol=1e-9)


@pytest.mark.parametrize("config", _configs())
def test_priority_always_within_0_100(config):
    rng = np.random.default_rng(1)
    n = 5000
    cox, epss = rng.uniform(0, 1, n), rng.uniform(0, 1, n)
    cox[:4], epss[:4] = [0, 0, 1, 1], [0, 1, 0, 1]
    inputs = {"cox_risk": cox, "epss": epss, "cvss": rng.uniform(0, 10, n),
              "cvss_missing": rng.integers(0, 2, n).astype(float), "blindspot": cox - epss}
    priority, _ = fl.score(inputs, config)
    assert np.isfinite(priority).all()
    assert priority.min() >= 0 and priority.max() <= 100


@pytest.mark.parametrize("config", _configs())
def test_missing_cvss_has_its_own_path_and_never_reads_as_low_severity(config):
    missing = _grid(np.array([0.0]), True)
    p_missing, f_missing = fl.score(missing, config)

    # No severity rule can fire without a CNA score, in either direction...
    assert f_missing[sorted(fl.CVSS_RULES)].to_numpy().max() == 0
    # ...and the missing path fires wherever its premise holds.
    low_low = (missing["cox_risk"] <= np.quantile(COX_GRID, 0.1)) & (missing["epss"] == 0)
    assert (f_missing.loc[low_low, "R16"] > 0).all()

    # The placeholder CVSS value of a missing row is inert.
    p_missing_10, _ = fl.score({**missing, "cvss": np.full(len(missing["cvss"]), 10.0)}, config)
    np.testing.assert_allclose(p_missing, p_missing_10, atol=1e-9)

    # Never ranked below the same row with ANY non-Critical CNA score (the
    # VeryLow rule R06 is closed to it), never above the same row with a
    # Critical one (it gets no severity boost either).
    for cvss, compare in [(0.0, "ge"), (3.9, "ge"), (5.5, "ge"), (8.8, "ge"), (9.0, "le"), (10.0, "le")]:
        p_present, _ = fl.score({**missing, "cvss": np.full(len(missing["cvss"]), cvss),
                                 "cvss_missing": np.zeros(len(missing["cvss"]))}, config)
        if compare == "ge":
            assert (p_missing >= p_present - 1e-9).all(), f"missing ranked below present cvss={cvss}"
        else:
            assert (p_missing <= p_present + 1e-9).all(), f"missing ranked above present cvss={cvss}"


def test_model_inputs_keep_missing_cvss_flagged_and_reject_other_nans():
    df = pd.DataFrame({"cox_risk_pct": [0.5, 0.9], "epss_pct_now": [0.1, 0.2],
                       "cvss_base_score": [np.nan, 9.8], "cvss_cna_missing": [True, False]})
    inputs = fl.model_inputs(df)
    np.testing.assert_array_equal(inputs["cvss_missing"], [1.0, 0.0])
    np.testing.assert_allclose(inputs["blindspot"], [0.4, 0.7])
    with pytest.raises(ValueError, match="NaN"):
        fl.model_inputs(df.assign(cvss_cna_missing=[False, False]))
    with pytest.raises(ValueError, match="NaN"):
        fl.model_inputs(df.assign(epss_pct_now=[np.nan, 0.2]))


def test_array_mode_matches_single_row_skfuzzy_and_records_min_firing():
    """The vectorised path (and the firing-strength recorder) agree with
    scikit-fuzzy evaluated one row at a time."""
    from skfuzzy import control as ctrl

    config = _synthetic_config()
    rng = np.random.default_rng(2)
    n = 25
    cox, epss = rng.uniform(0, 1, n), rng.uniform(0, 1, n)
    inputs = {"cox_risk": cox, "epss": epss, "cvss": rng.choice([3.0, 7.5, 9.8], n),
              "cvss_missing": rng.integers(0, 2, n).astype(float), "blindspot": cox - epss}
    priority, firing = fl.score(inputs, config)

    system, v = fl.build_system(config)
    for i in range(n):
        sim = ctrl.ControlSystemSimulation(system)
        for k in inputs:
            sim.input[k] = float(inputs[k][i])
        sim.compute()
        assert sim.output["priority"] == pytest.approx(priority[i], abs=1e-9)

    mu = lambda var, term, x: fuzz.interp_membership(v[var].universe, v[var][term].mf, x)
    np.testing.assert_allclose(firing["R02"], np.minimum(mu("cox_risk", "High", cox), mu("epss", "Low", epss)))
    np.testing.assert_allclose(firing["R01"], mu("cox_risk", "VeryHigh", cox))


def test_cutoffs_follow_validation_quantiles_with_narrower_top_spacing():
    config = _synthetic_config()
    for name in ("cox_risk", "epss"):
        q = list(config["validation_quantiles"][name].values())
        sets = config["membership_functions"][name]
        assert sets["Low"][1] == [0.0, 0.0, q[0], q[1]]
        assert sets["VeryHigh"][1] == [q[2], q[3], 1.0, 1.0]
    gaps = np.diff(fl.LEVEL_QUANTILES)
    assert np.all(np.diff(gaps) < 0)


def test_cvss_terms_are_the_standard_bands():
    system, v = fl.build_system(_synthetic_config())
    for score, band in [(0.0, "Low"), (3.9, "Low"), (4.0, "Medium"), (6.9, "Medium"),
                        (7.0, "High"), (8.9, "High"), (9.0, "Critical"), (10.0, "Critical")]:
        for term in fl.CVSS_BANDS:
            expected = 1.0 if term == band else 0.0
            assert fuzz.interp_membership(v["cvss"].universe, v["cvss"][term].mf, score) == pytest.approx(expected)


def test_ranking_score_is_a_total_order_respecting_priority():
    priority = np.array([50.0, 80.0, 80.0, 20.0, 80.0])
    cox = np.array([0.9, 0.2, 0.7, 0.99, 0.7])
    epss = np.array([0.1, 0.1, 0.3, 0.1, 0.2])
    ranks = fl.ranking_score(priority, cox, epss)
    assert len(np.unique(ranks)) == len(ranks)
    assert list(np.argsort(-ranks)) == [2, 4, 1, 0, 3]
