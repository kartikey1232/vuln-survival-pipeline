"""
Tests for blind_spot_catch_rate / evaluate_blind_spot_catch_rate in
scripts/evaluate/common.py: same definition as final_comparison.py's
original step4 loop, on the same CVE resamples as the other metrics.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from scripts.evaluate.common import (
    _bootstrap_rows,
    blind_spot_catch_rate,
    evaluate_blind_spot_catch_rate,
)


def _step4_definition(risk_model, risk_epss, ev, budget=0.10):
    """final_comparison.py step4's catch_rate, verbatim logic."""
    n_top = max(1, int(np.ceil(len(risk_epss) * budget)))
    epss_top = set(np.argsort(-risk_epss)[:n_top])
    positives = np.where(ev == 1)[0]
    blind_spots = [i for i in positives if i not in epss_top]
    if not blind_spots:
        return np.nan
    model_top = set(np.argsort(-risk_model)[:n_top])
    return sum(1 for i in blind_spots if i in model_top) / len(blind_spots)


def _synthetic(n=3000, seed=0):
    rng = np.random.default_rng(seed)
    latent = rng.normal(size=n)
    event = (latent + rng.normal(scale=0.8, size=n) > 2.0).astype(int)
    df = pd.DataFrame({"cve_id": [f"CVE-{i // 3}" for i in range(n)], "composite_event": event})
    return df, latent + rng.normal(scale=0.5, size=n), latent + rng.normal(scale=1.5, size=n), rng.normal(size=n)


@pytest.mark.parametrize("budget", [0.01, 0.05, 0.10])
def test_matches_the_original_step4_definition(budget):
    df, model, epss, noise = _synthetic()
    ev = df["composite_event"].to_numpy()
    for score in (model, epss, noise):
        assert blind_spot_catch_rate(score, epss, ev, budget) == pytest.approx(_step4_definition(score, epss, ev, budget))
    assert blind_spot_catch_rate(epss, epss, ev, budget) == 0.0


def test_no_blind_spots_gives_nan():
    ev = np.array([1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    epss = np.arange(10, 0, -1, dtype=float)  # the only event is EPSS's top row
    assert np.isnan(blind_spot_catch_rate(np.zeros(10), epss, ev, 0.10))


def test_bootstrap_uses_shared_resamples_and_pairs_the_difference():
    df, model, epss, noise = _synthetic()
    ev = df["composite_event"].to_numpy()
    out = evaluate_blind_spot_catch_rate(df, {"model": model, "noise": noise}, epss, label="t",
                                         reference="noise", n_resamples=40, log_every=0)
    samples = _bootstrap_rows(df["cve_id"].values, lambda idx: [
        _step4_definition(model[idx], epss[idx], ev[idx]), _step4_definition(noise[idx], epss[idx], ev[idx])],
        2, n_resamples=40, seed=20260922, log_every=0, log_label="")
    assert out["per_model"]["model"]["mean"] == pytest.approx(np.nanmean(samples[:, 0]))
    diff = out["paired_vs_reference"]["model"]
    assert diff["point_diff"] == pytest.approx(out["per_model"]["model"]["point"] - out["per_model"]["noise"]["point"])
    assert diff["mean_diff"] == pytest.approx(np.nanmean(samples[:, 0] - samples[:, 1]))
    assert diff["excludes_zero"] and diff["ci_lower"] > 0
