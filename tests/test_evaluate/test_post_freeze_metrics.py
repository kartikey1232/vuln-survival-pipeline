"""
Tests for the post-freeze secondary metrics in scripts/evaluate/common.py
(time-dependent AUC, Brier/IPA, KM calibration). Synthetic data with known
answers — these are pure functions of arrays, same as the concordance
tests' synthetic cases.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from lifelines import KaplanMeierFitter
from sksurv.metrics import integrated_brier_score

from scripts.evaluate.common import (
    HorizonOutOfRangeError,
    _bootstrap_rows,
    bootstrap_metric,
    check_ipcw_horizons,
    evaluate_brier,
    evaluate_time_dependent_auc,
    fast_concordance_index,
    km_calibration_table,
    km_event_probability,
    survival_array,
)


def _synthetic(n=600, seed=0):
    """Exponential event times whose rate rises with a known risk score,
    plus independent uniform administrative censoring. 2 rows per CVE, so
    the CVE-clustered resampling path is exercised."""
    rng = np.random.default_rng(seed)
    risk = rng.normal(size=n)
    event_time = rng.exponential(200 / np.exp(risk))
    censor_time = rng.uniform(1, 400, n)
    duration = np.ceil(np.minimum(event_time, censor_time))
    event = event_time <= censor_time
    df = pd.DataFrame({
        "cve_id": [f"CVE-{i // 2}" for i in range(n)],
        "event_time": duration, "composite_event": event,
    })
    return df, risk


def test_bootstrap_rows_draws_the_same_resamples_as_bootstrap_metric():
    df, risk = _synthetic()
    cve_ids, d, e = df["cve_id"].values, df["event_time"].values, df["composite_event"].values.astype(int)
    cindex, _ = bootstrap_metric(cve_ids, d, e, risk, n_resamples=30, log_every=0)
    samples = _bootstrap_rows(cve_ids, lambda idx: [fast_concordance_index(d[idx], risk[idx], e[idx])], 1,
                              n_resamples=30, seed=20260922, log_every=0, log_label="")
    assert np.mean(samples) == pytest.approx(cindex.mean, abs=1e-12)
    assert np.percentile(samples, 2.5) == pytest.approx(cindex.ci_lower, abs=1e-12)


def test_horizon_outside_test_follow_up_raises_instead_of_clipping():
    with pytest.raises(HorizonOutOfRangeError, match="outside test follow-up"):
        check_ipcw_horizons(np.array([1, 1000]), np.array([1, 150]), (30, 90, 180))
    with pytest.raises(HorizonOutOfRangeError, match="training follow-up"):
        check_ipcw_horizons(np.array([1, 100]), np.array([1, 150]), (30,))
    check_ipcw_horizons(np.array([1, 1000]), np.array([1, 620]), (30, 90, 180))  # in range: no error


def test_time_dependent_auc_direction_and_range_check():
    df, risk = _synthetic()
    y_train = survival_array(df["event_time"], df["composite_event"])
    good = evaluate_time_dependent_auc(df, risk, survival_train=y_train, label="t", horizons=(30, 90),
                                       n_resamples=5, log_every=0)
    bad = evaluate_time_dependent_auc(df, -risk, survival_train=y_train, label="t", horizons=(30, 90),
                                      n_resamples=5, log_every=0)
    for h in (30, 90):
        assert good[h].point_estimate > 0.6
        assert good[h].point_estimate + bad[h].point_estimate == pytest.approx(1.0, abs=1e-9)
    with pytest.raises(HorizonOutOfRangeError):
        evaluate_time_dependent_auc(df, risk, survival_train=y_train, label="t", horizons=(10_000,),
                                    n_resamples=5, log_every=0)


def test_integrated_brier_matches_sksurv_and_ipa_rewards_the_true_model():
    df, risk = _synthetic()
    y = survival_array(df["event_time"], df["composite_event"])
    times = np.arange(30, 181, dtype=float)
    true_surv = np.exp(-np.outer(np.exp(risk) / 200, times))  # the generating model's own S(t|x)
    reference = np.exp(-times * np.exp(risk).mean() / 200)

    res = evaluate_brier(df, true_surv, times, survival_train=y, reference_surv_prob=reference,
                         label="t", point_horizons=(30, 90, 180), n_resamples=5, log_every=0)
    assert res["ibs"].point_estimate == pytest.approx(integrated_brier_score(y, y, true_surv, times), rel=1e-12)
    assert res["ipa_ibs"].point_estimate > 0
    assert res["ipa_90d"].point_estimate == pytest.approx(
        1 - res["brier_90d"].point_estimate / res["brier_90d_reference"].point_estimate)


def test_km_event_probability_matches_lifelines():
    df, _ = _synthetic()
    kmf = KaplanMeierFitter().fit(df["event_time"], df["composite_event"])
    for h in (0.5, 30, 90, 180):
        expected = 1 - float(kmf.survival_function_at_times(h).iloc[0])
        assert km_event_probability(df["event_time"].values, df["composite_event"].values, h) == pytest.approx(expected)


def test_calibration_table_bins_and_overall_row():
    df, risk = _synthetic()
    p90 = 1 - np.exp(-np.exp(risk) * 90 / 200)
    table = km_calibration_table(df, p90, 90, label="t", n_bins=5, n_resamples=5, log_every=0)
    assert list(table["bin"]) == ["1", "2", "3", "4", "5", "all"]
    assert table["n_rows"].iloc[:5].sum() == len(df)
    assert table["mean_predicted"].iloc[:5].is_monotonic_increasing
    overall = km_event_probability(df["event_time"].values, df["composite_event"].values, 90)
    assert table["observed"].iloc[-1] == pytest.approx(overall)
    # the generating model is calibrated by construction: overall ratio near 1
    assert table["ratio"].iloc[-1] == pytest.approx(1.0, abs=0.15)
