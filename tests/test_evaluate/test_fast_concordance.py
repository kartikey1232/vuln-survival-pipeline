"""
Validates fast_concordance_index against lifelines.utils.concordance_index
exactly (to 1e-9) — required before fast_concordance_index is trusted for
real evaluation. Includes the small controlled cases used to reverse-
engineer lifelines' tie-handling rules (documented in
scripts/evaluate/common.py's fast_concordance_index docstring), large
synthetic data with heavy ties, and real project data (EPSS scores,
random vectors, and bootstrap-resampled/duplicated rows).
"""

from __future__ import annotations

import numpy as np
import pytest
from lifelines.utils import concordance_index

from scripts.evaluate.common import (
    _build_cve_row_index,
    _resampled_row_index,
    fast_concordance_index,
)

TOLERANCE = 1e-9


# --- controlled small cases (the ones used to reverse-engineer the tie rules) ---


def _with_baseline(extra_d, extra_e, extra_s):
    # X: event@0, score 0.0 ; Y: censored@100, score 1.0 -- always 1 concordant baseline pair
    d = [0, 100] + extra_d
    e = [1, 0] + extra_e
    s = [0.0, 1.0] + extra_s
    return d, e, s


@pytest.mark.parametrize(
    "extra_d,extra_e,extra_s,expected",
    [
        ([5, 5], [1, 1], [1.0, 2.0], 0.7),   # tied-time both-event, different scores
        ([5, 5], [1, 1], [1.0, 1.0], 0.8),   # tied-time both-event, same scores
        ([5, 5], [1, 0], [1.0, 2.0], 0.9),   # tied-time event+censored -> comparable
        ([3, 5], [1, 0], [1.0, 2.0], 0.9),   # event earlier than censored, concordant by construction
        ([3, 5], [1, 0], [2.0, 1.0], 0.6),   # event earlier than censored, discordant by construction
        ([3, 5], [0, 1], [1.0, 2.0], 0.75),  # censored earlier than event -> not comparable
    ],
)
def test_matches_lifelines_on_controlled_tie_cases(extra_d, extra_e, extra_s, expected):
    d, e, s = _with_baseline(extra_d, extra_e, extra_s)
    d, e, s = np.array(d, dtype=float), np.array(e), np.array(s, dtype=float)
    # `s` here is in LIFELINES' own convention (higher = longer survival),
    # matching how these cases were hand-derived against lifelines directly.
    # fast_concordance_index wants a risk_score (higher = higher risk) --
    # the opposite -- so negate before passing it in, same as every other
    # caller in this project does.
    c_ll = concordance_index(d, s, e)
    assert c_ll == pytest.approx(expected)
    c_fast = fast_concordance_index(d, -s, e)
    assert c_fast == pytest.approx(expected)
    assert abs(c_fast - c_ll) < TOLERANCE


def test_matches_lifelines_large_synthetic_with_heavy_ties():
    rng = np.random.default_rng(0)
    n = 5000
    duration = rng.integers(1, 200, n).astype(float)  # narrow integer range -> plenty of ties
    event = rng.binomial(1, 0.05, n)
    risk = rng.random(n)

    c_fast = fast_concordance_index(duration, risk, event)
    c_ll = concordance_index(duration, -risk, event)
    assert abs(c_fast - c_ll) < TOLERANCE


# --- real project data ---


@pytest.fixture(scope="module")
def real_test_data():
    import pandas as pd
    from sqlalchemy.exc import OperationalError

    from database.engine import get_engine

    try:
        df = pd.read_sql(
            "SELECT cve_id, event_time, composite_event, epss_score_at_asof_raw, epss_pct_now "
            "FROM training.training_dataset "
            "WHERE dataset_version = 'landmark_v20260922' AND as_of_date >= '2025-01-01'",
            get_engine(),
        )
    except OperationalError as exc:
        pytest.skip(f"production database unavailable: {exc}")
    if df.empty:
        pytest.skip("production database has no landmark_v20260922 test rows")
    duration = df["event_time"].clip(lower=0.5).values.astype(float)
    event = df["composite_event"].values.astype(int)
    return df, duration, event


def test_matches_lifelines_on_real_epss_and_random_vectors(real_test_data):
    df, duration, event = real_test_data
    rng = np.random.default_rng(7)

    vectors = {
        "epss_score_at_asof_raw": df["epss_score_at_asof_raw"].fillna(0).values,
        "epss_pct_now": df["epss_pct_now"].fillna(0).values,
    }
    for i in range(5):
        vectors[f"random_{i}"] = rng.random(len(df))

    for name, risk in vectors.items():
        c_fast = fast_concordance_index(duration, risk, event)
        c_ll = concordance_index(duration, -risk, event)
        assert abs(c_fast - c_ll) < TOLERANCE, f"mismatch for {name}: fast={c_fast} lifelines={c_ll}"


def test_matches_lifelines_on_bootstrap_resamples_with_duplicates(real_test_data):
    df, duration, event = real_test_data
    risk = df["epss_pct_now"].fillna(0).values
    cve_ids = df["cve_id"].values
    unique_cves = np.unique(cve_ids)
    cve_row_index = _build_cve_row_index(cve_ids)

    rng = np.random.default_rng(99)
    for _ in range(10):
        row_idx = _resampled_row_index(cve_row_index, unique_cves, rng)
        d, e, s = duration[row_idx], event[row_idx], risk[row_idx]
        c_fast = fast_concordance_index(d, s, e)
        c_ll = concordance_index(d, -s, e)
        assert abs(c_fast - c_ll) < TOLERANCE
