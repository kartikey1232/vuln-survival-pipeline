"""
Tests for scripts/fuzzy/risk_percentile.py's training-reference percentile
mapping. Synthetic scores with known answers — RiskReference is a pure
function of arrays.
"""

from __future__ import annotations

import numpy as np
import pytest

from scripts.fuzzy.risk_percentile import RiskReference

LANDMARKS = (7, 14, 30)


def _reference_data(n_per_landmark=2000, seed=0):
    """Per-landmark lognormal scores (Cox partial hazards are positive and
    right-skewed) with a different location per landmark, so a mapping
    that ignored landmark_day would give visibly wrong percentiles."""
    rng = np.random.default_rng(seed)
    scores = np.concatenate([rng.lognormal(mean=i, sigma=1.0, size=n_per_landmark) for i in range(len(LANDMARKS))])
    landmarks = np.repeat(LANDMARKS, n_per_landmark)
    return scores, landmarks


def test_percentile_is_monotonic_in_risk_score():
    scores, landmarks = _reference_data()
    ref = RiskReference.from_scores(scores, landmarks)
    grid = np.linspace(0, scores.max() * 1.1, 5000)
    for lm in LANDMARKS:
        pct = ref.percentile(grid, np.full(len(grid), lm))
        assert np.all(np.diff(pct) >= 0)
        assert pct[0] == 0.0 and pct[-1] == 1.0
    # Strictly increasing across distinct reference points of a landmark.
    ref_7 = np.unique(scores[landmarks == 7])
    assert np.all(np.diff(ref.percentile(ref_7, np.full(len(ref_7), 7))) > 0)


def test_training_set_against_its_own_reference_reproduces_empirical_quantiles():
    scores, landmarks = _reference_data()
    ref = RiskReference.from_scores(scores, landmarks)
    pct = ref.percentile(scores, landmarks)
    qs = np.linspace(0.01, 0.99, 99)
    for lm in LANDMARKS:
        own, own_pct = scores[landmarks == lm], pct[landmarks == lm]
        n = len(own)
        # Distinct scores: the training percentiles are exactly 1/n, 2/n, ..., 1.
        np.testing.assert_allclose(np.sort(own_pct), np.arange(1, n + 1) / n)
        # The empirical q-quantile of the training scores maps back to q
        # (up to the 1/n grid), and the share of training rows at or below
        # percentile q is q.
        q_scores = np.quantile(own, qs, method="inverted_cdf")
        np.testing.assert_allclose(ref.percentile(q_scores, np.full(len(qs), lm)), np.ceil(qs * n) / n)
        np.testing.assert_allclose([(own_pct <= q).mean() for q in qs], np.floor(qs * n) / n)


def test_ties_take_the_same_or_lower_fraction():
    ref = RiskReference.from_scores([1.0, 2.0, 2.0, 2.0, 3.0], [7] * 5)
    np.testing.assert_allclose(ref.percentile([0.5, 1.0, 2.0, 2.5, 3.0, 9.0], [7] * 6),
                               [0.0, 0.2, 0.8, 0.8, 1.0, 1.0])


def test_each_row_is_mapped_against_its_own_landmark_only():
    scores, landmarks = _reference_data()
    ref = RiskReference.from_scores(scores, landmarks)
    x = np.array([np.median(scores[landmarks == 14])] * 3)
    pct = ref.percentile(x, [7, 14, 30])
    assert pct[0] > 0.5 > pct[2]
    assert pct[1] == pytest.approx(0.5, abs=1e-3)


def test_mapping_does_not_depend_on_the_batch_being_scored():
    """Not ranked within the scored set: a row's percentile is the same
    alone as inside any batch."""
    scores, landmarks = _reference_data()
    ref = RiskReference.from_scores(scores, landmarks)
    rng = np.random.default_rng(1)
    batch = rng.lognormal(mean=3.0, sigma=0.2, size=500)  # all far into the upper tail
    batch_lm = rng.choice(LANDMARKS, size=500)
    together = ref.percentile(batch, batch_lm)
    alone = np.array([ref.percentile(batch[i:i + 1], batch_lm[i:i + 1])[0] for i in range(len(batch))])
    np.testing.assert_array_equal(together, alone)
    assert together.min() > 0.5


def test_unknown_landmark_and_nan_raise():
    ref = RiskReference.from_scores([1.0, 2.0], [7, 7])
    with pytest.raises(ValueError, match="landmark"):
        ref.percentile([1.0], [90])
    with pytest.raises(ValueError, match="NaN"):
        ref.percentile([np.nan], [7])


def test_save_load_round_trip(tmp_path):
    scores, landmarks = _reference_data(n_per_landmark=100)
    ref = RiskReference.from_scores(scores, landmarks)
    path = tmp_path / "ref.npz"
    ref.save(path)
    loaded = RiskReference.load(path)
    assert set(loaded.sorted_scores) == set(LANDMARKS)
    np.testing.assert_array_equal(loaded.percentile(scores, landmarks), ref.percentile(scores, landmarks))
