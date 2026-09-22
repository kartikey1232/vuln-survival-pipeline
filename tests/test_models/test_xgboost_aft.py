"""
Sign-convention test for XGBoost-AFT: it predicts a TIME (higher =
longer predicted survival = LOWER risk), the opposite direction from
Cox's partial hazard or an RSF risk score. scripts/models/xgboost_aft.py
negates the prediction (risk_score = -pred_time) before handing it to
scripts/evaluate/common.py, which expects a risk_score (higher = higher
risk). This test proves that negation is the right direction, using
synthetic data with a known, deterministic ground truth — no need to fit
a real XGBoost model to check a sign.
"""

from __future__ import annotations

import numpy as np
from lifelines.utils import concordance_index


def test_negated_aft_prediction_gives_correct_concordance_direction():
    # Construct a "perfect" AFT model: predicted_time is exactly
    # proportional to the true duration (a maximally good prediction).
    rng = np.random.default_rng(0)
    n = 200
    duration = rng.uniform(1, 1000, n)
    event = np.ones(n, dtype=int)  # all observed, for a clean deterministic check
    pred_time = duration * 2.0 + 1.0  # perfectly monotonic with duration

    risk_score = -pred_time  # the convention scripts/models/xgboost_aft.py uses

    # scripts/evaluate/common.py's bootstrap_metric computes concordance_index(duration, -risk_score, event)
    c_correct = concordance_index(duration, -risk_score, event)
    assert c_correct == 1.0  # perfect concordance in the correct direction

    # using the RAW (un-negated) prediction as if it were already a risk_score
    # would invert every comparison and produce the worst possible score
    c_wrong = concordance_index(duration, -pred_time, event)
    assert c_wrong == 0.0


def test_recall_at_budget_prefers_high_risk_score_rows():
    from scripts.evaluate.common import recall_at_budget

    # 100 rows, 10 events, the 10 events are exactly the 10 highest predicted_time
    # (i.e., the AFT model thinks these are the LEAST risky) -> if we (wrongly)
    # used pred_time as risk_score directly, recall@budget would be near-perfect
    # for the wrong reason; using -pred_time (correct) should score near zero.
    n = 100
    pred_time = np.arange(n, dtype=float)
    event = np.zeros(n, dtype=int)
    event[-10:] = 1  # events are the highest-pred_time rows (lowest true risk, by construction)

    risk_score_correct = -pred_time
    recall_correct = recall_at_budget(risk_score_correct, event, budget=0.10)
    assert recall_correct == 0.0  # events are NOT in the top-10-by-risk when the sign is right

    recall_wrong = recall_at_budget(pred_time, event, budget=0.10)
    assert recall_wrong == 1.0  # (demonstrates the wrong sign would look "perfect" for the wrong reason)
