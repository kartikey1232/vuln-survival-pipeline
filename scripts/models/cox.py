"""
Cox PH (penalizer=0.1), refit on the full original train set using the
same allowlisted features as every other model, evaluated on test via the
shared, fast scripts/evaluate/common.py module.

Cox's partial hazard is already a risk score (higher = higher risk), same
convention as RSF and the shared module — no sign flip needed (unlike
XGBoost-AFT).

Usage: python -m scripts.models.cox
"""

from __future__ import annotations

import json

from lifelines import CoxPHFitter

from config.config_schema import get_config
from scripts.evaluate.common import evaluate_model, evaluate_model_per_landmark
from scripts.evaluate.data_splits import load_full_train_and_test
from scripts.evaluate.features import encode_for_model, impute_numeric, one_hot, prepare_raw
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS


def main() -> None:
    cfg = get_config()
    train_df, test_df = load_full_train_and_test()
    train_df = prepare_raw(train_df)
    test_df = prepare_raw(test_df)
    train_df, test_df = impute_numeric(train_df, test_df)

    X_train = one_hot(train_df, MODEL_FEATURE_COLUMNS)
    X_test = encode_for_model(test_df, list(X_train.columns))

    X_train = X_train.copy()
    X_train["event_time"] = train_df["event_time"].clip(lower=0.5)
    X_train["composite_event"] = train_df["composite_event"].astype(int)
    const_cols = [
        c for c in X_train.columns
        if c not in ("event_time", "composite_event") and X_train[c].nunique() <= 1
    ]
    X_train = X_train.drop(columns=const_cols)
    X_test = X_test.drop(columns=[c for c in const_cols if c in X_test.columns])

    cph = CoxPHFitter(penalizer=0.1)
    cph.fit(X_train, duration_col="event_time", event_col="composite_event")

    risk_score_test = cph.predict_partial_hazard(X_test).values

    result = evaluate_model(test_df, risk_score_test, label="Cox", n_resamples=100)
    per_landmark = evaluate_model_per_landmark(test_df, risk_score_test, label="Cox", n_resamples=100)

    out = {
        "config": {"penalizer": 0.1},
        "train_cindex_lifelines_internal": cph.concordance_index_,
        "pooled": result.as_dict(),
        "per_landmark": {k: v.as_dict() for k, v in per_landmark.items()},
    }
    print(json.dumps(out, indent=2, default=str))
    with open(cfg.project_root / "scratch" / "cox_results_fast.json", "w") as f:
        json.dump(out, f, indent=2, default=str)


if __name__ == "__main__":
    main()
