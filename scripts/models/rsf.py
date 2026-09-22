"""
Random Survival Forest (sksurv). Tunes min_samples_leaf and max_features
on the fit/val split, refits on the full original train set, evaluates on
test via scripts/evaluate/common.py, and reports top permutation feature
importances computed on VALIDATION (never test).

RSF's .predict() already returns a risk score (higher = higher risk),
same convention as Cox's partial hazard — no sign flip needed, unlike
XGBoost-AFT.

If memory becomes a problem, this reduces max_samples (reported) rather
than crashing.

Usage: python -m scripts.models.rsf
"""

from __future__ import annotations

import csv
import itertools
import json
import logging

import numpy as np
import pandas as pd
from sksurv.ensemble import RandomSurvivalForest
from sksurv.util import Surv

from config.config_schema import get_config
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.evaluate.common import evaluate_model, evaluate_model_per_landmark
from scripts.evaluate.data_splits import load_full_train_and_test, load_splits
from scripts.evaluate.features import impute_numeric, one_hot, prepare_raw
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS

logger = get_logger(__name__, category="evaluate")

GRID = {
    "min_samples_leaf": [30, 50, 100],
    "max_features": ["sqrt", "log2", 0.3],
}
N_ESTIMATORS = 200
MAX_SAMPLES = 20_000


def _to_structured_y(duration: np.ndarray, event: np.ndarray):
    return Surv.from_arrays(event=event.astype(bool), time=duration.astype(float))


def _fit_rsf(X, y, *, min_samples_leaf, max_features, max_samples=MAX_SAMPLES):
    n = len(X)
    ms = min(max_samples, n)
    while True:
        try:
            rsf = RandomSurvivalForest(
                n_estimators=N_ESTIMATORS, min_samples_leaf=min_samples_leaf, max_features=max_features,
                max_samples=ms, low_memory=True, n_jobs=-1, random_state=0,
            )
            rsf.fit(X, y)
            return rsf, ms
        except MemoryError:
            log_with_fields(logger, logging.WARNING, "RSF MemoryError, reducing max_samples", attempted_max_samples=ms)
            ms = ms // 2
            if ms < 500:
                raise


def main() -> None:
    cfg = get_config()
    splits = load_splits()
    fit_df = prepare_raw(splits.fit)
    val_df = prepare_raw(splits.val)
    fit_df, val_df = impute_numeric(fit_df, val_df)

    X_fit = one_hot(fit_df, MODEL_FEATURE_COLUMNS)
    X_val = one_hot(val_df, MODEL_FEATURE_COLUMNS, align_to=list(X_fit.columns))
    y_fit = _to_structured_y(fit_df["event_time"].values, fit_df["composite_event"].values)
    y_val = _to_structured_y(val_df["event_time"].values, val_df["composite_event"].values)

    results_csv = cfg.project_root / "scratch" / "rsf_tuning.csv"
    results_csv.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    best = {"val_cindex": -1.0, "config": None}

    combos = list(itertools.product(GRID["min_samples_leaf"], GRID["max_features"]))
    for i, (leaf, feat) in enumerate(combos):
        rsf, used_max_samples = _fit_rsf(X_fit, y_fit, min_samples_leaf=leaf, max_features=feat)
        val_c = rsf.score(X_val, y_val)
        log_with_fields(
            logger, logging.INFO, "rsf tuning config evaluated",
            config_index=i + 1, total_configs=len(combos),
            min_samples_leaf=leaf, max_features=feat, max_samples_used=used_max_samples, val_cindex=val_c,
        )
        rows.append({"min_samples_leaf": leaf, "max_features": feat, "max_samples_used": used_max_samples, "val_cindex": val_c})
        if val_c > best["val_cindex"]:
            best = {"val_cindex": val_c, "config": (leaf, feat)}

    with open(results_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    leaf, feat = best["config"]
    log_with_fields(
        logger, logging.INFO, "rsf tuning complete", chosen_config=best["config"],
        chosen_val_cindex=best["val_cindex"], results_csv=str(results_csv),
    )

    # --- permutation feature importance, on VALIDATION (never test) ---
    from sklearn.inspection import permutation_importance
    rsf_val, _ = _fit_rsf(X_fit, y_fit, min_samples_leaf=leaf, max_features=feat)
    perm = permutation_importance(rsf_val, X_val, y_val, n_repeats=5, random_state=0, n_jobs=-1)
    importance_df = pd.DataFrame({
        "feature": X_val.columns, "importance_mean": perm.importances_mean, "importance_std": perm.importances_std,
    }).sort_values("importance_mean", ascending=False)
    importance_df.to_csv(cfg.project_root / "scratch" / "rsf_permutation_importance.csv", index=False)
    log_with_fields(
        logger, logging.INFO, "rsf top permutation importances (validation)",
        top10=importance_df.head(10).to_dict("records"),
    )

    # --- refit chosen config on the FULL original train set ---
    train_df, test_df = load_full_train_and_test()
    train_df = prepare_raw(train_df)
    test_df = prepare_raw(test_df)
    train_df, test_df = impute_numeric(train_df, test_df)

    X_train = one_hot(train_df, MODEL_FEATURE_COLUMNS)
    X_test = one_hot(test_df, MODEL_FEATURE_COLUMNS, align_to=list(X_train.columns))
    y_train = _to_structured_y(train_df["event_time"].values, train_df["composite_event"].values)

    final_rsf, final_max_samples = _fit_rsf(X_train, y_train, min_samples_leaf=leaf, max_features=feat)
    risk_score_test = final_rsf.predict(X_test)  # already a risk score, higher = higher risk

    result = evaluate_model(test_df, risk_score_test, label="RSF", n_resamples=100)
    per_landmark = evaluate_model_per_landmark(test_df, risk_score_test, label="RSF", n_resamples=100)

    out = {
        "chosen_config": {"min_samples_leaf": leaf, "max_features": feat, "n_estimators": N_ESTIMATORS,
                           "max_samples": final_max_samples},
        "chosen_reason": f"highest validation C-index ({best['val_cindex']:.4f}) among {len(combos)} tuned configs",
        "top_permutation_importances_val": importance_df.head(15).to_dict("records"),
        "pooled": result.as_dict(),
        "per_landmark": {k: v.as_dict() for k, v in per_landmark.items()},
    }
    print(json.dumps(out, indent=2, default=str))
    with open(cfg.project_root / "scratch" / "rsf_results.json", "w") as f:
        json.dump(out, f, indent=2, default=str)


if __name__ == "__main__":
    main()
