"""
XGBoost-AFT (primary candidate model). Tunes aft_loss_distribution,
aft_loss_distribution_scale, and max_depth on the fit/val split (never
touching test), refits the chosen configuration on the full original
train set, and evaluates on test via scripts/evaluate/common.py.

AFT predicts a TIME (higher predicted time = lower risk), the opposite
direction of a Cox partial hazard or an RSF risk score — every place this
module hands a score to the shared evaluation module, it negates the
prediction first. See test_xgboost_aft_prediction_sign_is_negated_for_risk
in tests/test_leakage/test_landmark_features.py.

Usage: python -m scripts.models.xgboost_aft
"""

from __future__ import annotations

import csv
import itertools
import json
import logging

import numpy as np
import pandas as pd
import xgboost as xgb

from config.config_schema import get_config
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.evaluate.common import evaluate_model, evaluate_model_per_landmark
from scripts.evaluate.data_splits import load_full_train_and_test, load_splits
from scripts.evaluate.features import CATEGORICAL, encode_for_model, impute_numeric, one_hot, prepare_raw
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS

logger = get_logger(__name__, category="evaluate")

GRID = {
    "aft_loss_distribution": ["normal", "logistic", "extreme"],
    "aft_loss_distribution_scale": [0.8, 1.0, 1.2],
    "max_depth": [3, 4, 6],
}
LEARNING_RATE = 0.05
N_BOOST_ROUND = 1000
EARLY_STOPPING_ROUNDS = 30


def _fix_zero_durations(df: pd.DataFrame, label: str) -> pd.DataFrame:
    df = df.copy()
    zero_mask = df["event_time"] <= 0
    n_zero = int(zero_mask.sum())
    if n_zero:
        log_with_fields(logger, logging.INFO, f"{label}: zero/negative durations found", count=n_zero)
        df.loc[zero_mask, "event_time"] = df.loc[zero_mask, "event_time"] + 0.5
    return df


def _to_dmatrix(X: pd.DataFrame, duration: np.ndarray, event: np.ndarray) -> xgb.DMatrix:
    y_lower = duration.astype(float)
    y_upper = np.where(event.astype(bool), duration.astype(float), np.inf)
    d = xgb.DMatrix(X)
    d.set_float_info("label_lower_bound", y_lower)
    d.set_float_info("label_upper_bound", y_upper)
    return d


def _fit_config(
    X_fit, fit_duration, fit_event, X_val, val_duration, val_event, *, dist, scale, max_depth,
):
    dfit = _to_dmatrix(X_fit, fit_duration, fit_event)
    dval = _to_dmatrix(X_val, val_duration, val_event)
    params = {
        "objective": "survival:aft",
        "eval_metric": "aft-nloglik",
        "aft_loss_distribution": dist,
        "aft_loss_distribution_scale": scale,
        "max_depth": max_depth,
        "learning_rate": LEARNING_RATE,
        "tree_method": "hist",
    }
    booster = xgb.train(
        params, dfit, num_boost_round=N_BOOST_ROUND,
        evals=[(dval, "val")], early_stopping_rounds=EARLY_STOPPING_ROUNDS,
        verbose_eval=False,
    )
    return booster


def _val_cindex(booster: xgb.Booster, X_val, val_duration, val_event) -> float:
    """lifelines' concordance_index wants a score that correlates with
    predicted SURVIVAL TIME (higher = longer survival) — AFT's raw
    prediction already IS that, unlike Cox's partial hazard (a risk, the
    opposite direction) — so pred_time is passed directly, un-negated."""
    from lifelines.utils import concordance_index
    dval = xgb.DMatrix(X_val)
    pred_time = booster.predict(dval, iteration_range=(0, booster.best_iteration + 1))
    return concordance_index(val_duration, pred_time, val_event)


def main() -> None:
    cfg = get_config()
    splits = load_splits()
    fit_df = _fix_zero_durations(splits.fit, "fit")
    val_df = _fix_zero_durations(splits.val, "val")

    fit_df = prepare_raw(fit_df)
    val_df = prepare_raw(val_df)
    fit_df, val_df = impute_numeric(fit_df, val_df)

    X_fit = one_hot(fit_df, MODEL_FEATURE_COLUMNS)
    X_val = encode_for_model(val_df, list(X_fit.columns))

    fit_duration = fit_df["event_time"].values
    fit_event = fit_df["composite_event"].values.astype(bool)
    val_duration = val_df["event_time"].values
    val_event = val_df["composite_event"].values.astype(bool)

    results_csv = cfg.project_root / "scratch" / "xgboost_aft_tuning.csv"
    results_csv.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    best = {"val_cindex": -1.0, "config": None, "best_iteration": None}

    combos = list(itertools.product(GRID["aft_loss_distribution"], GRID["aft_loss_distribution_scale"], GRID["max_depth"]))
    for i, (dist, scale, depth) in enumerate(combos):
        booster = _fit_config(
            X_fit, fit_duration, fit_event, X_val, val_duration, val_event,
            dist=dist, scale=scale, max_depth=depth,
        )
        val_c = _val_cindex(booster, X_val, val_duration, val_event)
        log_with_fields(
            logger, logging.INFO, "xgboost-aft tuning config evaluated",
            config_index=i + 1, total_configs=len(combos),
            aft_loss_distribution=dist, aft_loss_distribution_scale=scale, max_depth=depth,
            best_iteration=booster.best_iteration, val_cindex=val_c,
        )
        rows.append({
            "aft_loss_distribution": dist, "aft_loss_distribution_scale": scale, "max_depth": depth,
            "best_iteration": booster.best_iteration, "val_cindex": val_c,
        })
        if val_c > best["val_cindex"]:
            best = {"val_cindex": val_c, "config": (dist, scale, depth), "best_iteration": booster.best_iteration}

    with open(results_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    dist, scale, depth = best["config"]
    log_with_fields(
        logger, logging.INFO, "xgboost-aft tuning complete", chosen_config=best["config"],
        chosen_val_cindex=best["val_cindex"], results_csv=str(results_csv),
    )

    # --- refit chosen config on the FULL original train set ---
    train_df, test_df = load_full_train_and_test()
    train_df = _fix_zero_durations(train_df, "full_train")
    test_df = _fix_zero_durations(test_df, "test")
    train_df = prepare_raw(train_df)
    test_df = prepare_raw(test_df)
    train_df, test_df = impute_numeric(train_df, test_df)

    X_train = one_hot(train_df, MODEL_FEATURE_COLUMNS)
    X_test = encode_for_model(test_df, list(X_train.columns))

    train_duration = train_df["event_time"].values
    train_event = train_df["composite_event"].values.astype(bool)

    dtrain = _to_dmatrix(X_train, train_duration, train_event)
    params = {
        "objective": "survival:aft",
        "eval_metric": "aft-nloglik",
        "aft_loss_distribution": dist,
        "aft_loss_distribution_scale": scale,
        "max_depth": depth,
        "learning_rate": LEARNING_RATE,
        "tree_method": "hist",
    }
    final_booster = xgb.train(params, dtrain, num_boost_round=best["best_iteration"] + 1)

    dtest = xgb.DMatrix(X_test)
    pred_time_test = final_booster.predict(dtest)
    risk_score_test = -pred_time_test  # negate: higher predicted time -> lower risk

    result = evaluate_model(test_df, risk_score_test, label="XGBoost-AFT", n_resamples=100)
    per_landmark = evaluate_model_per_landmark(test_df, risk_score_test, label="XGBoost-AFT", n_resamples=100)

    out = {
        "chosen_config": {"aft_loss_distribution": dist, "aft_loss_distribution_scale": scale, "max_depth": depth,
                           "learning_rate": LEARNING_RATE, "n_rounds": best["best_iteration"] + 1},
        "chosen_reason": f"highest validation C-index ({best['val_cindex']:.4f}) among {len(combos)} tuned configs",
        "pooled": result.as_dict(),
        "per_landmark": {k: v.as_dict() for k, v in per_landmark.items()},
    }
    print(json.dumps(out, indent=2, default=str))
    with open(cfg.project_root / "scratch" / "xgboost_aft_results.json", "w") as f:
        json.dump(out, f, indent=2, default=str)

    final_booster.save_model(str(cfg.project_root / "scratch" / "xgboost_aft_model.json"))


if __name__ == "__main__":
    main()
