"""
Final model-comparison analysis: paired bootstrap differences vs EPSS,
trajectory ablation, blind-spot catch rate, and RSF run-to-run variance.
Refits each model ONCE with its already-chosen (not re-tuned) config —
tuning already happened in scripts/models/{cox,rsf,xgboost_aft}.py.

Usage: python -m scripts.evaluate.final_comparison
"""

from __future__ import annotations

import json
import logging

import numpy as np
import pandas as pd
import xgboost as xgb
from lifelines import CoxPHFitter
from sksurv.ensemble import RandomSurvivalForest
from sksurv.util import Surv

from config.config_schema import get_config
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.evaluate.common import (
    _build_cve_row_index,
    _resampled_row_index,
    evaluate_model,
    fast_concordance_index,
    paired_bootstrap_compare,
    recall_at_budget,
)
from scripts.evaluate.data_splits import load_full_train_and_test
from scripts.evaluate.features import impute_numeric, one_hot, prepare_raw
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS
from scripts.models.xgboost_aft import _fix_zero_durations, _to_dmatrix

logger = get_logger(__name__, category="evaluate")

# chosen configs (from the fixed-features tuning runs, NOT re-tuned here)
XGB_CONFIG = {"aft_loss_distribution": "extreme", "aft_loss_distribution_scale": 1.2, "max_depth": 6,
              "learning_rate": 0.05, "n_rounds": 272}
RSF_CONFIG = {"min_samples_leaf": 50, "max_features": "log2", "n_estimators": 200, "max_samples": 20000}

TRAJECTORY_FEATURES = [
    "epss_pct_7d_ago", "epss_pct_7d_ago_missing", "epss_pct_delta_7d",
    "epss_pct_first", "epss_pct_max_to_date", "days_to_first_epss",
]
EPSS_FEATURES = [c for c in MODEL_FEATURE_COLUMNS if c.startswith("epss") or c == "landmark_day" or c == "days_to_first_epss"]


def _prep():
    train_df, test_df = load_full_train_and_test()
    train_df = _fix_zero_durations(prepare_raw(train_df), "train")
    test_df = _fix_zero_durations(prepare_raw(test_df), "test")
    train_df, test_df = impute_numeric(train_df, test_df)
    return train_df, test_df


def _fit_xgb(train_df, test_df, feature_cols, config=XGB_CONFIG):
    X_train = one_hot(train_df, feature_cols)
    X_test = one_hot(test_df, feature_cols, align_to=list(X_train.columns))
    duration = train_df["event_time"].values
    event = train_df["composite_event"].values.astype(bool)
    dtrain = _to_dmatrix(X_train, duration, event)
    params = {
        "objective": "survival:aft", "eval_metric": "aft-nloglik",
        "aft_loss_distribution": config["aft_loss_distribution"],
        "aft_loss_distribution_scale": config["aft_loss_distribution_scale"],
        "max_depth": config["max_depth"], "learning_rate": config["learning_rate"], "tree_method": "hist",
    }
    booster = xgb.train(params, dtrain, num_boost_round=config["n_rounds"])
    pred_time = booster.predict(xgb.DMatrix(X_test))
    return -pred_time  # risk_score: negate AFT's time prediction


def _fit_rsf(train_df, test_df, feature_cols, *, random_state=0):
    X_train = one_hot(train_df, feature_cols)
    X_test = one_hot(test_df, feature_cols, align_to=list(X_train.columns))
    y_train = Surv.from_arrays(event=train_df["composite_event"].values.astype(bool),
                                time=train_df["event_time"].values.astype(float))
    rsf = RandomSurvivalForest(
        n_estimators=RSF_CONFIG["n_estimators"], min_samples_leaf=RSF_CONFIG["min_samples_leaf"],
        max_features=RSF_CONFIG["max_features"], max_samples=min(RSF_CONFIG["max_samples"], len(X_train)),
        low_memory=True, n_jobs=-1, random_state=random_state,
    )
    rsf.fit(X_train, y_train)
    return rsf.predict(X_test)


def _fit_cox(train_df, test_df, feature_cols):
    X_train = one_hot(train_df, feature_cols)
    X_test = one_hot(test_df, feature_cols, align_to=list(X_train.columns))
    X_train = X_train.copy()
    X_train["event_time"] = train_df["event_time"].clip(lower=0.5)
    X_train["composite_event"] = train_df["composite_event"].astype(int)
    const_cols = [c for c in X_train.columns if c not in ("event_time", "composite_event") and X_train[c].nunique() <= 1]
    X_train = X_train.drop(columns=const_cols)
    X_test = X_test.drop(columns=[c for c in const_cols if c in X_test.columns])
    cph = CoxPHFitter(penalizer=0.1)
    cph.fit(X_train, duration_col="event_time", event_col="composite_event")
    return cph.predict_partial_hazard(X_test).values


def step2_paired_comparison(test_df, scores: dict) -> dict:
    epss = scores["EPSS-alone"]
    out = {}
    for name, s in scores.items():
        if name == "EPSS-alone":
            continue
        out[name] = paired_bootstrap_compare(test_df, s, epss, label=f"{name} vs EPSS", n_resamples=200)
    return out


def step3_trajectory_ablation(train_df, test_df):
    full_score = _fit_xgb(train_df, test_df, MODEL_FEATURE_COLUMNS)
    b_cols = [c for c in MODEL_FEATURE_COLUMNS if c not in TRAJECTORY_FEATURES]
    b_score = _fit_xgb(train_df, test_df, b_cols)
    c_cols = [c for c in MODEL_FEATURE_COLUMNS if c not in EPSS_FEATURES]
    c_score = _fit_xgb(train_df, test_df, c_cols)

    duration = test_df["event_time"].clip(lower=0.5).values
    event = test_df["composite_event"].values.astype(int)

    results = {}
    for name, s in [("a) full model", full_score), ("b) minus trajectory", b_score), ("c) minus all EPSS", c_score)]:
        results[name] = {
            "cindex": fast_concordance_index(duration, s, event),
            "recall_10pct": recall_at_budget(s, event, 0.10),
        }

    paired_a_minus_b = paired_bootstrap_compare(test_df, full_score, b_score, label="a minus b", n_resamples=200)
    results["paired_a_minus_b"] = paired_a_minus_b
    return results


def step4_blind_spot_catch_rate(test_df, scores: dict, n_resamples=200, seed=20260922):
    epss = scores["EPSS-alone"]
    cve_ids = test_df["cve_id"].values
    event = test_df["composite_event"].values.astype(int)
    unique_cves = np.unique(cve_ids)
    cve_row_index = _build_cve_row_index(cve_ids)
    rng = np.random.default_rng(seed)

    def catch_rate(risk_model, risk_epss, ev):
        n_top = max(1, int(np.ceil(len(risk_epss) * 0.10)))
        epss_top = set(np.argsort(-risk_epss)[:n_top])
        positives = np.where(ev == 1)[0]
        blind_spots = [i for i in positives if i not in epss_top]
        if not blind_spots:
            return np.nan
        model_top = set(np.argsort(-risk_model)[:n_top])
        caught = sum(1 for i in blind_spots if i in model_top)
        return caught / len(blind_spots)

    out = {}
    for name, s in scores.items():
        if name == "EPSS-alone":
            continue
        point = catch_rate(s, epss, event)
        samples = []
        for i in range(n_resamples):
            row_idx = _resampled_row_index(cve_row_index, unique_cves, rng)
            samples.append(catch_rate(s[row_idx], epss[row_idx], event[row_idx]))
            if (i + 1) % 20 == 0:
                log_with_fields(logger, logging.INFO, "blind-spot bootstrap progress", model=name, resample=i + 1)
        arr = np.array(samples)
        arr = arr[~np.isnan(arr)]
        out[name] = {
            "point": point, "mean": float(np.mean(arr)),
            "ci_lower": float(np.percentile(arr, 2.5)), "ci_upper": float(np.percentile(arr, 97.5)), "n": len(arr),
        }
    return out


def step5_rsf_variance(train_df, test_df):
    duration = test_df["event_time"].clip(lower=0.5).values
    event = test_df["composite_event"].values.astype(int)
    results = []
    for rs in [0, 1, 2]:
        score = _fit_rsf(train_df, test_df, MODEL_FEATURE_COLUMNS, random_state=rs)
        c = fast_concordance_index(duration, score, event)
        results.append({"random_state": rs, "test_cindex": c})
        log_with_fields(logger, logging.INFO, "rsf variance run", random_state=rs, test_cindex=c)
    cs = [r["test_cindex"] for r in results]
    return {"runs": results, "spread": max(cs) - min(cs), "mean": float(np.mean(cs)), "std": float(np.std(cs))}


def main():
    cfg = get_config()
    train_df, test_df = _prep()

    log_with_fields(logger, logging.INFO, "fitting final models for comparison")
    scores = {
        "EPSS-alone": test_df["epss_pct_now"].fillna(0).values,
        "Cox": _fit_cox(train_df, test_df, MODEL_FEATURE_COLUMNS),
        "RSF": _fit_rsf(train_df, test_df, MODEL_FEATURE_COLUMNS, random_state=RSF_CONFIG.get("random_state", 0)),
        "XGBoost-AFT": _fit_xgb(train_df, test_df, MODEL_FEATURE_COLUMNS),
    }

    log_with_fields(logger, logging.INFO, "STEP 2: paired comparison vs EPSS")
    step2 = step2_paired_comparison(test_df, scores)

    log_with_fields(logger, logging.INFO, "STEP 3: trajectory ablation")
    step3 = step3_trajectory_ablation(train_df, test_df)

    log_with_fields(logger, logging.INFO, "STEP 4: blind-spot catch rate")
    step4 = step4_blind_spot_catch_rate(test_df, scores)

    log_with_fields(logger, logging.INFO, "STEP 5: RSF variance")
    step5 = step5_rsf_variance(train_df, test_df)

    out = {"step2_paired_vs_epss": step2, "step3_trajectory_ablation": step3,
           "step4_blind_spot_catch_rate": step4, "step5_rsf_variance": step5}
    print(json.dumps(out, indent=2, default=str))
    with open(cfg.project_root / "scratch" / "final_comparison_results.json", "w") as f:
        json.dump(out, f, indent=2, default=str)


if __name__ == "__main__":
    main()
