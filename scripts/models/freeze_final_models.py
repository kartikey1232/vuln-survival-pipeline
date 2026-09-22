"""
Freezes the final chosen Cox, RSF, and XGBoost-AFT models to models/, each
refit ONCE on the full train set with its already-chosen config (no
tuning happens here -- see scripts/models/{cox,rsf,xgboost_aft}.py for
that). Writes a metadata JSON per model with the git commit hash, data
cutoff, feature list, hyperparameters, and test metrics.

Per project rule: no further tuning of any model against test results
after this point.

Usage: python -m scripts.models.freeze_final_models
"""

from __future__ import annotations

import json
import pickle
import subprocess
from datetime import datetime, timezone

from sksurv.util import Surv

from config.config_schema import get_config
from scripts.evaluate.common import fast_concordance_index, recall_at_budget
from scripts.evaluate.final_comparison import RSF_CONFIG, XGB_CONFIG, _fit_cox, _prep
from scripts.evaluate.features import one_hot
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS
from scripts.models.xgboost_aft import _to_dmatrix

import xgboost as xgb
from lifelines import CoxPHFitter
from sksurv.ensemble import RandomSurvivalForest


def _git_commit_hash() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()


def _test_metrics(duration, event, risk_score) -> dict:
    return {
        "test_cindex": fast_concordance_index(duration, risk_score, event),
        "test_recall_5pct": recall_at_budget(risk_score, event, 0.05),
        "test_recall_10pct": recall_at_budget(risk_score, event, 0.10),
    }


def main():
    cfg = get_config()
    models_dir = cfg.project_root / "models"
    models_dir.mkdir(exist_ok=True)

    train_df, test_df = _prep()
    duration = test_df["event_time"].clip(lower=0.5).values
    event = test_df["composite_event"].values.astype(int)

    commit_hash = _git_commit_hash()
    common_meta = {
        "git_commit_hash": commit_hash,
        "frozen_at_utc": datetime.now(timezone.utc).isoformat(),
        "data_cutoff": "2025-01-01 (train/test split); test observed through 2026-09-20",
        "dataset_version": "landmark_v20260922",
        "feature_list": MODEL_FEATURE_COLUMNS,
        "train_rows": len(train_df),
        "train_cves": int(train_df["cve_id"].nunique()),
        "test_rows": len(test_df),
        "test_cves": int(test_df["cve_id"].nunique()),
    }

    # --- Cox ---
    X_train = one_hot(train_df, MODEL_FEATURE_COLUMNS)
    X_test = one_hot(test_df, MODEL_FEATURE_COLUMNS, align_to=list(X_train.columns))
    X_train_cox_raw = X_train.copy()
    X_train_cox_raw["event_time"] = train_df["event_time"].clip(lower=0.5)
    X_train_cox_raw["composite_event"] = train_df["composite_event"].astype(int)
    const_cols = [c for c in X_train_cox_raw.columns if c not in ("event_time", "composite_event") and X_train_cox_raw[c].nunique() <= 1]
    X_train_cox = X_train_cox_raw.drop(columns=const_cols)
    X_test_cox = X_test.drop(columns=[c for c in const_cols if c in X_test.columns])
    cph = CoxPHFitter(penalizer=0.1)
    cph.fit(X_train_cox, duration_col="event_time", event_col="composite_event")
    cox_risk = cph.predict_partial_hazard(X_test_cox).values
    with open(models_dir / "cox_final.pkl", "wb") as f:
        pickle.dump({"model": cph, "one_hot_columns": list(X_train.columns), "dropped_const_cols": const_cols}, f)
    cox_meta = {
        **common_meta,
        "model_type": "CoxPHFitter (lifelines)",
        "hyperparameters": {"penalizer": 0.1},
        "test_metrics": _test_metrics(duration, event, cox_risk),
    }
    with open(models_dir / "cox_final_metadata.json", "w") as f:
        json.dump(cox_meta, f, indent=2, default=str)
    print("Cox frozen:", cox_meta["test_metrics"])

    # --- RSF ---
    y_train = Surv.from_arrays(event=train_df["composite_event"].values.astype(bool),
                                time=train_df["event_time"].values.astype(float))
    rsf = RandomSurvivalForest(
        n_estimators=RSF_CONFIG["n_estimators"], min_samples_leaf=RSF_CONFIG["min_samples_leaf"],
        max_features=RSF_CONFIG["max_features"], max_samples=min(RSF_CONFIG["max_samples"], len(X_train)),
        low_memory=True, n_jobs=-1, random_state=0,
    )
    rsf.fit(X_train, y_train)
    rsf_risk = rsf.predict(X_test)
    with open(models_dir / "rsf_final.pkl", "wb") as f:
        pickle.dump({"model": rsf, "one_hot_columns": list(X_train.columns)}, f)
    rsf_meta = {
        **common_meta,
        "model_type": "RandomSurvivalForest (sksurv)",
        "hyperparameters": {**RSF_CONFIG, "random_state": 0, "n_jobs": -1, "low_memory": True},
        "test_metrics": _test_metrics(duration, event, rsf_risk),
        "known_limitation": "Not exactly reproducible even with random_state fixed under n_jobs=-1; "
                             "test C-index observed to vary by up to 0.0062 across seeds at this config "
                             "(see docs/model_comparison.md RSF run-to-run variance). Treat as approximate.",
    }
    with open(models_dir / "rsf_final_metadata.json", "w") as f:
        json.dump(rsf_meta, f, indent=2, default=str)
    print("RSF frozen:", rsf_meta["test_metrics"])

    # --- XGBoost-AFT ---
    xgb_duration = train_df["event_time"].values
    xgb_event = train_df["composite_event"].values.astype(bool)
    dtrain = _to_dmatrix(X_train, xgb_duration, xgb_event)
    params = {
        "objective": "survival:aft", "eval_metric": "aft-nloglik",
        "aft_loss_distribution": XGB_CONFIG["aft_loss_distribution"],
        "aft_loss_distribution_scale": XGB_CONFIG["aft_loss_distribution_scale"],
        "max_depth": XGB_CONFIG["max_depth"], "learning_rate": XGB_CONFIG["learning_rate"], "tree_method": "hist",
    }
    booster = xgb.train(params, dtrain, num_boost_round=XGB_CONFIG["n_rounds"])
    xgb_pred_time = booster.predict(xgb.DMatrix(X_test))
    xgb_risk = -xgb_pred_time
    booster.save_model(str(models_dir / "xgboost_aft_final.json"))
    with open(models_dir / "xgboost_aft_final_columns.json", "w") as f:
        json.dump({"one_hot_columns": list(X_train.columns)}, f, indent=2)
    xgb_meta = {
        **common_meta,
        "model_type": "XGBoost survival:aft",
        "hyperparameters": params | {"num_boost_round": XGB_CONFIG["n_rounds"]},
        "test_metrics": _test_metrics(duration, event, xgb_risk),
        "note": "risk_score = -predicted_time (AFT predicts time; higher time = lower risk)",
    }
    with open(models_dir / "xgboost_aft_final_metadata.json", "w") as f:
        json.dump(xgb_meta, f, indent=2, default=str)
    print("XGBoost-AFT frozen:", xgb_meta["test_metrics"])


if __name__ == "__main__":
    main()
