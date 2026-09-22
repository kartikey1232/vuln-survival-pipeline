"""
Full evaluation of the rebuilt (publication-time-only) Cox baseline vs the
EPSS-alone reference, with whole-CVE bootstrap confidence intervals.
One-off diagnostic, not a pipeline stage.

Bootstrap design: fit the Cox model ONCE on the real training set, score
every test row ONCE, then resample TEST CVE IDs (not rows) with
replacement 200 times — each resample takes every row belonging to each
resampled CVE (so a CVE's up-to-3 landmark rows always move together) and
recomputes the metric on that resampled row set. This is the standard,
cheap way to bootstrap a fixed model's evaluation metric; it does NOT
refit the model per resample.

Usage: python -m scripts.eda.cox_rebuilt_eval
"""

from __future__ import annotations

import json

import numpy as np
import pandas as pd
from lifelines import CoxPHFitter
from lifelines.utils import concordance_index

from config.config_schema import get_config
from database.engine import get_engine
from scripts.eda.cox_preliminary import BOOLEAN, CATEGORICAL, _prepare
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS

N_BOOTSTRAP = 200
BUDGETS = [0.01, 0.05, 0.10]
RNG = np.random.default_rng(20260922)


def _fit(train: pd.DataFrame, feature_cols: list[str]) -> tuple[CoxPHFitter, list[str]]:
    cats = [c for c in CATEGORICAL if c in feature_cols]
    train_X = pd.get_dummies(train[feature_cols], columns=cats, drop_first=True)
    train_X["event_time"] = train["event_time"].clip(lower=0.5)
    train_X["composite_event"] = train["composite_event"].astype(int)
    const_cols = [c for c in train_X.columns if c not in ("event_time", "composite_event") and train_X[c].nunique() <= 1]
    train_X = train_X.drop(columns=const_cols)
    cph = CoxPHFitter(penalizer=0.1)
    cph.fit(train_X, duration_col="event_time", event_col="composite_event")
    return cph, list(train_X.columns)


def _score_test(cph: CoxPHFitter, test: pd.DataFrame, feature_cols: list[str], train_cols: list[str]) -> np.ndarray:
    cats = [c for c in CATEGORICAL if c in feature_cols]
    test_X = pd.get_dummies(test[feature_cols], columns=cats, drop_first=True)
    test_X = test_X.reindex(columns=[c for c in train_cols if c not in ("event_time", "composite_event")], fill_value=0)
    return cph.predict_partial_hazard(test_X).values


def _recall_at_budget(risk_score: np.ndarray, event: np.ndarray, budget: float) -> float:
    n_top = max(1, int(np.ceil(len(risk_score) * budget)))
    order = np.argsort(-risk_score)
    top_idx = order[:n_top]
    total_events = event.sum()
    if total_events == 0:
        return np.nan
    return event[top_idx].sum() / total_events


def _bootstrap(test: pd.DataFrame, model_score: np.ndarray, epss_score: np.ndarray) -> dict:
    cve_ids = test["cve_id"].values
    duration = test["event_time"].clip(lower=0.5).values
    event = test["composite_event"].values.astype(int)
    unique_cves = np.unique(cve_ids)

    metrics = {
        "model_cindex": [], "epss_cindex": [],
        **{f"model_recall_{int(b*100)}pct": [] for b in BUDGETS},
        **{f"epss_recall_{int(b*100)}pct": [] for b in BUDGETS},
    }

    for _ in range(N_BOOTSTRAP):
        sample_cves = RNG.choice(unique_cves, size=len(unique_cves), replace=True)
        # build row indices: every row of every resampled CVE (duplicates included)
        cve_to_rows = {}
        idx = np.arange(len(test))
        for cve in np.unique(sample_cves):
            cve_to_rows[cve] = idx[cve_ids == cve]
        row_idx = np.concatenate([np.tile(cve_to_rows[c], 1) for c in sample_cves])

        d = duration[row_idx]
        e = event[row_idx]
        ms = model_score[row_idx]
        es = epss_score[row_idx]

        metrics["model_cindex"].append(concordance_index(d, -ms, e))
        metrics["epss_cindex"].append(concordance_index(d, -es, e))
        for b in BUDGETS:
            metrics[f"model_recall_{int(b*100)}pct"].append(_recall_at_budget(ms, e, b))
            metrics[f"epss_recall_{int(b*100)}pct"].append(_recall_at_budget(es, e, b))

    return metrics


def _summarize(values: list[float]) -> tuple[float, float, float]:
    arr = np.array(values)
    arr = arr[~np.isnan(arr)]
    return float(np.mean(arr)), float(np.percentile(arr, 2.5)), float(np.percentile(arr, 97.5))


def main() -> None:
    cfg = get_config()
    engine = get_engine()

    df = pd.read_sql(
        "SELECT * FROM training.training_dataset WHERE dataset_version = 'landmark_v20260922'",
        engine, parse_dates=["as_of_date"],
    )
    df["landmark_day"] = df["checkpoint_day"]
    df["split"] = np.where(df["as_of_date"] < pd.Timestamp("2025-01-01"), "train", "test")
    df = _prepare(df)

    train = df[df["split"] == "train"].copy()
    test = df[df["split"] == "test"].copy()

    numeric_cols = [c for c in MODEL_FEATURE_COLUMNS if c not in CATEGORICAL and c not in BOOLEAN]
    for c in numeric_cols:
        median = train[c].median()
        train[c] = train[c].fillna(median)
        test[c] = test[c].fillna(median)

    results = {}

    # --- pooled full model vs EPSS-alone ---
    cph, train_cols = _fit(train, MODEL_FEATURE_COLUMNS)
    model_score_test = _score_test(cph, test, MODEL_FEATURE_COLUMNS, train_cols)
    epss_score_test = test["epss_pct_now"].values

    pooled_boot = _bootstrap(test, model_score_test, epss_score_test)
    results["pooled"] = {k: _summarize(v) for k, v in pooled_boot.items()}
    results["pooled"]["train_cindex_point"] = cph.concordance_index_
    results["pooled"]["test_cindex_point_model"] = concordance_index(
        test["event_time"].clip(lower=0.5), -model_score_test, test["composite_event"].astype(int)
    )
    results["pooled"]["test_cindex_point_epss"] = concordance_index(
        test["event_time"].clip(lower=0.5), -epss_score_test, test["composite_event"].astype(int)
    )

    # --- per-landmark ---
    results["per_landmark"] = {}
    for landmark in [7, 14, 30]:
        tr_lm = train[train["landmark_day"] == landmark]
        te_lm = test[test["landmark_day"] == landmark]
        cph_lm, cols_lm = _fit(tr_lm, MODEL_FEATURE_COLUMNS)
        ms = _score_test(cph_lm, te_lm, MODEL_FEATURE_COLUMNS, cols_lm)
        es = te_lm["epss_pct_now"].values
        boot = _bootstrap(te_lm, ms, es)
        results["per_landmark"][landmark] = {k: _summarize(v) for k, v in boot.items()}
        results["per_landmark"][landmark]["train_cindex_point"] = cph_lm.concordance_index_
        results["per_landmark"][landmark]["n_train"] = len(tr_lm)
        results["per_landmark"][landmark]["n_test"] = len(te_lm)
        results["per_landmark"][landmark]["events_train"] = int(tr_lm["composite_event"].sum())
        results["per_landmark"][landmark]["events_test"] = int(te_lm["composite_event"].sum())

    # --- ablation ---
    EPSS_F = [c for c in MODEL_FEATURE_COLUMNS if c.startswith("epss") or c == "landmark_day" or c == "days_to_first_epss"]
    CVSS_F = [
        "cvss_base_score", "attack_vector", "attack_complexity", "privileges_required",
        "user_interaction", "confidentiality_impact", "integrity_impact", "availability_impact",
        "cvss_version", "cvss_cna_missing",
    ]
    CWE_F = ["cwe_kev_rate_expanding"]
    CNA_F = ["cna_kev_rate_expanding"]

    ablation_groups = {
        "EPSS only": EPSS_F,
        "+ CNA CVSS": EPSS_F + CVSS_F,
        "+ CNA CWE": EPSS_F + CVSS_F + CWE_F,
        "+ CNA identity": EPSS_F + CVSS_F + CWE_F + CNA_F,
    }
    results["ablation"] = {}
    for name, cols in ablation_groups.items():
        cph_a, cols_a = _fit(train, cols)
        ms = _score_test(cph_a, test, cols, cols_a)
        train_c = cph_a.concordance_index_
        test_c = concordance_index(test["event_time"].clip(lower=0.5), -ms, test["composite_event"].astype(int))
        results["ablation"][name] = {"train_cindex": train_c, "test_cindex": test_c}

    print(json.dumps(results, indent=2, default=str))
    with open(cfg.project_root / "scratch" / "cox_rebuilt_eval_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)


if __name__ == "__main__":
    main()
