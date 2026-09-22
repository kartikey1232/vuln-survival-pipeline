"""
HISTORICAL diagnostic — superseded by scripts/eda/cox_rebuilt_eval.py's
own ablation section, which runs against the rebuilt (publication-time-
only) features. This script's results (the vendor-feature-group ablation
that helped find the enrichment leak) are reported in
docs/enrichment_leakage.md; kept for reproducibility of that finding
against the pre-fix schema, not for re-running now — the feature groups
below reference the pre-fix column names.

Diagnostic ablation for the preliminary Cox baseline's suspiciously high
test C-index (0.8897 > 0.85 stop threshold, and > train's 0.8635). Refits
the same penalizer=0.1 CoxPHFitter on train with feature groups removed,
reporting test C-index for each. One-off diagnostic, not a pipeline stage.

Usage: python -m scripts.eda.cox_ablation
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from lifelines import CoxPHFitter

from database.engine import get_engine
from scripts.eda.cox_preliminary import BOOLEAN, CATEGORICAL, _prepare

EPSS_FEATURES = [
    "epss_pct_now", "epss_pct_7d_ago", "epss_pct_7d_ago_missing", "epss_pct_delta_7d",
    "epss_pct_first", "epss_pct_max_to_date", "days_to_first_epss", "epss_model_version_at_asof",
    "landmark_day",
]
CVSS_FEATURES = [
    "cvss_base_score", "attack_vector", "attack_complexity", "privileges_required",
    "user_interaction", "confidentiality_impact", "integrity_impact", "availability_impact",
    "cvss_version", "cvss_cna_missing",
]
CWE_FEATURES = ["cwe_kev_rate_expanding"]
CNA_FEATURES = ["cna_kev_rate_expanding"]
EXPLOIT_FEATURES = ["exploit_published_by_asof", "days_to_first_exploit"]

ALL_FEATURES = EPSS_FEATURES + CVSS_FEATURES + CWE_FEATURES + CNA_FEATURES + EXPLOIT_FEATURES

GROUPS = {
    "a) EPSS only": EPSS_FEATURES,
    "b) EPSS + CVSS": EPSS_FEATURES + CVSS_FEATURES,
    "c) EPSS + CVSS + CWE encoding": EPSS_FEATURES + CVSS_FEATURES + CWE_FEATURES,
    "d) All minus vendor_kev_rate_expanding/vendor_count/product_count": (
        EPSS_FEATURES + CVSS_FEATURES + CWE_FEATURES + EXPLOIT_FEATURES
    ),
    "e) All features (current)": ALL_FEATURES,
}


def _fit_and_score(train: pd.DataFrame, test: pd.DataFrame, feature_cols: list[str]) -> tuple[float, float]:
    cats = [c for c in CATEGORICAL if c in feature_cols]
    train_X = pd.get_dummies(train[feature_cols], columns=cats, drop_first=True)
    test_X = pd.get_dummies(test[feature_cols], columns=cats, drop_first=True)
    test_X = test_X.reindex(columns=train_X.columns, fill_value=0)

    train_X["event_time"] = train["event_time"].clip(lower=0.5)
    train_X["composite_event"] = train["composite_event"].astype(int)
    test_X["event_time"] = test["event_time"].clip(lower=0.5)
    test_X["composite_event"] = test["composite_event"].astype(int)

    const_cols = [c for c in train_X.columns if c not in ("event_time", "composite_event") and train_X[c].nunique() <= 1]
    train_X = train_X.drop(columns=const_cols)
    test_X = test_X.drop(columns=const_cols)

    cph = CoxPHFitter(penalizer=0.1)
    cph.fit(train_X, duration_col="event_time", event_col="composite_event")
    train_c = cph.concordance_index_
    test_c = cph.score(test_X, scoring_method="concordance_index")
    return train_c, test_c


def main() -> None:
    engine = get_engine()
    df = pd.read_sql("SELECT * FROM training.training_dataset", engine, parse_dates=["as_of_date"])
    df["landmark_day"] = df["checkpoint_day"]
    df["split"] = np.where(df["as_of_date"] < pd.Timestamp("2025-01-01"), "train", "test")
    df = _prepare(df)

    train = df[df["split"] == "train"].copy()
    test = df[df["split"] == "test"].copy()

    numeric_cols = [c for c in ALL_FEATURES if c not in CATEGORICAL and c not in BOOLEAN]
    for c in numeric_cols:
        median = train[c].median()
        train[c] = train[c].fillna(median)
        test[c] = test[c].fillna(median)

    print(f"{'group':<65} {'train C':>10} {'test C':>10}")
    results = []
    for name, cols in GROUPS.items():
        train_c, test_c = _fit_and_score(train, test, cols)
        print(f"{name:<65} {train_c:>10.4f} {test_c:>10.4f}")
        results.append((name, train_c, test_c))

    print()
    print("=== per-landmark C-index (full model, group e) ===")
    for landmark in sorted(df["landmark_day"].unique()):
        tr_lm = train[train["landmark_day"] == landmark]
        te_lm = test[test["landmark_day"] == landmark]
        train_c, test_c = _fit_and_score(tr_lm, te_lm, ALL_FEATURES)
        print(f"landmark={landmark}: train n={len(tr_lm)} events={int(tr_lm['composite_event'].sum())} "
              f"C={train_c:.4f} | test n={len(te_lm)} events={int(te_lm['composite_event'].sum())} C={test_c:.4f}")

    print()
    print("=== per-landmark C-index (EPSS-alone: epss_pct_now) ===")
    from lifelines.utils import concordance_index
    for landmark in sorted(df["landmark_day"].unique()):
        for split_name, split_df in [("train", train), ("test", test)]:
            sub = split_df[split_df["landmark_day"] == landmark]
            c = concordance_index(sub["event_time"].clip(lower=0.5), -sub["epss_pct_now"], sub["composite_event"])
            print(f"landmark={landmark} split={split_name}: n={len(sub)} events={int(sub['composite_event'].sum())} C={c:.4f}")


if __name__ == "__main__":
    main()
