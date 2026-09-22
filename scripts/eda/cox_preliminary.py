"""
PRELIMINARY, UNTUNED Cox PH baseline on the landmark training data —
a sanity check, not a candidate model. One-off, not a pipeline stage.

Simplification (documented, not hidden): a CVE contributes up to 3 rows
(one per landmark it's eligible for), pooled here as if independent
observations. This violates the Cox model's independence assumption and
is NOT how a real model for this project should be fit — it's adequate
for a quick "does anything blow up / does discrimination look sane"
check, nothing more.

Usage: python -m scripts.eda.cox_preliminary
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from lifelines import CoxPHFitter

from config.config_schema import get_config
from database.engine import get_engine
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS

CATEGORICAL = [
    "attack_vector", "attack_complexity", "privileges_required", "user_interaction",
    "confidentiality_impact", "integrity_impact", "availability_impact",
    "cvss_version", "epss_model_version_at_asof", "landmark_day",
]
BOOLEAN = ["cvss_cna_missing", "exploit_published_by_asof", "epss_pct_7d_ago_missing"]


def _prepare(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    # impute: numeric -> median (computed on TRAIN only, applied to both — done by caller),
    # missing epss_pct_7d_ago / epss_pct_delta_7d -> 0 (paired with the _missing flag already
    # present as a feature, so the model can still distinguish these rows)
    df["epss_pct_7d_ago"] = df["epss_pct_7d_ago"].fillna(0.0)
    df["epss_pct_delta_7d"] = df["epss_pct_delta_7d"].fillna(0.0)
    df["days_to_first_exploit"] = df["days_to_first_exploit"].fillna(0.0)

    for c in CATEGORICAL:
        df[c] = df[c].astype(object).where(df[c].notna(), "missing").astype(str)
    for c in BOOLEAN:
        df[c] = df[c].astype(int)

    return df


def main() -> None:
    cfg = get_config()
    engine = get_engine()

    df = pd.read_sql(
        "SELECT * FROM training.training_dataset", engine, parse_dates=["as_of_date"],
    )
    df["landmark_day"] = df["checkpoint_day"]
    df["split"] = np.where(df["as_of_date"] < pd.Timestamp("2025-01-01"), "train", "test")

    feature_cols = list(MODEL_FEATURE_COLUMNS)  # landmark_day already included
    numeric_cols = [
        c for c in feature_cols
        if c not in CATEGORICAL and c not in BOOLEAN
    ]

    df = _prepare(df)

    train = df[df["split"] == "train"].copy()
    test = df[df["split"] == "test"].copy()

    for c in numeric_cols:
        median = train[c].median()
        train[c] = train[c].fillna(median)
        test[c] = test[c].fillna(median)

    train_X = pd.get_dummies(train[feature_cols], columns=CATEGORICAL, drop_first=True)
    test_X = pd.get_dummies(test[feature_cols], columns=CATEGORICAL, drop_first=True)
    test_X = test_X.reindex(columns=train_X.columns, fill_value=0)  # align dummy columns

    train_X["event_time"] = train["event_time"].clip(lower=0.5)  # CoxPH needs duration > 0
    train_X["composite_event"] = train["composite_event"].astype(int)
    test_X["event_time"] = test["event_time"].clip(lower=0.5)
    test_X["composite_event"] = test["composite_event"].astype(int)

    # drop any dummy column with zero variance in train (CoxPH chokes on these)
    const_cols = [c for c in train_X.columns if c not in ("event_time", "composite_event") and train_X[c].nunique() <= 1]
    train_X = train_X.drop(columns=const_cols)
    test_X = test_X.drop(columns=const_cols)

    cph = CoxPHFitter(penalizer=0.1)
    cph.fit(train_X, duration_col="event_time", event_col="composite_event")

    train_cindex = cph.concordance_index_
    test_cindex = cph.score(test_X, scoring_method="concordance_index")

    print(f"train n={len(train_X)} events={int(train_X['composite_event'].sum())}")
    print(f"test  n={len(test_X)} events={int(test_X['composite_event'].sum())}")
    print(f"train C-index: {train_cindex:.4f}")
    print(f"test  C-index: {test_cindex:.4f}")
    if test_cindex > 0.85:
        print("!!! test C-index exceeds 0.85 — STOP, this indicates leakage, not success !!!")

    summary = cph.summary.copy()
    summary = summary.sort_values("p")

    with open(cfg.project_root / "docs" / "cox_preliminary.md", "w") as f:
        f.write("# Preliminary Cox PH baseline — PRELIMINARY, UNTUNED\n\n")
        f.write(
            "Sanity-check model only, not a candidate for deployment or comparison. "
            "Simplification: a CVE contributes up to 3 rows (one per eligible landmark), "
            "pooled here as independent observations, which violates the Cox model's "
            "independence assumption — see module docstring in "
            "`scripts/eda/cox_preliminary.py`.\n\n"
        )
        f.write(f"- Train: n={len(train_X)}, events={int(train_X['composite_event'].sum())}\n")
        f.write(f"- Test: n={len(test_X)}, events={int(test_X['composite_event'].sum())}\n")
        f.write(f"- **Train C-index: {train_cindex:.4f}**\n")
        f.write(f"- **Test C-index: {test_cindex:.4f}**\n\n")
        if test_cindex > 0.85:
            f.write("**STOP — test C-index exceeds 0.85, which indicates leakage, not a good model.**\n\n")
        f.write("## Coefficients (sorted by p-value)\n\n")
        f.write(summary[["coef", "exp(coef)", "se(coef)", "p"]].to_markdown())
        f.write("\n")

    print("wrote docs/cox_preliminary.md")


if __name__ == "__main__":
    main()
