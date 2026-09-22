"""
Shared feature preparation for every model (Cox, RSF, XGBoost-AFT) —
one definition of which columns are categorical/boolean/numeric and how
missing values are imputed, so the three models are compared on
identically-prepared inputs.
"""

from __future__ import annotations

import pandas as pd

from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS

CATEGORICAL = [
    "attack_vector", "attack_complexity", "privileges_required", "user_interaction",
    "confidentiality_impact", "integrity_impact", "availability_impact",
    "cvss_version", "epss_model_version_at_asof", "landmark_day",
]
BOOLEAN = ["cvss_cna_missing", "exploit_published_by_asof", "epss_pct_7d_ago_missing"]
NUMERIC = [c for c in MODEL_FEATURE_COLUMNS if c not in CATEGORICAL and c not in BOOLEAN]


def prepare_raw(df: pd.DataFrame) -> pd.DataFrame:
    """Fills the two structural missing-value cases that have a defined
    meaning (paired with their own _missing flag, already a feature) and
    casts categorical/boolean dtypes. Does NOT impute numeric medians —
    that must be fit-set-only, done by the caller after this."""
    df = df.copy()
    df["epss_pct_7d_ago"] = df["epss_pct_7d_ago"].fillna(0.0)
    df["epss_pct_delta_7d"] = df["epss_pct_delta_7d"].fillna(0.0)
    df["days_to_first_exploit"] = df["days_to_first_exploit"].fillna(0.0)

    for c in CATEGORICAL:
        df[c] = df[c].astype(object).where(df[c].notna(), "missing").astype(str)
    for c in BOOLEAN:
        df[c] = df[c].astype(int)
    return df


def impute_numeric(train: pd.DataFrame, *others: pd.DataFrame) -> tuple[pd.DataFrame, ...]:
    """Median-impute NUMERIC columns, computed on `train` ONLY, applied to
    train and every frame in `others` (e.g. val, test) — never let a later
    split's values leak into the imputation itself."""
    train = train.copy()
    other_copies = [o.copy() for o in others]
    for c in NUMERIC:
        median = train[c].median()
        train[c] = train[c].fillna(median)
        for o in other_copies:
            o[c] = o[c].fillna(median)
    return (train, *other_copies)


def one_hot(df: pd.DataFrame, feature_cols: list[str], align_to: list[str] | None = None) -> pd.DataFrame:
    cats = [c for c in CATEGORICAL if c in feature_cols]
    X = pd.get_dummies(df[feature_cols], columns=cats, drop_first=True)
    if align_to is not None:
        X = X.reindex(columns=align_to, fill_value=0)
    return X
