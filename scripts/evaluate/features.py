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


def encode_against(df: pd.DataFrame, model_columns: list[str], *, encoding: str = "corrected") -> pd.DataFrame:
    """Encode a non-training frame (test, a request) against a frozen
    model's columns. encoding="original" is the path every number recorded
    before 2026-10-21 was computed with (one_hot on `df` itself, then
    aligned), kept so those numbers stay reproducible; "corrected" is
    encode_for_model. See docs/results_corrected_encoding.md."""
    if encoding == "original":
        return one_hot(df, MODEL_FEATURE_COLUMNS).reindex(columns=model_columns, fill_value=0)
    if encoding == "corrected":
        return encode_for_model(df, model_columns)
    raise ValueError(f"encoding must be 'original' or 'corrected', got {encoding!r}")


def encode_for_model(df: pd.DataFrame, model_columns: list[str]) -> pd.DataFrame:
    """One-hot encode against a FROZEN model's column list, correct for any
    number of rows. `one_hot(df, ..., align_to=...)` is not: it drops the
    first category OF `df` before aligning, so when `df`'s first category
    differs from the training frame's (on test: cvss_version 3.0 vs 2.0,
    confidentiality/availability_impact HIGH vs COMPLETE,
    epss_model_version_at_asof v2023.03.01 vs unversioned) those rows are
    encoded as the training reference category, and a single row always
    loses its own category. `one_hot` is kept unchanged: it is correct for
    encoding the training frame itself, and every number recorded before
    2026-10-21 was produced with it (encode_against(encoding="original"))."""
    cats = [c for c in CATEGORICAL if c in MODEL_FEATURE_COLUMNS]
    X = pd.get_dummies(df[MODEL_FEATURE_COLUMNS], columns=cats, drop_first=False)
    return X.reindex(columns=model_columns, fill_value=0).astype(float)
