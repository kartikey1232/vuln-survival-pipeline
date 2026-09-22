"""
fit/validation/test split for hyperparameter tuning, built on top of
training.training_dataset (dataset_version=landmark_v20260922 — the
publication-time/enrichment-leakage-fixed features).

- TEST: unchanged from training_dataset's existing test split (published
  >= 2025-01-01, censored at the real data cutoff 2026-09-20). Not
  touched until a model's hyperparameters are final.
- VALIDATION: existing train-split rows with published_date in
  [2024-07-01, 2024-12-31]. Their stored event_time/composite_event are
  reused as-is — training_dataset's original train-side censoring cutoff
  (2025-01-01) is EXACTLY validation's own censoring cutoff, so no
  relabeling is needed.
- FIT: existing train-split rows with published_date < 2024-07-01, but
  RELABELED with a 2024-07-01 censoring cutoff instead of the stored
  2025-01-01 one — reusing the stored labels here would leak validation-
  period KEV listings (anything between 2024-07-01 and 2025-01-01) into
  the labels a model "fit as of 2024-07-01" is allowed to see. Rows whose
  as_of_date already falls on/after 2024-07-01 are dropped entirely (same
  row-existence rule the original build applies for its own cutoff, just
  evaluated at the fit cutoff instead).

Row EXISTENCE (condition 1: not already KEV-listed by as_of_date) never
changes across these three sets — it's a physical fact independent of any
analysis cutoff — only the labels' censoring point does.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from database.engine import get_engine

DATASET_VERSION = "landmark_v20260922"
FIT_CUTOFF = pd.Timestamp("2024-07-01")
VAL_CUTOFF = pd.Timestamp("2025-01-01")  # == training_dataset's original train cutoff
DATA_CUTOFF = pd.Timestamp("2026-09-20")


@dataclass
class Splits:
    fit: pd.DataFrame
    val: pd.DataFrame
    test: pd.DataFrame


def _relabel(df: pd.DataFrame, cutoff: pd.Timestamp) -> pd.DataFrame:
    df = df.copy()
    event_observed = df["date_added"].notna() & (df["date_added"] <= cutoff)
    event_date = np.where(event_observed, df["date_added"], cutoff)
    event_date = pd.to_datetime(event_date)
    df["event_time"] = (event_date - df["as_of_date"]).dt.days
    df["composite_event"] = event_observed
    return df


def load_splits(*, dataset_version: str = DATASET_VERSION) -> Splits:
    engine = get_engine()
    df = pd.read_sql(
        "SELECT t.*, k.date_added FROM training.training_dataset t "
        "LEFT JOIN canonical.kev k ON k.cve_id = t.cve_id "
        f"WHERE t.dataset_version = '{dataset_version}'",
        engine, parse_dates=["as_of_date", "date_added"],
    )
    df["landmark_day"] = df["checkpoint_day"]
    df["published_date"] = df["as_of_date"] - pd.to_timedelta(df["landmark_day"], unit="D")

    is_orig_train = df["as_of_date"] < VAL_CUTOFF

    test = df[~is_orig_train].reset_index(drop=True)

    val_mask = is_orig_train & (df["published_date"] >= FIT_CUTOFF) & (df["published_date"] <= pd.Timestamp("2024-12-31"))
    val = df[val_mask].reset_index(drop=True)

    fit_mask = is_orig_train & (df["published_date"] < FIT_CUTOFF) & (df["as_of_date"] < FIT_CUTOFF)
    fit = _relabel(df[fit_mask], FIT_CUTOFF).reset_index(drop=True)

    return Splits(fit=fit, val=val, test=test)


if __name__ == "__main__":
    splits = load_splits()
    for name, d in [("fit", splits.fit), ("val", splits.val), ("test", splits.test)]:
        print(f"{name}: n={len(d)} cves={d['cve_id'].nunique()} events={int(d['composite_event'].sum())}")
