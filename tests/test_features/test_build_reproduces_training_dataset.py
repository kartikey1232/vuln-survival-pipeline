"""
Regression guard: an in-memory build() (default train_test_cutoff),
rounded with round_to_storage(), must reproduce the stored
training.training_dataset EXACTLY on every default-export test row. The
frozen models were fit on that table, and scripts/evaluate/rolling_origin.py
builds its folds from build() output, so any drift between the two (a
feature-code change, a data change, a dropped rounding step) fails here
instead of silently changing a fold.

This is the one test that reads the PRODUCTION database (read-only): the
stored landmark_v20260922 table and the raw data build() reads exist only
there, not in the empty test database the rest of the suite uses. It is
marked slow (a full build, ~1 minute) and skips if that dataset is absent.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from database.engine import get_engine
from scripts.evaluate.data_splits import DATASET_VERSION, VAL_CUTOFF
from scripts.features.build_landmark_dataset import (
    EXPORT_COLUMNS,
    STORAGE_ROUNDING,
    build,
    round_to_storage,
)

N_TEST_ROWS = 178_756
KEY = ["cve_id", "landmark_day"]
# event_observed is stored as composite_event; split is derived, not stored
COMPARED = [c for c in EXPORT_COLUMNS if c not in ("cve_id", "landmark_day", "split", "event_observed")]


def _stored_test_rows(engine) -> pd.DataFrame:
    df = pd.read_sql(
        text("SELECT * FROM training.training_dataset WHERE dataset_version = :v AND as_of_date >= :cutoff"),
        engine, params={"v": DATASET_VERSION, "cutoff": VAL_CUTOFF.date()}, parse_dates=["as_of_date"],
    )
    return df.rename(columns={"checkpoint_day": "landmark_day", "composite_event": "event_observed"})


@pytest.fixture(scope="module")
def stored_and_built() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Stored test rows and the UNROUNDED default build's test rows (one
    build for the module)."""
    try:
        stored = _stored_test_rows(get_engine())  # production, read-only
    except OperationalError as exc:
        pytest.skip(f"production database unavailable: {exc}")
    if stored.empty:
        pytest.skip(f"production database has no {DATASET_VERSION} rows")
    built = build()
    built = built[(built["split"] == "test") & ~built["spans_version_transition"]].reset_index(drop=True)
    return stored, built


@pytest.mark.slow
def test_default_build_reproduces_stored_test_rows_exactly(stored_and_built):
    stored, built = stored_and_built
    built = round_to_storage(built)
    assert len(stored) == len(built) == N_TEST_ROWS

    m = stored.merge(built, on=KEY, suffixes=("_stored", "_built"), validate="one_to_one")
    assert len(m) == N_TEST_ROWS, "row sets differ"

    for c in COMPARED + ["event_observed"]:
        a, b = m[f"{c}_stored"], m[f"{c}_built"]
        if pd.api.types.is_float_dtype(a) or pd.api.types.is_float_dtype(b):
            a, b = a.astype(float).to_numpy(), b.astype(float).to_numpy()
            same = (a == b) | (np.isnan(a) & np.isnan(b))  # exact: no tolerance
        else:
            same = ((a == b) | (a.isna() & b.isna())).to_numpy()
        assert same.all(), f"{c}: {int((~same).sum())} of {N_TEST_ROWS} rows differ"


@pytest.mark.slow
def test_rounding_is_what_makes_the_target_encodings_match(stored_and_built):
    """Documents WHY round_to_storage exists: without it the target
    encodings differ (by up to 5e-7) on almost every row. The other
    NUMERIC columns differ only by float noise (~1e-17), which the exact
    test above also catches."""
    stored, built = stored_and_built
    m = stored.merge(built, on=KEY, suffixes=("_stored", "_built"))
    for c in ("cwe_kev_rate_expanding", "cna_kev_rate_expanding"):
        assert c in STORAGE_ROUNDING
        diff = (m[f"{c}_stored"] - m[f"{c}_built"]).abs()
        assert (diff > 0).mean() > 0.99 and diff.max() <= 5e-7 + 1e-12
