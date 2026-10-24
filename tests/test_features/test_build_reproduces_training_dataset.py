"""
Regression guard: an in-memory build() (default train_test_cutoff),
rounded with round_to_storage(), against the stored
training.training_dataset on every default-export test row. The frozen
models were fit on that table, and scripts/evaluate/rolling_origin.py
builds its folds from build() output, so any drift between the two (a
feature-code change, a data change, a dropped rounding step) fails here
instead of silently changing a fold.

Features and labels are checked separately:

- FEATURES must match bit for bit on every row, with no exceptions.
- LABELS must differ on exactly the rows recorded in
  tests/fixtures/kev_label_diffs_20261021.json, and nowhere else: the
  stored table was built from KEV catalog 2026.08.06, build() now reads
  2026.10.21, and 6 test CVEs listed in between change from censored to
  event. The test fails if a row outside the record differs AND if a
  recorded row stops differing (e.g. the stored labels were updated
  without updating the record).

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
from scripts.evaluate.data_splits import DATA_CUTOFF, DATASET_VERSION, VAL_CUTOFF
from scripts.evaluate.label_corrections import known_diffs, load_record, set_labels
from scripts.features.build_landmark_dataset import (
    EXPORT_COLUMNS,
    STORAGE_ROUNDING,
    build,
    round_to_storage,
)

N_TEST_ROWS = 178_756
KEY = ["cve_id", "landmark_day"]
# event_observed is stored as composite_event; split is derived, not stored
LABEL_COLUMNS = ["event_time", "event_observed"]
FEATURE_COLUMNS = [c for c in EXPORT_COLUMNS if c not in KEY + LABEL_COLUMNS + ["split"]]


def _stored_test_rows(engine) -> pd.DataFrame:
    df = pd.read_sql(
        text("SELECT * FROM training.training_dataset WHERE dataset_version = :v AND as_of_date >= :cutoff"),
        engine, params={"v": DATASET_VERSION, "cutoff": VAL_CUTOFF.date()}, parse_dates=["as_of_date"],
    )
    return df.rename(columns={"checkpoint_day": "landmark_day", "composite_event": "event_observed"})


def _same(a: pd.Series, b: pd.Series) -> np.ndarray:
    """Exact equality per row. Floats are compared bit for bit (NaN equal
    to NaN, -0.0 not equal to 0.0); everything else by value."""
    if pd.api.types.is_float_dtype(a) or pd.api.types.is_float_dtype(b):
        a, b = a.astype(float).to_numpy(), b.astype(float).to_numpy()
        both_nan = np.isnan(a) & np.isnan(b)
        return both_nan | (~np.isnan(a) & ~np.isnan(b) & (a.view(np.uint64) == b.view(np.uint64)))
    return ((a == b) | (a.isna() & b.isna())).to_numpy()


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


@pytest.fixture(scope="module")
def merged(stored_and_built) -> pd.DataFrame:
    stored, built = stored_and_built
    built = round_to_storage(built)
    assert len(stored) == len(built) == N_TEST_ROWS
    m = stored.merge(built, on=KEY, suffixes=("_stored", "_built"), validate="one_to_one")
    assert len(m) == N_TEST_ROWS, "row sets differ"
    return m


@pytest.mark.slow
def test_default_build_reproduces_stored_test_features_exactly(merged):
    assert FEATURE_COLUMNS, "no feature columns compared"
    for c in FEATURE_COLUMNS:
        same = _same(merged[f"{c}_stored"], merged[f"{c}_built"])
        assert same.all(), f"{c}: {int((~same).sum())} of {N_TEST_ROWS} rows differ"


@pytest.mark.slow
def test_stored_test_labels_differ_from_build_exactly_on_recorded_rows(merged):
    differs = np.zeros(len(merged), dtype=bool)
    for c in LABEL_COLUMNS:
        differs |= ~_same(merged[f"{c}_stored"], merged[f"{c}_built"])
    observed = set(map(tuple, merged.loc[differs, KEY].astype({"landmark_day": int}).to_numpy().tolist()))
    diffs = known_diffs()
    recorded = set(map(tuple, diffs[KEY].to_numpy().tolist()))

    assert not observed - recorded, f"labels differ on rows not in the record: {sorted(observed - recorded)}"
    assert not recorded - observed, f"recorded rows whose labels no longer differ: {sorted(recorded - observed)}"

    # and they differ in exactly the recorded way: stored = censored at the
    # cutoff, built = event at the listing date in the later catalog
    rows = merged[differs].set_index(KEY).sort_index()
    rec = diffs.set_index(KEY).sort_index()
    assert (rows["as_of_date_stored"] == rec["as_of_date"]).all()
    assert (rows["event_time_stored"].to_numpy() == rec["stored_event_time"].to_numpy()).all()
    assert (rows["event_observed_stored"].to_numpy() == rec["stored_event_observed"].to_numpy()).all()
    assert (rows["event_time_built"].to_numpy() == rec["corrected_event_time"].to_numpy()).all()
    assert (rows["event_observed_built"].to_numpy() == rec["corrected_event_observed"].to_numpy()).all()


def test_label_record_is_internally_consistent():
    """DB-free: every recorded row is censored at the test cutoff in its
    stored label and an event at its CVE's listing date in its corrected
    one, and every listing date falls between the two catalogs."""
    record = load_record()
    d = known_diffs()
    assert record["test_label_cutoff"] == str(DATA_CUTOFF.date())
    assert d["stored_event_time"].tolist() == (DATA_CUTOFF - d["as_of_date"]).dt.days.tolist()
    assert not d["stored_event_observed"].any()
    assert d["corrected_event_time"].tolist() == (d["kev_date_added"] - d["as_of_date"]).dt.days.tolist()
    assert d["corrected_event_observed"].all()
    stored_latest = pd.Timestamp(record["catalogs"]["stored"]["latest_date_added"])
    assert ((d["kev_date_added"] > stored_latest) & (d["kev_date_added"] <= DATA_CUTOFF)).all()
    assert len(d) == len(d.drop_duplicates(KEY)) == record["n_rows"]


def test_set_labels_round_trips_and_rejects_unknown_labels():
    d = known_diffs()
    frame = pd.DataFrame({
        "cve_id": list(d["cve_id"]) + ["CVE-2025-00001"], "landmark_day": list(d["landmark_day"]) + [7],
        "as_of_date": list(d["as_of_date"]) + [pd.Timestamp("2025-06-01")],
        "event_time": list(d["stored_event_time"]) + [100], "composite_event": [False] * len(d) + [False],
    })
    corrected, n = set_labels(frame, "corrected", diffs=d)
    assert n == len(d)
    assert corrected["event_time"].tolist()[:-1] == d["corrected_event_time"].tolist()
    assert corrected["composite_event"].tolist() == [True] * len(d) + [False]
    assert corrected.iloc[-1].equals(frame.iloc[-1])
    back, _ = set_labels(corrected, "stored", diffs=d)
    pd.testing.assert_frame_equal(back, frame)

    bad = frame.copy()
    bad.loc[0, "event_time"] = 1  # neither recorded label (e.g. a train-censored row)
    with pytest.raises(ValueError, match="neither"):
        set_labels(bad, "corrected", diffs=d)


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
