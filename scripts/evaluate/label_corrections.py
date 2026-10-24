"""
Known label differences between training.training_dataset and a build
against the later KEV catalog, and an in-memory relabel that applies them.
training.training_dataset itself is never written to.

The record is tests/fixtures/kev_label_diffs_20261021.json: 6 test CVEs
added to KEV after the catalog the stored table was built from (2026.08.06)
and on or before the test label cutoff (2026-09-20), so the 2026.10.21
catalog turns their 18 default-export test rows from censored at the cutoff
into events at the listing date. Features are unaffected
(tests/test_features/test_build_reproduces_training_dataset.py holds both
facts).

`set_labels(df, "corrected")` gives those rows their corrected labels;
`set_labels(df, "stored")` gives them their stored ones. The second is for
frames built in memory from the current catalog (rolling_origin's grid), so
the stored-label run can reproduce the recorded numbers. Only the listed
rows are touched, and only if each one currently carries one of its two
recorded labels; anything else (a row with a different as_of_date, or a
train-censored label) raises.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

KNOWN_DIFFS_PATH = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "kev_label_diffs_20261021.json"
LABELS = ("stored", "corrected")


def load_record(path: Path = KNOWN_DIFFS_PATH) -> dict:
    return json.loads(path.read_text())


def known_diffs(path: Path = KNOWN_DIFFS_PATH) -> pd.DataFrame:
    """One row per (cve_id, landmark_day): as_of_date, kev_date_added, and
    the stored and corrected (event_time, event_observed)."""
    record = load_record(path)
    rows = [
        {"cve_id": c["cve_id"], "landmark_day": r["landmark_day"], "as_of_date": pd.Timestamp(r["as_of_date"]),
         "kev_date_added": pd.Timestamp(c["kev_date_added"]),
         **{f"{which}_{k}": r[which][k] for which in LABELS for k in ("event_time", "event_observed")}}
        for c in record["cves"] for r in c["rows"]
    ]
    out = pd.DataFrame(rows)
    if len(out) != record["n_rows"]:
        raise ValueError(f"{path.name}: {len(out)} rows listed, n_rows says {record['n_rows']}")
    return out


def set_labels(df: pd.DataFrame, which: str, *, diffs: pd.DataFrame | None = None) -> tuple[pd.DataFrame, int]:
    """Copy of `df` with every listed row present in it given its `which`
    labels; returns (frame, number of listed rows found). Writes
    event_time and composite_event, plus event_observed / censor_flag /
    event_type where the frame has them."""
    if which not in LABELS:
        raise ValueError(f"which must be one of {LABELS}, got {which!r}")
    diffs = known_diffs() if diffs is None else diffs
    df = df.copy()
    key = pd.MultiIndex.from_frame(df[["cve_id", "landmark_day"]].astype({"landmark_day": int}))
    pos = key.get_indexer(pd.MultiIndex.from_frame(diffs[["cve_id", "landmark_day"]]))
    found = diffs[pos >= 0]
    pos = pos[pos >= 0]
    if len(found) == 0:
        return df, 0

    as_of = pd.to_datetime(df["as_of_date"]).to_numpy()[pos]
    if (as_of != found["as_of_date"].to_numpy()).any():
        raise ValueError("listed rows found with a different as_of_date than recorded")
    current_time = df["event_time"].to_numpy()[pos]
    current_event = df["composite_event"].astype(bool).to_numpy()[pos]
    known = np.zeros(len(found), dtype=bool)
    for w in LABELS:
        known |= (current_time == found[f"{w}_event_time"].to_numpy()) & (
            current_event == found[f"{w}_event_observed"].to_numpy())
    if not known.all():
        bad = found.loc[~known, ["cve_id", "landmark_day"]].to_dict("records")
        raise ValueError(f"listed rows carry neither their stored nor their corrected label: {bad}")

    event_time = found[f"{which}_event_time"].to_numpy()
    event = found[f"{which}_event_observed"].to_numpy().astype(bool)
    idx = df.index[pos]
    df.loc[idx, "event_time"] = event_time.astype(df["event_time"].dtype)
    df.loc[idx, "composite_event"] = event
    if "event_observed" in df.columns:
        df.loc[idx, "event_observed"] = event
    if "censor_flag" in df.columns:
        df.loc[idx, "censor_flag"] = ~event
    if "event_type" in df.columns:
        df.loc[idx, "event_type"] = np.where(event, "kev", "none")
    return df, len(found)
