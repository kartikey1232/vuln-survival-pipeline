"""
Builds the 2026 holdout cohort (docs/holdout_protocol.md) into
training.holdout_2026.

Population: CVEs published COHORT_START (2026-03-25, the day after the
frozen study's last publication date) through COHORT_CUTOFF - 30 days
(2026-09-21), so every landmark (7/14/30) falls on or before the cutoff.
COHORT_CUTOFF (2026-10-21) is the as-of date of the refresh's NVD, KEV and
EPSS steps (scripts/download/refresh.py).

Features: build_landmark_dataset.build() unchanged. Same publication-time
(own-CNA) rule, same as-of EPSS/Exploit-DB/target-encoding rules, same row
conditions 1 and 2. All rows are on the test side of the split (no
condition-3 drops), and labels are censored at COHORT_CUTOFF.

Follow-up: each row stores observation_window_end and
followup_days = cutoff - as_of_date. The 180-day minimum follow-up the
frozen study applied at BUILD time (STUDY_END) is NOT applied here. It is
applied at evaluation, from followup_days, so the cohort keeps every CVE
and an evaluation can pick its own horizon.

Version-transition rows (now including 2026-06-15) are stored with
spans_version_transition = TRUE, as features.temporal_features stores them.
The default cohort excludes them, as training_dataset's default export does.

No CVE may also be in training.training_dataset. This is enforced by
constraint triggers in the database (database/schema.sql) and checked here
before writing.

Nothing here evaluates a model.

Usage: python -m scripts.features.build_holdout_cohort
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone

import pandas as pd
from sqlalchemy import text

from config.config_schema import get_config
from database.engine import get_engine, session_scope
from database.models import Holdout2026
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS, _nn, build

logger = get_logger(__name__, category="features")

COHORT_START = date(2026, 3, 25)
COHORT_CUTOFF = date(2026, 10, 21)
LAST_LANDMARK = 30
COHORT_END = COHORT_CUTOFF - timedelta(days=LAST_LANDMARK)  # 2026-09-21

HOLDOUT_COLUMNS = (
    ["cve_id", "checkpoint_day", "published_date", "as_of_date"]
    + [c for c in MODEL_FEATURE_COLUMNS if c != "landmark_day"]  # landmark_day is checkpoint_day
    + ["epss_score_at_asof_raw", "spans_version_transition", "event_time", "composite_event",
       "observation_window_end", "followup_days", "dataset_version", "exported_at"]
)


def build_cohort(cfg=None) -> pd.DataFrame:
    df = build(cfg, train_test_cutoff=COHORT_START, study_start=COHORT_START, study_end=COHORT_END,
               data_cutoff=COHORT_CUTOFF)
    if not (df["split"] == "test").all():
        raise RuntimeError("cohort rows on the train side of the split")
    df["observation_window_end"] = pd.Timestamp(COHORT_CUTOFF)
    df["followup_days"] = (pd.Timestamp(COHORT_CUTOFF) - df["as_of_date"]).dt.days
    return df


def write_cohort(df: pd.DataFrame, dataset_version: str) -> int:
    engine = get_engine()
    overlap = pd.read_sql(text("SELECT DISTINCT cve_id FROM training.training_dataset"), engine)["cve_id"]
    shared = sorted(set(overlap) & set(df["cve_id"]))
    if shared:
        raise RuntimeError(f"{len(shared)} cohort CVEs are in training.training_dataset, e.g. {shared[:5]}")

    now = datetime.now(tz=timezone.utc)
    out = df.rename(columns={"landmark_day": "checkpoint_day", "event_observed": "composite_event"}).copy()
    for c in ("published_date", "as_of_date", "observation_window_end"):
        out[c] = out[c].dt.date
    out["dataset_version"] = dataset_version
    out["exported_at"] = now
    records = [{c: _nn(v) for c, v in zip(HOLDOUT_COLUMNS, row)}
               for row in out[HOLDOUT_COLUMNS].itertuples(index=False, name=None)]

    chunk_size = 65000 // len(HOLDOUT_COLUMNS)  # CLAUDE.md rule 7
    with session_scope() as session:
        session.execute(text("DELETE FROM training.holdout_2026 WHERE dataset_version = :v"), {"v": dataset_version})
        for i in range(0, len(records), chunk_size):
            session.execute(Holdout2026.__table__.insert(), records[i:i + chunk_size])
    return len(records)


def main() -> None:
    cfg = get_config()
    df = build_cohort(cfg)
    dataset_version = f"holdout_2026_v{datetime.now(tz=timezone.utc):%Y%m%d}"
    n = write_cohort(df, dataset_version)
    default = df[~df["spans_version_transition"]]
    log_with_fields(logger, logging.INFO, "holdout cohort written", dataset_version=dataset_version, rows=n,
                    default_rows=len(default), cves=df["cve_id"].nunique(), events=int(df["event_observed"].sum()))


if __name__ == "__main__":
    main()
