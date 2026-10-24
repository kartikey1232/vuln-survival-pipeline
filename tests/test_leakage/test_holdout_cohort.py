"""
training.holdout_2026 (the 2026 holdout cohort,
scripts/features/build_holdout_cohort.py): the CVE-overlap constraint, the
feature allowlist, and the leakage rules checked on the stored rows.

- Constraint and allowlist tests run on the test database (schema only).
- The stored-row tests read the PRODUCTION database (read-only), like
  tests/test_features/test_build_reproduces_training_dataset.py, and skip
  if no cohort has been built. Where a rule can be checked independently
  of build_landmark_dataset's own code, it is: SQL against
  canonical.kev / canonical.epss_timeline / canonical.exploitdb, not the
  pandas path that produced the rows.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

import pandas as pd
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from database.engine import get_engine
from scripts.features.build_holdout_cohort import (
    COHORT_CUTOFF,
    COHORT_END,
    COHORT_START,
    HOLDOUT_COLUMNS,
)
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS
from tests.test_leakage.test_landmark_features import BANNED_COLUMNS

NOW = datetime(2026, 10, 24, tzinfo=timezone.utc)
# stored alongside the features, never model inputs
HOLDOUT_NON_FEATURE_COLUMNS = {
    "cve_id", "checkpoint_day", "published_date", "as_of_date", "epss_score_at_asof_raw",
    "spans_version_transition", "event_time", "composite_event", "observation_window_end", "followup_days",
    "dataset_version", "exported_at",
}


# --- the overlap constraint (test database) ---


def _insert_training(session: Session, cve_id: str) -> None:
    session.execute(text(
        "INSERT INTO training.training_dataset (cve_id, checkpoint_day, as_of_date, censor_flag, composite_event, "
        "dataset_version, exported_at) VALUES (:c, 7, DATE '2026-01-08', TRUE, FALSE, 'landmark_vtest', :t)"),
        {"c": cve_id, "t": NOW})


def _insert_holdout(session: Session, cve_id: str, published: date = date(2026, 4, 1)) -> None:
    as_of = pd.Timestamp(published) + pd.Timedelta(days=7)
    followup = (pd.Timestamp(COHORT_CUTOFF) - as_of).days
    session.execute(text(
        "INSERT INTO training.holdout_2026 (cve_id, checkpoint_day, published_date, as_of_date, "
        "epss_pct_7d_ago_missing, cvss_cna_missing, exploit_published_by_asof, spans_version_transition, "
        "event_time, composite_event, observation_window_end, followup_days, dataset_version, exported_at) "
        "VALUES (:c, 7, :p, :a, FALSE, FALSE, FALSE, FALSE, :f, FALSE, :end, :f, 'holdout_2026_vtest', :t)"),
        {"c": cve_id, "p": published, "a": as_of.date(), "f": followup, "end": COHORT_CUTOFF, "t": NOW})


def test_holdout_insert_rejected_when_cve_is_in_training(db_session: Session):
    _insert_training(db_session, "CVE-2026-0001")
    with pytest.raises(IntegrityError, match="holdout_2026_no_training_overlap|is in training.training_dataset"):
        _insert_holdout(db_session, "CVE-2026-0001")
        db_session.flush()


def test_training_insert_rejected_when_cve_is_in_holdout(db_session: Session):
    _insert_holdout(db_session, "CVE-2026-0002")
    with pytest.raises(IntegrityError, match="training_dataset_no_holdout_overlap|is in training.holdout_2026"):
        _insert_training(db_session, "CVE-2026-0002")
        db_session.flush()


def test_update_into_overlap_rejected(db_session: Session):
    _insert_training(db_session, "CVE-2026-0003")
    _insert_holdout(db_session, "CVE-2026-0004")
    with pytest.raises(IntegrityError, match="holdout_2026_no_training_overlap|is in training.training_dataset"):
        db_session.execute(text("UPDATE training.holdout_2026 SET cve_id = 'CVE-2026-0003' "
                                "WHERE cve_id = 'CVE-2026-0004'"))


def test_disjoint_cves_accepted(db_session: Session):
    _insert_training(db_session, "CVE-2026-0005")
    _insert_holdout(db_session, "CVE-2026-0006")
    db_session.flush()
    assert db_session.execute(text("SELECT count(*) FROM training.holdout_2026")).scalar_one() == 1


def test_publication_window_is_a_check_constraint(db_session: Session):
    with pytest.raises(IntegrityError, match="holdout_2026_published_window"):
        _insert_holdout(db_session, "CVE-2026-0007", published=date(2026, 3, 24))  # frozen study's last day


# --- the feature allowlist (test database schema) ---


def test_holdout_columns_are_exactly_the_allowlist(db_session: Session):
    cols = set(db_session.execute(text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'training' AND table_name = 'holdout_2026'")).scalars())
    assert cols == set(HOLDOUT_COLUMNS)
    features = {"landmark_day" if c == "checkpoint_day" else c for c in cols - (HOLDOUT_NON_FEATURE_COLUMNS - {"checkpoint_day"})}
    assert features == set(MODEL_FEATURE_COLUMNS)
    assert BANNED_COLUMNS.isdisjoint(cols)


# --- stored rows (production, read-only) ---


@pytest.fixture(scope="module")
def cohort() -> pd.DataFrame:
    try:
        engine = get_engine()
        df = pd.read_sql(text(
            "SELECT * FROM training.holdout_2026 WHERE dataset_version = "
            "(SELECT max(dataset_version) FROM training.holdout_2026)"), engine,
            parse_dates=["published_date", "as_of_date", "observation_window_end"])
    except OperationalError as exc:
        pytest.skip(f"production database unavailable: {exc}")
    if df.empty:
        pytest.skip("no holdout cohort built in the production database")
    return df


def _prod(sql: str, **params) -> pd.DataFrame:
    return pd.read_sql(text(sql), get_engine(), params=params)


@pytest.mark.slow
def test_stored_cohort_shares_no_cve_with_training_dataset(cohort):
    shared = _prod("SELECT count(DISTINCT h.cve_id) AS n FROM training.holdout_2026 h "
                   "JOIN training.training_dataset t USING (cve_id)")["n"].iloc[0]
    assert shared == 0


@pytest.mark.slow
def test_stored_cohort_population_and_follow_up(cohort):
    assert cohort["published_date"].min().date() >= COHORT_START
    assert cohort["published_date"].max().date() <= COHORT_END
    assert (cohort["observation_window_end"].dt.date == COHORT_CUTOFF).all()
    assert (cohort["followup_days"] == (cohort["observation_window_end"] - cohort["as_of_date"]).dt.days).all()
    assert (cohort["followup_days"] < 180).any()  # the 180-day rule is NOT applied at build


@pytest.mark.slow
def test_stored_cohort_no_row_on_or_after_kev_listing_and_labels_censored_at_cutoff(cohort):
    kev = _prod("SELECT cve_id, date_added FROM canonical.kev")
    kev["date_added"] = pd.to_datetime(kev["date_added"])
    x = cohort.merge(kev, on="cve_id", how="left")
    assert (x["date_added"].isna() | (x["date_added"] > x["as_of_date"])).all()  # condition 1

    cutoff = pd.Timestamp(COHORT_CUTOFF)
    event = x["date_added"].notna() & (x["date_added"] <= cutoff)
    assert (x["composite_event"] == event).all()
    expected_time = ((x["date_added"].where(event, cutoff)) - x["as_of_date"]).dt.days
    assert (x["event_time"] == expected_time).all()


@pytest.mark.slow
def test_stored_cohort_epss_is_as_of_landmark(cohort):
    """Independent SQL check on a sample: epss_pct_now is the latest snapshot
    on or before as_of_date, epss_pct_7d_ago the latest on or before
    as_of_date - 7. No snapshot after either date can be the source."""
    s = cohort.sample(n=min(3000, len(cohort)), random_state=20260922)[
        ["cve_id", "as_of_date", "epss_pct_now", "epss_pct_7d_ago"]]
    rows = []
    with get_engine().connect() as conn:
        for r in s.itertuples(index=False):
            now, ago = conn.execute(text(
                "SELECT (SELECT percentile FROM canonical.epss_timeline WHERE cve_id = :c AND snapshot_date <= :d "
                "        ORDER BY snapshot_date DESC LIMIT 1), "
                "       (SELECT percentile FROM canonical.epss_timeline WHERE cve_id = :c AND snapshot_date <= :d7 "
                "        ORDER BY snapshot_date DESC LIMIT 1)"),
                {"c": r.cve_id, "d": r.as_of_date.date(), "d7": (r.as_of_date - pd.Timedelta(days=7)).date()}).one()
            rows.append((now, ago))
    ref = pd.DataFrame(rows, columns=["now", "ago"], index=s.index).astype(float)
    assert ref["now"].notna().all()  # condition 2: every row had EPSS by its as_of_date
    assert (ref["now"] == s["epss_pct_now"].astype(float)).all()
    assert ((ref["ago"] == s["epss_pct_7d_ago"].astype(float)) | (ref["ago"].isna() & s["epss_pct_7d_ago"].isna())).all()


@pytest.mark.slow
def test_stored_cohort_exploit_feature_is_as_of_landmark(cohort):
    first = _prod("SELECT m.cve_id, min(e.date_published) AS first_exploit FROM canonical.exploitdb_cve_map m "
                  "JOIN canonical.exploitdb e ON e.exploit_id = m.exploit_id GROUP BY m.cve_id")
    first["first_exploit"] = pd.to_datetime(first["first_exploit"])
    x = cohort.merge(first, on="cve_id", how="left")
    by_asof = x["first_exploit"].notna() & (x["first_exploit"] <= x["as_of_date"])
    assert (x["exploit_published_by_asof"] == by_asof).all()
    assert x.loc[~by_asof, "days_to_first_exploit"].isna().all()


@pytest.mark.slow
def test_stored_cohort_target_encodings_are_rates(cohort):
    for c in ("cwe_kev_rate_expanding", "cna_kev_rate_expanding"):
        v = cohort[c].astype(float)
        assert v.notna().all() and ((v >= 0) & (v <= 1)).all()
