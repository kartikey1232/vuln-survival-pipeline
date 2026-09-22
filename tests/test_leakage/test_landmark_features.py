"""
Leakage-safety tests for scripts/features/build_landmark_dataset.py, using
its extracted pure (DB-free) functions with synthetic data — these run
fast and exercise the actual code paths the real pipeline uses, not a
reimplementation of them.
"""

from __future__ import annotations

from datetime import date

import numpy as np
import pandas as pd
import pytest

from scripts.features.build_landmark_dataset import (
    DATA_CUTOFF,
    EXPORT_COLUMNS,
    MODEL_FEATURE_COLUMNS,
    NON_FEATURE_COLUMNS,
    TRAIN_TEST_CUTOFF,
    _expanding_positive_rate,
    compute_epss_asof_features,
    compute_labels,
    generate_candidate_grid,
)


# --- 1. EPSS forward-fill: a value the day after as_of_date must never be picked up ---


def test_epss_asof_feature_ignores_value_the_day_after_checkpoint():
    # CVE-A's EPSS jumps from 0.1 to 0.9 the day AFTER as_of_date (day 7).
    epss = pd.DataFrame(
        {
            "cve_id": ["CVE-A"] * 3,
            "snapshot_date": pd.to_datetime(["2023-01-01", "2023-01-08", "2023-01-09"]),
            "epss_score": [0.05, 0.10, 0.90],
            "percentile": [0.20, 0.30, 0.95],
        }
    ).sort_values("snapshot_date")
    epss["model_version"] = "vtest"
    epss["percentile_cummax"] = epss.groupby("cve_id")["percentile"].cummax()

    queries = pd.DataFrame({"cve_id": ["CVE-A"], "as_of_date": pd.to_datetime(["2023-01-08"])})
    out = compute_epss_asof_features(epss, queries)

    assert out.loc[0, "epss_pct_now"] == pytest.approx(0.30)
    assert out.loc[0, "epss_score_at_asof_raw"] == pytest.approx(0.10)
    # the 0.90/0.95 observation (dated the day AFTER as_of_date) must never appear
    assert out.loc[0, "epss_pct_now"] != pytest.approx(0.95)
    assert out.loc[0, "epss_pct_max_to_date"] != pytest.approx(0.95)
    assert out.loc[0, "epss_pct_max_to_date"] == pytest.approx(0.30)


def test_epss_asof_feature_7d_ago_also_ignores_future_values():
    epss = pd.DataFrame(
        {
            "cve_id": ["CVE-B"] * 2,
            "snapshot_date": pd.to_datetime(["2023-01-01", "2023-01-08"]),
            "epss_score": [0.05, 0.50],
            "percentile": [0.10, 0.85],
        }
    ).sort_values("snapshot_date")
    epss["model_version"] = "vtest"
    epss["percentile_cummax"] = epss.groupby("cve_id")["percentile"].cummax()

    # as_of_date = 2023-01-08 -> 7d-ago threshold = 2023-01-01, exactly the first observation
    queries = pd.DataFrame({"cve_id": ["CVE-B"], "as_of_date": pd.to_datetime(["2023-01-08"])})
    out = compute_epss_asof_features(epss, queries)
    assert out.loc[0, "epss_pct_7d_ago"] == pytest.approx(0.10)
    assert not out.loc[0, "epss_pct_7d_ago_missing"]
    assert out.loc[0, "epss_pct_delta_7d"] == pytest.approx(0.85 - 0.10)


def test_epss_asof_feature_no_observation_yet_flags_missing_not_nan_silently():
    epss = pd.DataFrame(
        {"cve_id": ["CVE-C"], "snapshot_date": pd.to_datetime(["2023-01-05"]), "epss_score": [0.1], "percentile": [0.2]}
    )
    epss["model_version"] = "vtest"
    epss["percentile_cummax"] = epss.groupby("cve_id")["percentile"].cummax()

    # as_of_date=2023-01-05, 7d-ago threshold=2022-12-29, before any observation
    queries = pd.DataFrame({"cve_id": ["CVE-C"], "as_of_date": pd.to_datetime(["2023-01-05"])})
    out = compute_epss_asof_features(epss, queries)
    assert out.loc[0, "epss_pct_7d_ago_missing"]
    assert pd.isna(out.loc[0, "epss_pct_7d_ago"])
    assert pd.isna(out.loc[0, "epss_pct_delta_7d"])
    # but epss_pct_now IS available (an observation exists on as_of_date itself)
    assert not pd.isna(out.loc[0, "epss_pct_now"])


# --- 2. Target encoding must ignore a KEV listing dated after the row's as_of_date ---


def test_expanding_positive_rate_ignores_kev_listing_after_threshold():
    epoch = pd.Timestamp("1970-01-01")
    # Two prior CVEs in the category: one listed well before any query threshold,
    # one listed AFTER the query threshold (must not count as positive for that query).
    published = pd.to_datetime(["2022-01-01", "2022-01-02"])
    date_added = pd.to_datetime(["2022-02-01", "2022-06-01"])  # second one is "future" relative to the query below
    published_ord = (published - epoch).days.values.astype(float)
    date_added_ord = (date_added - epoch).days.values.astype(float)

    query_threshold = pd.Timestamp("2022-03-01")  # after first date_added, before second
    query_ord = np.array([(query_threshold - epoch).days], dtype=float)

    numer, denom = _expanding_positive_rate(published_ord, date_added_ord, query_ord)
    assert denom[0] == 2  # both published before the threshold
    assert numer[0] == 1  # only the Feb listing counts; the June listing is in the query's future


def test_expanding_positive_rate_member_published_after_threshold_excluded_entirely():
    epoch = pd.Timestamp("1970-01-01")
    published = pd.to_datetime(["2022-05-01"])  # published AFTER the query threshold
    date_added = pd.to_datetime(["2022-01-01"])  # even though its date_added is before it, doesn't matter
    published_ord = (published - epoch).days.values.astype(float)
    date_added_ord = (date_added - epoch).days.values.astype(float)

    query_ord = np.array([(pd.Timestamp("2022-03-01") - epoch).days], dtype=float)
    numer, denom = _expanding_positive_rate(published_ord, date_added_ord, query_ord)
    assert denom[0] == 0
    assert numer[0] == 0


# --- 3. No training row shows an event after the 2025-01-01 cutoff ---


def _synthetic_study(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    df["published_date"] = pd.to_datetime(df["published_date"])
    df["date_added"] = pd.to_datetime(df.get("date_added"))
    return df


def test_no_training_row_shows_event_after_cutoff():
    study = _synthetic_study(
        [
            # published well before cutoff, KEV-listed AFTER cutoff -> must be censored, not an event
            {"cve_id": "CVE-TRAIN-1", "published_date": "2023-01-01", "date_added": "2025-06-01"},
            # published before cutoff, KEV-listed before cutoff -> real event
            {"cve_id": "CVE-TRAIN-2", "published_date": "2023-01-01", "date_added": "2023-06-01"},
        ]
    )
    candidates = generate_candidate_grid(study, [30], TRAIN_TEST_CUTOFF)
    candidates = compute_labels(candidates, TRAIN_TEST_CUTOFF, DATA_CUTOFF)

    train_rows = candidates[candidates["split"] == "train"]
    assert len(train_rows) == 2

    row1 = train_rows[train_rows["cve_id"] == "CVE-TRAIN-1"].iloc[0]
    assert not row1["event_observed"]  # censored, not an event
    assert row1["_train_censored_by_cutoff"]

    row2 = train_rows[train_rows["cve_id"] == "CVE-TRAIN-2"].iloc[0]
    assert row2["event_observed"]
    assert not row2["_train_censored_by_cutoff"]

    # the actual assertion this test is named for: no train row's implied event date exceeds the cutoff
    for _, r in train_rows.iterrows():
        if r["event_observed"]:
            implied_event_date = r["as_of_date"] + pd.Timedelta(days=int(r["event_time"]))
            assert implied_event_date.date() <= TRAIN_TEST_CUTOFF


# --- 4. No row exists for a CVE at a landmark on or after its KEV date ---


def test_no_row_exists_for_cve_at_landmark_on_or_after_kev_date():
    study = _synthetic_study(
        [
            # KEV-listed exactly 10 days after publication: landmark 7 should get a row
            # (not yet listed at day 7), landmarks 14 and 30 must NOT (already listed by then).
            {"cve_id": "CVE-EARLY", "published_date": "2023-01-01", "date_added": "2023-01-11"},
            # never KEV-listed: every landmark gets a row
            {"cve_id": "CVE-NEVER", "published_date": "2023-01-01", "date_added": None},
        ]
    )
    candidates = generate_candidate_grid(study, [7, 14, 30], TRAIN_TEST_CUTOFF)

    early_landmarks = set(candidates.loc[candidates["cve_id"] == "CVE-EARLY", "landmark_day"])
    assert early_landmarks == {7}

    never_landmarks = set(candidates.loc[candidates["cve_id"] == "CVE-NEVER", "landmark_day"])
    assert never_landmarks == {7, 14, 30}

    # direct statement of the property: for every row, as_of_date < date_added (or date_added is null)
    merged = candidates.merge(study[["cve_id", "date_added"]], on="cve_id", suffixes=("", "_orig"))
    still_unlisted = merged["date_added"].isna() | (merged["as_of_date"] < merged["date_added"])
    assert still_unlisted.all()


# --- allowlist test (STEP 1a) ---


def test_export_column_allowlist_exact():
    """The exported column set must be EXACTLY the model-feature allowlist
    plus the flagged non-feature columns — nothing more, nothing less.
    Explicitly guards against legacy day-30-design columns AND the
    enrichment-leaking columns (vendor_kev_rate_expanding, vendor_count,
    product_count, the any-source cvss_missing) ever leaking back in — see
    docs/enrichment_leakage.md for why those were removed."""
    assert set(EXPORT_COLUMNS) == set(MODEL_FEATURE_COLUMNS) | set(NON_FEATURE_COLUMNS)
    assert len(EXPORT_COLUMNS) == len(set(EXPORT_COLUMNS))  # no duplicates

    banned_columns = {
        # legacy day-30-design columns
        "kev_observed_by_checkpoint", "epss_score_at_checkpoint", "epss_percentile_at_checkpoint",
        "epss_slope_7d", "epss_growth_rate_7d", "epss_volatility_7d", "epss_percentile_change",
        "days_until_poc", "poc_observed_by_checkpoint", "days_until_kev",
        "related_vendor_kev_velocity", "related_cwe_kev_velocity",
        "rolling_epss_avg_7d", "rolling_epss_avg_30d", "composite_risk_index",
        "vendor_historical_kev_rate", "time_since_disclosure_days", "epss_max_to_date",
        "cwe_historical_base_rate",
        # enrichment-leaking columns (NVD's own analyst-added enrichment,
        # present only once a CVE is analyst-reviewed — preferentially for
        # KEV-listed CVEs)
        "vendor_kev_rate_expanding", "vendor_count", "product_count", "cvss_missing",
        "vulnStatus", "vuln_status", "lastModified", "last_modified_date",
    }
    assert banned_columns.isdisjoint(EXPORT_COLUMNS)
