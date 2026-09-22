"""
Builds the landmark-prediction feature/label dataset.

Replaces the earlier single day-30-checkpoint design. That design was
abandoned after two rounds of population analysis found: (1) 62% of KEV
listings happen within 30 days of publication (so a single day-30 snapshot
discards most of the signal, since most events have already happened by
the time day-30 features would be computed), and (2) restricting further to
CVEs not-yet-listed by day 30 left too few positives (73 test / 172 train)
to model at all. Landmark prediction — evaluate at MULTIPLE checkpoints
(day 7, 14, 30), each asking "will this still-unlisted CVE be KEV-listed
after this point" — keeps far more of the 689 in-window positives usable
(237 train / 113 test are still unlisted as of day 7 alone) while keeping
every row leakage-safe: a row only exists if nothing about its label was
already knowable as of its own as_of_date.

For each CVE in the study population (published 2022-01-01 through
data_cutoff - 180 days) and each landmark L in config.checkpoints.days
(7, 14, 30), as_of_date = published_date + L. A row is created only if ALL
of:
  1. The CVE was NOT KEV-listed on or before as_of_date (date_added is
     null, or > as_of_date) — this is what makes "will it be listed after
     this point" a well-posed question for this row at all.
  2. At least one EPSS observation exists on or before as_of_date.
  3. TRAIN CVEs only (published before the cutoff): as_of_date is also
     before the cutoff — a training row's as_of_date must itself be in
     the training period, not past it.
Every row ALSO gets a `spans_version_transition` flag: TRUE if
[published_date, as_of_date] contains an EPSS model-version transition
(2022-02-04 / 2023-03-07 / 2025-03-17 — see scripts/download/download_epss.py
for how these were found). Flagged rows are NOT dropped from the table —
they're written with the flag set, so a later sensitivity analysis can
query training.training_dataset without this filter — but the DEFAULT
export (and every count reported by this script) excludes them.

Labels: duration is measured from as_of_date (not publication). TRAIN rows
are censored at the 2025-01-01 cutoff (a listing after the cutoff was
unknowable at train time, so it's treated as censored, not as an event).
TEST rows are observed through the final data cutoff, 2026-09-20.

Leakage-safety design notes:
  - Every EPSS-derived feature is forward-fill only (pandas merge_asof with
    direction="backward"), computed against each CVE's own EPSS series
    filtered to snapshot_date <= as_of_date before any aggregation runs —
    never a value observed after as_of_date.
  - CWE/vendor target encoding is an EXPANDING window per row: for row R,
    "prior" means every canonical.cve CVE published before R's own
    as_of_date (not before R's CVE's published_date — a later landmark's
    as_of_date sees more history than an earlier landmark's, even for the
    same CVE), and a prior CVE counts as positive only if ITS OWN
    date_added <= R's as_of_date (never using a future KEV listing of a
    prior CVE, even though we already know it happened, since it wasn't
    knowable at R's as_of_date). See _expanding_positive_rate.
  - Exploit-DB and raw EPSS score at as_of_date follow the same forward-
    fill-only, on-or-before-as_of_date rule.

See tests/test_leakage/test_landmark_features.py for the tests exercising
these guarantees directly.

Usage: python -m scripts.features.build_landmark_dataset
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone

import numpy as np
import pandas as pd
from sqlalchemy.dialects.postgresql import insert as pg_insert

from config.config_schema import get_config
from database.engine import get_engine, session_scope
from database.models import StaticFeatures, SurvivalLabels, TemporalFeatures, TrainingDataset
from scripts.common.logging_utils import get_logger, log_with_fields

_CHUNK_SIZE = 3000

logger = get_logger(__name__, category="features")

STUDY_START = date(2022, 1, 1)
TRAIN_TEST_CUTOFF = date(2025, 1, 1)
DATA_CUTOFF = date(2026, 9, 20)
FOLLOWUP_DAYS = 180
STUDY_END = DATA_CUTOFF - timedelta(days=FOLLOWUP_DAYS)  # 2026-03-24

# EPSS model-version transition dates, found by scanning every downloaded
# file's #model_version header (see scripts/download/download_epss.py).
VERSION_TRANSITIONS = [date(2022, 2, 4), date(2023, 3, 7), date(2025, 3, 17)]
VERSION_BOUNDARIES = [
    (None, date(2022, 2, 4), "unversioned"),
    (date(2022, 2, 4), date(2023, 3, 7), "v2022.01.01"),
    (date(2023, 3, 7), date(2025, 3, 17), "v2023.03.01"),
    (date(2025, 3, 17), date(2026, 6, 15), "v2025.03.14"),
    (date(2026, 6, 15), None, "v2026.06.15"),
]

# --- the ONLY columns permitted as model features in the export (STEP 1a) ---
MODEL_FEATURE_COLUMNS = [
    "epss_pct_now", "epss_pct_7d_ago", "epss_pct_7d_ago_missing", "epss_pct_delta_7d",
    "epss_pct_first", "epss_pct_max_to_date", "days_to_first_epss", "epss_model_version_at_asof",
    "landmark_day",
    "cvss_base_score", "attack_vector", "attack_complexity", "privileges_required",
    "user_interaction", "confidentiality_impact", "integrity_impact", "availability_impact",
    "cvss_version", "cvss_missing",
    "cwe_kev_rate_expanding", "vendor_kev_rate_expanding", "vendor_count", "product_count",
    "exploit_published_by_asof", "days_to_first_exploit",
]
# Exported alongside the features but explicitly NOT model inputs.
NON_FEATURE_COLUMNS = [
    "cve_id", "as_of_date", "split", "event_time", "event_observed",
    "epss_score_at_asof_raw", "spans_version_transition",
]
EXPORT_COLUMNS = NON_FEATURE_COLUMNS + MODEL_FEATURE_COLUMNS


def _version_at(d: pd.Series) -> pd.Series:
    out = pd.Series(index=d.index, dtype=object)
    for lo, hi, name in VERSION_BOUNDARIES:
        mask = pd.Series(True, index=d.index)
        if lo is not None:
            mask &= d >= pd.Timestamp(lo)
        if hi is not None:
            mask &= d < pd.Timestamp(hi)
        out[mask] = name
    return out


def _spans_transition(published: pd.Series, as_of: pd.Series) -> pd.Series:
    spans = pd.Series(False, index=published.index)
    for t in VERSION_TRANSITIONS:
        t = pd.Timestamp(t)
        spans |= (published <= t) & (as_of >= t)
    return spans


class _Fenwick:
    __slots__ = ("n", "tree")

    def __init__(self, n: int) -> None:
        self.n = n
        self.tree = [0] * (n + 1)

    def update(self, i: int) -> None:
        i += 1
        while i <= self.n:
            self.tree[i] += 1
            i += i & (-i)

    def prefix(self, i: int) -> int:
        if i < 0:
            return 0
        i += 1
        s = 0
        while i > 0:
            s += self.tree[i]
            i -= i & (-i)
        return s


def _expanding_positive_rate(
    published_ord: np.ndarray, date_added_ord: np.ndarray, query_threshold_ord: np.ndarray
) -> tuple[np.ndarray, np.ndarray]:
    """For a single category's members (published_ord, date_added_ord — NaN
    where never KEV-listed) and a set of query thresholds (as_of_dates, as
    ordinal ints), returns (numer, denom) per query:
      denom[i] = # members with published_date < threshold[i]
      numer[i] = # of those with date_added <= threshold[i]
    Offline sweep (sort members by published_date, sort queries by
    threshold, two-pointer + Fenwick tree keyed on date_added) — O((n+q) log n)
    per category, exact (not an approximation)."""
    n = len(published_ord)
    order = np.argsort(published_ord, kind="stable")
    pub_sorted = published_ord[order]
    da_sorted = date_added_ord[order]

    valid_da = da_sorted[~np.isnan(da_sorted)]
    all_vals = np.unique(np.concatenate([valid_da, query_threshold_ord.astype(float)]))
    rank = {v: i for i, v in enumerate(all_vals)}
    tree = _Fenwick(len(all_vals))

    q_order = np.argsort(query_threshold_ord, kind="stable")
    numer = np.zeros(len(query_threshold_ord), dtype=np.int64)
    denom = np.zeros(len(query_threshold_ord), dtype=np.int64)

    ptr = 0
    for qi in q_order:
        threshold = query_threshold_ord[qi]
        while ptr < n and pub_sorted[ptr] < threshold:
            if not np.isnan(da_sorted[ptr]):
                tree.update(rank[da_sorted[ptr]])
            ptr += 1
        denom[qi] = ptr
        numer[qi] = tree.prefix(rank[threshold])
    return numer, denom


def _load_base_cve_table(engine) -> pd.DataFrame:
    """One row per CVE in canonical.cve, with the static features that
    don't vary by landmark: CVSS, primary CWE, primary vendor, vendor/
    product counts, KEV date_added (all of canonical.cve, not just the
    study population — the expanding-window target encoding needs the
    full history as its candidate pool)."""
    cve = pd.read_sql(
        "SELECT cve_id, published_date, cvss_missing FROM canonical.cve", engine,
        parse_dates=["published_date"],
    )
    kev = pd.read_sql("SELECT cve_id, date_added FROM canonical.kev", engine, parse_dates=["date_added"])
    cvss = pd.read_sql(
        "SELECT cve_id, cvss_version, base_score AS cvss_base_score, attack_vector, attack_complexity, "
        "privileges_required, user_interaction, confidentiality_impact, integrity_impact, availability_impact "
        "FROM canonical.cvss_metric WHERE is_primary = true",
        engine,
    )
    cwe_map = pd.read_sql("SELECT cve_id, cwe_id FROM canonical.cve_cwe_map", engine)
    primary_cwe = (
        cwe_map.sort_values("cwe_id").groupby("cve_id", as_index=False).first()
        .rename(columns={"cwe_id": "primary_cwe_id"})
    )
    cpe = pd.read_sql(
        "SELECT cpe_product_id, cve_id, vendor_normalized, product_normalized FROM canonical.cpe_product", engine
    )
    primary_vendor = (
        cpe.sort_values("cpe_product_id").groupby("cve_id", as_index=False).first()
        [["cve_id", "vendor_normalized"]].rename(columns={"vendor_normalized": "primary_vendor"})
    )
    vendor_count = cpe.groupby("cve_id")["vendor_normalized"].nunique().rename("vendor_count")
    product_count = cpe.groupby("cve_id")["product_normalized"].nunique().rename("product_count")

    exploit = pd.read_sql(
        "SELECT m.cve_id, min(e.date_published) AS first_exploit_date "
        "FROM canonical.exploitdb_cve_map m JOIN canonical.exploitdb e ON e.exploit_id = m.exploit_id "
        "GROUP BY m.cve_id",
        engine, parse_dates=["first_exploit_date"],
    )

    df = cve.merge(kev, on="cve_id", how="left")
    df = df.merge(cvss, on="cve_id", how="left")
    df = df.merge(primary_cwe, on="cve_id", how="left")
    df = df.merge(primary_vendor, on="cve_id", how="left")
    df = df.merge(vendor_count, on="cve_id", how="left")
    df = df.merge(product_count, on="cve_id", how="left")
    df = df.merge(exploit, on="cve_id", how="left")
    df["vendor_count"] = df["vendor_count"].fillna(0).astype(int)
    df["product_count"] = df["product_count"].fillna(0).astype(int)
    return df


def _load_epss_timeline(engine, cve_ids: pd.Series) -> pd.DataFrame:
    """Loads canonical.epss_timeline in full and filters to the given CVE
    set in pandas — avoids a huge SQL IN(...) clause (see clean_epss.py's
    docstring for why that blows Postgres's bound-parameter limit here).

    Sorted by snapshot_date ALONE (not [cve_id, snapshot_date]) — required
    by pd.merge_asof, which needs its "on" column globally sorted even when
    `by=` is used for grouped matching (verified: `by=` does NOT relax this
    to within-group sorting). A stable global sort by snapshot_date still
    leaves each cve_id's own rows in chronological relative order, which is
    all groupby-based cummax/first-per-group operations below need."""
    epss = pd.read_sql(
        "SELECT cve_id, snapshot_date, epss_score, percentile FROM canonical.epss_timeline", engine,
        parse_dates=["snapshot_date"],
    )
    epss = epss[epss["cve_id"].isin(set(cve_ids))].sort_values("snapshot_date", kind="mergesort")
    epss["model_version"] = _version_at(epss["snapshot_date"])
    epss["percentile_cummax"] = epss.groupby("cve_id")["percentile"].cummax()
    return epss


def generate_candidate_grid(
    study: pd.DataFrame, landmarks: list[int], train_test_cutoff: date = TRAIN_TEST_CUTOFF
) -> pd.DataFrame:
    """Pure, DB-free: takes a `study` frame (cve_id, published_date,
    date_added — date_added NaT/None if never KEV-listed) and returns the
    candidate (cve, landmark) grid with as_of_date/split computed and
    conditions 1 (not already KEV-listed on/before as_of_date) and 3
    (train rows' as_of_date must itself precede the cutoff) applied, plus
    spans_version_transition. Condition 2 (EPSS coverage) is applied
    separately in `build()` since it needs the EPSS timeline.

    Isolated so leakage tests can exercise it directly with synthetic
    frames — see tests/test_leakage/test_landmark_features.py."""
    rows = []
    for landmark in landmarks:
        chunk = study[["cve_id", "published_date", "date_added"]].copy()
        chunk["landmark_day"] = landmark
        chunk["as_of_date"] = chunk["published_date"] + pd.Timedelta(days=landmark)
        rows.append(chunk)
    candidates = pd.concat(rows, ignore_index=True)

    candidates["split"] = np.where(candidates["published_date"].dt.date < train_test_cutoff, "train", "test")

    # condition 1: not already KEV-listed on or before as_of_date
    not_yet_listed = candidates["date_added"].isna() | (candidates["date_added"] > candidates["as_of_date"])
    # condition 3 (train-only): as_of_date must itself precede the cutoff
    train_asof_ok = (candidates["split"] != "train") | (candidates["as_of_date"].dt.date < train_test_cutoff)
    candidates = candidates[not_yet_listed & train_asof_ok].reset_index(drop=True)
    candidates["spans_version_transition"] = _spans_transition(candidates["published_date"], candidates["as_of_date"])
    return candidates


def compute_labels(
    candidates: pd.DataFrame, train_test_cutoff: date = TRAIN_TEST_CUTOFF, data_cutoff: date = DATA_CUTOFF
) -> pd.DataFrame:
    """Pure, DB-free: adds event_time / event_observed / _train_censored_by_cutoff
    to a candidates frame that already has (split, date_added, as_of_date).
    TRAIN rows observe until train_test_cutoff (a listing after it is
    censored, not an event); TEST rows observe until data_cutoff."""
    candidates = candidates.copy()
    is_train = candidates["split"] == "train"
    observe_until = np.where(is_train, pd.Timestamp(train_test_cutoff), pd.Timestamp(data_cutoff))
    observe_until = pd.to_datetime(observe_until)

    train_censored_by_cutoff = (
        is_train & candidates["date_added"].notna() & (candidates["date_added"] > pd.Timestamp(train_test_cutoff))
    )

    event_observed = candidates["date_added"].notna() & (candidates["date_added"] <= observe_until)
    event_date = np.where(event_observed, candidates["date_added"], observe_until)
    event_date = pd.to_datetime(event_date)
    candidates["event_time"] = (event_date - candidates["as_of_date"]).dt.days
    candidates["event_observed"] = event_observed
    candidates["_train_censored_by_cutoff"] = train_censored_by_cutoff
    return candidates


def compute_epss_asof_features(epss: pd.DataFrame, queries: pd.DataFrame) -> pd.DataFrame:
    """Pure, DB-free: `epss` has (cve_id, snapshot_date, epss_score,
    percentile, model_version, percentile_cummax), sorted by snapshot_date
    ALONE (see _load_epss_timeline for why). `queries` has (cve_id,
    as_of_date), any index/order. Returns `queries`' index with
    epss_pct_now / epss_score_at_asof_raw / epss_model_version_at_asof /
    epss_pct_max_to_date / epss_pct_7d_ago / epss_pct_7d_ago_missing /
    epss_pct_delta_7d joined on — forward-fill only (direction='backward'
    in pandas' terminology means the match is the most recent row at or
    before the query time, never after)."""
    out = queries.copy()

    now_keys = out[["cve_id", "as_of_date"]].reset_index().sort_values("as_of_date", kind="mergesort")
    now = pd.merge_asof(
        now_keys, epss, left_on="as_of_date", right_on="snapshot_date", by="cve_id", direction="backward",
    ).set_index("index").reindex(out.index)

    ago_keys = out[["cve_id", "as_of_date"]].reset_index()
    ago_keys["threshold"] = ago_keys["as_of_date"] - pd.Timedelta(days=7)
    ago_keys = ago_keys.sort_values("threshold", kind="mergesort")
    ago = pd.merge_asof(
        ago_keys, epss, left_on="threshold", right_on="snapshot_date", by="cve_id", direction="backward",
    ).set_index("index").reindex(out.index)

    out["epss_pct_now"] = now["percentile"].values
    out["epss_score_at_asof_raw"] = now["epss_score"].values
    out["epss_model_version_at_asof"] = now["model_version"].values
    out["epss_pct_max_to_date"] = now["percentile_cummax"].values
    out["epss_pct_7d_ago"] = ago["percentile"].values
    out["epss_pct_7d_ago_missing"] = out["epss_pct_7d_ago"].isna()
    out["epss_pct_delta_7d"] = out["epss_pct_now"] - out["epss_pct_7d_ago"]
    out["_has_epss_by_asof"] = now["snapshot_date"].notna()
    return out


def build(cfg=None) -> pd.DataFrame:
    cfg = cfg or get_config()
    engine = get_engine()
    landmarks = cfg.checkpoints.days
    smoothing_weight = cfg.feature_engineering.cwe_base_rate.min_prior_observations

    base = _load_base_cve_table(engine)

    study = base[(base["published_date"].dt.date >= STUDY_START) & (base["published_date"].dt.date <= STUDY_END)].copy()

    candidates = generate_candidate_grid(study, landmarks, TRAIN_TEST_CUTOFF)

    # --- condition 2 + EPSS features, via merge_asof (forward-fill only) ---
    epss = _load_epss_timeline(engine, study["cve_id"])
    candidates = compute_epss_asof_features(epss, candidates)

    first_obs = epss.groupby("cve_id").first()[["snapshot_date", "percentile"]].rename(
        columns={"snapshot_date": "first_epss_date", "percentile": "epss_pct_first"}
    )
    candidates = candidates.merge(first_obs, on="cve_id", how="left")
    candidates["days_to_first_epss"] = (candidates["first_epss_date"] - candidates["published_date"]).dt.days

    candidates = candidates[candidates["_has_epss_by_asof"]].drop(columns=["_has_epss_by_asof"]).reset_index(drop=True)  # condition 2

    # --- CVSS + identity static features (already in `base`, join in) ---
    static_cols = [
        "cve_id", "cvss_version", "cvss_base_score", "attack_vector", "attack_complexity",
        "privileges_required", "user_interaction", "confidentiality_impact", "integrity_impact",
        "availability_impact", "cvss_missing", "primary_cwe_id", "primary_vendor",
        "vendor_count", "product_count", "first_exploit_date",
    ]
    candidates = candidates.merge(base[static_cols], on="cve_id", how="left")

    # --- exploit-db features (forward-fill: only counts if on/before as_of_date) ---
    candidates["exploit_published_by_asof"] = (
        candidates["first_exploit_date"].notna() & (candidates["first_exploit_date"] <= candidates["as_of_date"])
    )
    candidates["days_to_first_exploit"] = np.where(
        candidates["exploit_published_by_asof"],
        (candidates["first_exploit_date"] - candidates["published_date"]).dt.days,
        np.nan,
    )

    # --- expanding-window target encoding (CWE, vendor) ---
    # `base` (all of canonical.cve) is the candidate pool for "prior CVEs" —
    # not just the study population — since the point of an expanding
    # window is to use the full history available as of each row's own
    # as_of_date. A prior CVE counts as positive only if ITS OWN date_added
    # <= the CURRENT row's as_of_date (see _expanding_positive_rate) — never
    # using a prior CVE's eventual-but-not-yet-knowable KEV listing.
    epoch = pd.Timestamp("1970-01-01")
    base_pub_ord = (base["published_date"] - epoch).dt.days.values.astype(float)
    base_da_ord = (base["date_added"] - epoch).dt.days.values.astype(float)  # NaN where not KEV
    query_ord = (candidates["as_of_date"] - epoch).dt.days.values.astype(float)

    global_numer, global_denom = _expanding_positive_rate(base_pub_ord, base_da_ord, query_ord)
    global_rate = np.where(global_denom > 0, global_numer / np.maximum(global_denom, 1), np.nan)
    overall_prior = global_numer.sum() / max(global_denom.sum(), 1)
    # smoothing prior for a row with denom==0 in its own global window too (extremely early
    # as_of_dates only) falls back to this single scalar — the unconditional overall rate.

    def encode(category_col: str, out_col: str) -> None:
        # A row's own CVE is technically a member of its own category pool
        # (its published_date is always < its own as_of_date), so it
        # contributes +1 to that category's denom for its own query. This
        # is harmless, not a leak: for any surviving row, date_added is
        # either null or > as_of_date by construction (condition 1), so
        # self-membership can only ever add to denom, never to numer — it
        # cannot reveal this row's own eventual outcome to itself.
        cat_members = base[category_col].values
        cat_queries = candidates[category_col].values
        result = np.full(len(candidates), np.nan)

        no_cat = pd.isnull(cat_queries)
        result[no_cat] = np.where(np.isnan(global_rate[no_cat]), overall_prior, global_rate[no_cat])

        for cat_value in pd.unique(cat_queries[~no_cat]):
            member_mask = cat_members == cat_value
            q_mask = cat_queries == cat_value
            numer, denom = _expanding_positive_rate(
                base_pub_ord[member_mask], base_da_ord[member_mask], query_ord[q_mask]
            )
            prior = np.where(np.isnan(global_rate[q_mask]), overall_prior, global_rate[q_mask])
            result[np.where(q_mask)[0]] = (numer + smoothing_weight * prior) / (denom + smoothing_weight)

        candidates[out_col] = result

    encode("primary_cwe_id", "cwe_kev_rate_expanding")
    encode("primary_vendor", "vendor_kev_rate_expanding")

    candidates = compute_labels(candidates, TRAIN_TEST_CUTOFF, DATA_CUTOFF)
    return candidates


def _chunked_upsert(session, model, records: list[dict], conflict_cols: list[str], update_cols: list[str]) -> None:
    if not records:
        return
    # chunk size must respect Postgres's 65535 bound-parameter limit for the
    # WIDEST table too (training_dataset has ~38 columns) — a fixed chunk
    # size safe for a narrow table (e.g. static_features) silently blows up
    # on a wide one, which is exactly what happened here the first time.
    n_cols = len(records[0])
    chunk_size = max(1, min(_CHUNK_SIZE, 65000 // n_cols))
    for i in range(0, len(records), chunk_size):
        chunk = records[i : i + chunk_size]
        stmt = pg_insert(model).values(chunk)
        stmt = stmt.on_conflict_do_update(
            index_elements=conflict_cols,
            set_={c: getattr(stmt.excluded, c) for c in update_cols},
        )
        session.execute(stmt)


def _nn(v):
    """NaN/NaT -> None for psycopg binding."""
    if v is None:
        return None
    try:
        if pd.isna(v):
            return None
    except (TypeError, ValueError):
        pass
    return v


def write_features(df: pd.DataFrame, base: pd.DataFrame) -> None:
    """Writes ALL rows in `df` (both spans_version_transition True and
    False — the flag is what future sensitivity analysis filters on, not
    a reason to never store the row) to features.static_features (one row
    per CVE) and features.temporal_features (one row per surviving
    (cve, landmark)), plus training.survival_labels and
    training.training_dataset (the flat export, default-filtered)."""
    now = datetime.now(tz=timezone.utc)

    cve_ids_in_df = set(df["cve_id"])
    static_rows = base[base["cve_id"].isin(cve_ids_in_df)]
    static_records = [
        {
            "cve_id": r.cve_id,
            "cvss_base_score": _nn(r.cvss_base_score),
            "cvss_version": _nn(r.cvss_version),
            "attack_vector": _nn(r.attack_vector),
            "attack_complexity": _nn(r.attack_complexity),
            "privileges_required": _nn(r.privileges_required),
            "user_interaction": _nn(r.user_interaction),
            "confidentiality_impact": _nn(r.confidentiality_impact),
            "integrity_impact": _nn(r.integrity_impact),
            "availability_impact": _nn(r.availability_impact),
            "vendor_normalized": _nn(r.primary_vendor),
            "product_normalized": None,
            "primary_cwe_id": _nn(r.primary_cwe_id),
            "cwe_historical_base_rate": None,  # superseded by temporal_features.cwe_kev_rate_expanding
            "n_affected_products": int(r.product_count),
            "vendor_count": int(r.vendor_count),
            "cvss_missing": bool(r.cvss_missing),
            "computed_at": now,
        }
        for r in static_rows.itertuples()
    ]

    temporal_records = []
    label_records = []
    training_records = []
    dataset_version = f"landmark_v{now:%Y%m%d}"
    export_default = df[~df["spans_version_transition"]]
    export_cve_asof = set(zip(export_default["cve_id"], export_default["landmark_day"]))

    for r in df.itertuples():
        temporal_records.append(
            {
                "cve_id": r.cve_id,
                "checkpoint_day": r.landmark_day,
                "as_of_date": r.as_of_date.date(),
                "poc_observed_by_checkpoint": False,
                "kev_observed_by_checkpoint": False,
                "epss_pct_now": _nn(r.epss_pct_now),
                "epss_pct_7d_ago": _nn(r.epss_pct_7d_ago),
                "epss_pct_7d_ago_missing": bool(r.epss_pct_7d_ago_missing),
                "epss_pct_delta_7d": _nn(r.epss_pct_delta_7d),
                "epss_pct_first": _nn(r.epss_pct_first),
                "epss_pct_max_to_date": _nn(r.epss_pct_max_to_date),
                "days_to_first_epss": _nn(r.days_to_first_epss),
                "epss_model_version_at_asof": _nn(r.epss_model_version_at_asof),
                "epss_score_at_asof_raw": _nn(r.epss_score_at_asof_raw),
                "spans_version_transition": bool(r.spans_version_transition),
                "cwe_kev_rate_expanding": _nn(r.cwe_kev_rate_expanding),
                "vendor_kev_rate_expanding": _nn(r.vendor_kev_rate_expanding),
                "product_count": int(r.product_count),
                "exploit_published_by_asof": bool(r.exploit_published_by_asof),
                "days_to_first_exploit": _nn(r.days_to_first_exploit),
                "computed_at": now,
            }
        )
        label_records.append(
            {
                "cve_id": r.cve_id,
                "checkpoint_day": r.landmark_day,
                "event_time": int(r.event_time),
                "censor_flag": not bool(r.event_observed),
                "composite_event": bool(r.event_observed),  # KEV-listing only — see module docstring
                "event_type": "kev" if r.event_observed else "none",
                "observation_window_end": (TRAIN_TEST_CUTOFF if r.split == "train" else DATA_CUTOFF),
                "label_computed_at": now,
            }
        )
        if (r.cve_id, r.landmark_day) in export_cve_asof:
            training_records.append(
                {
                    "cve_id": r.cve_id,
                    "checkpoint_day": r.landmark_day,
                    "as_of_date": r.as_of_date.date(),
                    "cvss_base_score": _nn(r.cvss_base_score),
                    "cvss_version": _nn(r.cvss_version),
                    "attack_vector": _nn(r.attack_vector),
                    "attack_complexity": _nn(r.attack_complexity),
                    "privileges_required": _nn(r.privileges_required),
                    "user_interaction": _nn(r.user_interaction),
                    "confidentiality_impact": _nn(r.confidentiality_impact),
                    "integrity_impact": _nn(r.integrity_impact),
                    "availability_impact": _nn(r.availability_impact),
                    "vendor_normalized": _nn(r.primary_vendor),
                    "product_normalized": None,
                    "primary_cwe_id": _nn(r.primary_cwe_id),
                    "n_affected_products": int(r.product_count),
                    "vendor_count": int(r.vendor_count),
                    "cvss_missing": bool(r.cvss_missing),
                    "epss_pct_now": _nn(r.epss_pct_now),
                    "epss_pct_7d_ago": _nn(r.epss_pct_7d_ago),
                    "epss_pct_7d_ago_missing": bool(r.epss_pct_7d_ago_missing),
                    "epss_pct_delta_7d": _nn(r.epss_pct_delta_7d),
                    "epss_pct_first": _nn(r.epss_pct_first),
                    "epss_pct_max_to_date": _nn(r.epss_pct_max_to_date),
                    "days_to_first_epss": _nn(r.days_to_first_epss),
                    "epss_model_version_at_asof": _nn(r.epss_model_version_at_asof),
                    "epss_score_at_asof_raw": _nn(r.epss_score_at_asof_raw),
                    "spans_version_transition": bool(r.spans_version_transition),
                    "cwe_kev_rate_expanding": _nn(r.cwe_kev_rate_expanding),
                    "vendor_kev_rate_expanding": _nn(r.vendor_kev_rate_expanding),
                    "product_count": int(r.product_count),
                    "exploit_published_by_asof": bool(r.exploit_published_by_asof),
                    "days_to_first_exploit": _nn(r.days_to_first_exploit),
                    "event_time": int(r.event_time),
                    "censor_flag": not bool(r.event_observed),
                    "composite_event": bool(r.event_observed),
                    "event_type": "kev" if r.event_observed else "none",
                    "dataset_version": dataset_version,
                    "exported_at": now,
                }
            )

    with session_scope() as session:
        _chunked_upsert(
            session, StaticFeatures, static_records, ["cve_id"],
            [c for c in static_records[0] if c != "cve_id"],
        )
        _chunked_upsert(
            session, TemporalFeatures, temporal_records, ["cve_id", "checkpoint_day"],
            [c for c in temporal_records[0] if c not in ("cve_id", "checkpoint_day")],
        )
        _chunked_upsert(
            session, SurvivalLabels, label_records, ["cve_id", "checkpoint_day"],
            [c for c in label_records[0] if c not in ("cve_id", "checkpoint_day")],
        )
        _chunked_upsert(
            session, TrainingDataset, training_records, ["cve_id", "checkpoint_day", "dataset_version"],
            [c for c in training_records[0] if c not in ("cve_id", "checkpoint_day", "dataset_version")],
        )

    log_with_fields(
        logger, logging.INFO, "landmark features written to DB",
        static_rows=len(static_records), temporal_rows=len(temporal_records),
        label_rows=len(label_records), training_rows=len(training_records),
    )

    return dataset_version


def export_parquet(cfg, df: pd.DataFrame, dataset_version: str):
    """The parquet file's columns are EXACTLY EXPORT_COLUMNS (the model
    feature allowlist plus the flagged non-feature columns) — nothing more.
    dataset_version is tracked in training.training_dataset's own column,
    not duplicated into this file; see
    tests/test_leakage/test_landmark_features.py::test_export_column_allowlist."""
    default_df = df[~df["spans_version_transition"]].copy()
    export = default_df[EXPORT_COLUMNS].copy()

    out_dir = cfg.paths.data_training
    out_dir.mkdir(parents=True, exist_ok=True)
    parquet_path = out_dir / f"{dataset_version}.parquet"
    export.to_parquet(parquet_path, index=False)
    log_with_fields(logger, logging.INFO, "training table exported", path=str(parquet_path), rows=len(export))
    return parquet_path


def main() -> None:
    cfg = get_config()
    engine = get_engine()
    base = _load_base_cve_table(engine)
    df = build(cfg)

    default_df = df[~df["spans_version_transition"]]
    log_with_fields(
        logger, logging.INFO, "landmark dataset built",
        total_candidate_rows=len(df), default_rows=len(default_df),
    )

    dataset_version = write_features(df, base)
    export_parquet(cfg, df, dataset_version)


if __name__ == "__main__":
    main()
