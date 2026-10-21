"""
Postgres reads for the API (synchronous engine — callers are plain `def`
endpoints, which FastAPI runs in its threadpool, so no request ever blocks
the event loop; see database/engine.py).
"""

from __future__ import annotations

import pandas as pd
from sqlalchemy import Engine, text

from scripts.evaluate.data_splits import DATASET_VERSION, VAL_CUTOFF
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS

_FEATURES = [c for c in MODEL_FEATURE_COLUMNS if c != "landmark_day"]
_LANDMARK_SELECT = (
    "SELECT t.cve_id, t.checkpoint_day, t.as_of_date, "
    + ", ".join(f"t.{c}" for c in _FEATURES)
    + ", t.epss_score_at_asof_raw, k.date_added AS kev_date_added "
    "FROM training.training_dataset t LEFT JOIN canonical.kev k ON k.cve_id = t.cve_id "
    "WHERE t.dataset_version = :version"
)
# Postgres NUMERIC comes back as Decimal; the model needs floats.
_NUMERIC_COLUMNS = ["cvss_base_score", "epss_pct_now", "epss_pct_7d_ago", "epss_pct_delta_7d", "epss_pct_first",
                    "epss_pct_max_to_date", "days_to_first_epss", "cwe_kev_rate_expanding",
                    "cna_kev_rate_expanding", "days_to_first_exploit", "epss_score_at_asof_raw"]


def _landmark_frame(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["landmark_day"] = df["checkpoint_day"].astype(int)
    for c in _NUMERIC_COLUMNS:
        df[c] = pd.to_numeric(df[c], errors="coerce").astype(float)
    df["as_of_date"] = pd.to_datetime(df["as_of_date"])
    df["kev_date_added"] = pd.to_datetime(df["kev_date_added"])
    df["split"] = (df["as_of_date"] >= VAL_CUTOFF).map({True: "test", False: "train"})
    return df.sort_values(["cve_id", "landmark_day"]).reset_index(drop=True)


def landmark_rows_for_cve(engine: Engine, cve_id: str) -> pd.DataFrame:
    df = pd.read_sql(text(_LANDMARK_SELECT + " AND t.cve_id = :cve_id"), engine,
                     params={"version": DATASET_VERSION, "cve_id": cve_id})
    return _landmark_frame(df)


def test_period_rows(engine: Engine) -> pd.DataFrame:
    """The watchlist pool: every landmark row in the test period (as_of_date
    >= 2025-01-01), the same rows the models were evaluated on."""
    df = pd.read_sql(text(_LANDMARK_SELECT + " AND t.as_of_date >= :cutoff"), engine,
                     params={"version": DATASET_VERSION, "cutoff": VAL_CUTOFF.date()})
    return _landmark_frame(df)


def cve_record(engine: Engine, cve_id: str) -> dict | None:
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT cve_id, published_date, last_modified_date, description, vuln_status "
            "FROM canonical.cve WHERE cve_id = :cve_id"), {"cve_id": cve_id}).mappings().first()
        if row is None:
            return None
        out = dict(row)
        # The CNA that owns the CVE: the same field the feature build's
        # own-CNA source rule uses (build_landmark_dataset._load_base_cve_table).
        out["cna_source_identifier"] = conn.execute(text(
            "SELECT payload->>'sourceIdentifier' FROM staging.nvd_cve_raw WHERE cve_id = :cve_id "
            "ORDER BY last_modified_src DESC LIMIT 1"), {"cve_id": cve_id}).scalar()
        out["cvss_metrics"] = [dict(r) for r in conn.execute(text(
            "SELECT cvss_version, base_score, base_severity, vector_string, source, is_primary "
            "FROM canonical.cvss_metric WHERE cve_id = :cve_id ORDER BY cvss_version, source"),
            {"cve_id": cve_id}).mappings()]
        out["cwes"] = [dict(r) for r in conn.execute(text(
            "SELECT m.cwe_id, c.name, m.source FROM canonical.cve_cwe_map m "
            "LEFT JOIN canonical.cwe c ON c.cwe_id = m.cwe_id WHERE m.cve_id = :cve_id ORDER BY m.cwe_id"),
            {"cve_id": cve_id}).mappings()]
        kev = conn.execute(text(
            "SELECT date_added, vendor_project, product, vulnerability_name, known_ransomware "
            "FROM canonical.kev WHERE cve_id = :cve_id"), {"cve_id": cve_id}).mappings().first()
        out["kev"] = dict(kev) if kev else None
        out["epss_history"] = [dict(r) for r in conn.execute(text(
            "SELECT snapshot_date, epss_score, percentile, is_observed FROM canonical.epss_timeline "
            "WHERE cve_id = :cve_id ORDER BY snapshot_date"), {"cve_id": cve_id}).mappings()]
    return out
