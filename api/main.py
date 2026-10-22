"""
Read-only API over the frozen artifacts. The system RANKS by Cox and
EXPLAINS by fuzzy rules (docs/fuzzy_layer.md, Conclusion): the watchlist
orders by the frozen Cox partial hazard, and the fuzzy priority and fired
rules are attached to each row as its explanation, never as the ordering.

Nothing is fit at request time. Endpoints are plain `def` so FastAPI runs
them in its threadpool; the synchronous engine never blocks the event loop.

Run: uv run uvicorn api.main:app
"""

from __future__ import annotations

import threading

import numpy as np
import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, Path, Query
from sqlalchemy import Engine

from api import db, scoring
from api.artifacts import FrozenArtifacts, get_artifacts
from api.schemas import BacktestResponse, CVEResponse, ModelResponse, WatchlistResponse
from config.config_schema import get_config
from database.engine import get_engine
from scripts.evaluate.data_splits import DATA_CUTOFF

CVE_ID_PATTERN = r"^CVE-\d{4}-\d{4,}$"
CALIBRATION_NOTE = (
    "Cox survival probabilities are under-dispersed (predicted P(KEV within 90d) spans 0.078-0.191% on test; "
    "top decile under-predicted ~6x, docs/final_results.md). Use them to order CVEs, not as calibrated "
    "probabilities."
)
ENCODING_ISSUE = (
    "Each model's recorded 'test_metrics' were computed with a test-time one-hot encoding bug that mis-encoded "
    "84,684 test rows; 'test_metrics_corrected_encoding' beside them is the same frozen model, correctly encoded "
    "(Cox test C-index 0.8501 vs 0.8492 recorded). The API scores with the correct encoding. See "
    "docs/results_corrected_encoding.md and GET /backtest."
)

app = FastAPI(title="Vulnerability survival API", version="1.0",
              description="Time-to-CISA-KEV risk from a frozen Cox model, with fuzzy-rule explanations.")


def get_db() -> Engine:
    return get_engine()


# Watchlist pool: test-period rows scored once per engine, then reused.
_pool_cache: dict[str, pd.DataFrame] = {}
_pool_lock = threading.Lock()


def _scored_pool(engine: Engine, art: FrozenArtifacts) -> pd.DataFrame:
    key = engine.url.render_as_string(hide_password=True)
    with _pool_lock:
        if key not in _pool_cache:
            rows = db.test_period_rows(engine)
            hazard = scoring.cox_scores(rows, art)
            rows["cox_partial_hazard"] = hazard
            rows["cox_risk_pct"] = scoring.cox_risk_pct(hazard, rows["landmark_day"], art) if len(rows) else hazard
            _pool_cache[key] = rows
        return _pool_cache[key]


def _top_k(score: np.ndarray, budget: float) -> np.ndarray:
    """Same top-k rule as scripts/evaluate/common.py::recall_at_budget."""
    n_top = max(1, int(np.ceil(len(score) * budget)))
    return np.argsort(-score)[:n_top]


@app.get("/cve/{cve_id}", response_model=CVEResponse)
def get_cve(cve_id: str = Path(pattern=CVE_ID_PATTERN), engine: Engine = Depends(get_db),
            art: FrozenArtifacts = Depends(get_artifacts)):
    record = db.cve_record(engine, cve_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")

    rows = db.landmark_rows_for_cve(engine, cve_id)
    landmarks = []
    if len(rows):
        hazard = scoring.cox_scores(rows, art)
        pct = scoring.cox_risk_pct(hazard, rows["landmark_day"], art)
        curves = scoring.survival_curves(rows, art)
        fuzzy = scoring.fuzzy_explanations(rows, pct, art)
        for i, r in rows.iterrows():
            landmarks.append({
                "landmark_day": r["landmark_day"], "as_of_date": r["as_of_date"].date(), "split": r["split"],
                "cox_partial_hazard": hazard[i], "cox_risk_pct": pct[i], "epss_pct_now": r["epss_pct_now"],
                "cvss_base_score": None if r["cvss_cna_missing"] else r["cvss_base_score"],
                "survival_curve": [{"day": d, "survival_probability": float(s)}
                                   for d, s in zip(scoring.SURVIVAL_CURVE_DAYS, curves[i])],
                "fuzzy": fuzzy[i],
            })

    scored = set(rows["landmark_day"]) if len(rows) else set()
    kev_date = record["kev"]["date_added"] if record["kev"] else None
    not_scored = []
    for lm in get_config().checkpoints.days:
        if lm in scored:
            continue
        as_of = record["published_date"] + pd.Timedelta(days=lm)
        if kev_date is not None and kev_date <= as_of:
            reason = "already KEV-listed on or before this landmark"
        elif pd.Timestamp(as_of) > DATA_CUTOFF:
            reason = f"landmark falls after the data cutoff ({DATA_CUTOFF.date()})"
        else:
            reason = "no landmark row: no EPSS observation by this landmark, or CVE outside the dataset"
        not_scored.append({"landmark_day": lm, "as_of_date": as_of, "reason": reason})

    return {**record, "landmarks": landmarks, "landmarks_not_scored": not_scored,
            "notes": [CALIBRATION_NOTE, "fuzzy priority is an explanation; ranking is by Cox (see /watchlist)"]}


@app.get("/watchlist", response_model=WatchlistResponse)
def get_watchlist(budget: float = Query(0.10, gt=0, le=1),
                  landmark_day: int | None = Query(None, description="Restrict the pool to one landmark"),
                  limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
                  engine: Engine = Depends(get_db), art: FrozenArtifacts = Depends(get_artifacts)):
    if landmark_day is not None and landmark_day not in get_config().checkpoints.days:
        raise HTTPException(status_code=422, detail=f"landmark_day must be one of {get_config().checkpoints.days}")
    pool = _scored_pool(engine, art)
    if landmark_day is not None:
        pool = pool[pool["landmark_day"] == landmark_day].reset_index(drop=True)
    if pool.empty:
        raise HTTPException(status_code=404, detail="watchlist pool is empty")

    top = _top_k(pool["cox_partial_hazard"].to_numpy(), budget)
    epss_top = np.zeros(len(pool), dtype=bool)
    epss_top[_top_k(pool["epss_pct_now"].to_numpy(), budget)] = True

    page_idx = top[offset:offset + limit]
    page = pool.iloc[page_idx].reset_index(drop=True)
    fuzzy = scoring.fuzzy_explanations(page, page["cox_risk_pct"].to_numpy(), art)
    items = [{
        "rank": offset + i + 1, "cve_id": r["cve_id"], "landmark_day": r["landmark_day"],
        "as_of_date": r["as_of_date"].date(), "cox_partial_hazard": r["cox_partial_hazard"],
        "cox_risk_pct": r["cox_risk_pct"], "epss_pct_now": r["epss_pct_now"],
        "epss_ranks_low": not epss_top[page_idx[i]],
        "kev_date_added": None if pd.isna(r["kev_date_added"]) else r["kev_date_added"].date(),
        "fuzzy": fuzzy[i],
    } for i, r in page.iterrows()]

    return {
        "budget": budget, "landmark_day": landmark_day,
        "pool": "test-period landmark rows (as_of_date >= 2025-01-01), pooled across landmarks unless filtered; "
                "the same rows the models were evaluated on",
        "pool_rows": len(pool), "selected_rows": len(top), "selected_epss_ranks_low": int((~epss_top[top]).sum()),
        "offset": offset, "limit": limit, "items": items,
    }


@app.get("/backtest", response_model=BacktestResponse)
def get_backtest(art: FrozenArtifacts = Depends(get_artifacts)):
    return art.metadata["backtest_corrected_encoding"]


@app.get("/model", response_model=ModelResponse)
def get_model(art: FrozenArtifacts = Depends(get_artifacts)):
    m = art.metadata
    fuzzy = m["fuzzy_config"]
    return {
        "cox": m["cox_final_metadata"], "rsf": m["rsf_final_metadata"], "xgboost_aft": m["xgboost_aft_final_metadata"],
        "risk_percentile_reference": m["cox_risk_reference_metadata"],
        "serving_preprocessing": m["cox_serving_preprocessing"],
        "fuzzy": {k: fuzzy[k] for k in ("rules", "membership_functions", "rule_weights", "tie_break",
                                        "monotonicity_check", "design_data", "validation_quantiles")},
        "known_issues": [ENCODING_ISSUE, CALIBRATION_NOTE,
                         "Fuzzy layer does not improve ranking over a linear blend and underperforms Cox at "
                         "recall@10%; it ships as an explanation layer only (docs/fuzzy_layer.md)."],
    }
