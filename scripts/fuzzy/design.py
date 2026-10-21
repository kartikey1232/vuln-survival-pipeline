"""
Fuzzy-layer design, on VALIDATION rows only (train-split rows published
2024-07-01..2024-12-31, identical to data_splits.load_splits().val). Never
reads test rows.

1. Membership cut-offs from validation input quantiles (fuzzy_layer.fit_cutoffs).
   The rule base must pass a dense monotonicity check in cox_risk before
   the config is written.
2. Rule weights: all 1.0. Validation has 55 events (one event = 1.8pp of
   recall), too few to choose between weight settings without fitting
   noise, so no weight search is run.
3. Reference (c), the linear blend: a Cox PH on the same inputs fitted on
   validation. blindspot = cox_risk - epss exactly, so it is not a separate
   column: any weight on it is already expressible through the other two.
4. Validation metrics for the fuzzy ranking and the references, through
   scripts/evaluate/common.py.

Caveat: the frozen Cox model was fit on the FULL train set, which contains
these validation rows, so cox_risk_pct is in-sample here. Validation
numbers flatter Cox and anything leaning on it (fuzzy layer, blend); only
the test evaluation (evaluate_fuzzy.py) is out-of-sample.

Writes models/fuzzy_config.json — the frozen design that
evaluate_fuzzy.py reads.

Usage: python -m scripts.fuzzy.design
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from lifelines import CoxPHFitter

from config.config_schema import get_config
from scripts.evaluate.common import evaluate_blind_spot_catch_rate, evaluate_model
from scripts.evaluate.data_splits import FIT_CUTOFF
from scripts.fuzzy import fuzzy_layer as fl

BLEND_FEATURES = ["cox_risk_pct", "epss_pct_now", "cvss_base_filled", "cvss_cna_missing"]
BLEND_PENALIZER = 0.0  # 0.01 shrank every weight towards 0: lifelines penalizes the per-row mean log-likelihood, and 55 events in 53k rows give that almost no curvature


def load_inputs(cfg) -> pd.DataFrame:
    return pd.read_parquet(cfg.project_root / "data" / "training" / "cox_risk_pct.parquet")


def validation_rows(df: pd.DataFrame) -> pd.DataFrame:
    return df[(df["split"] == "train") & (df["published_date"] >= FIT_CUTOFF)].reset_index(drop=True)


def blend_design(df: pd.DataFrame) -> pd.DataFrame:
    """CVSS on 0-1, 0 when missing; the missing flag carries the rest."""
    return pd.DataFrame({
        "cox_risk_pct": df["cox_risk_pct"].to_numpy(dtype=float),
        "epss_pct_now": df["epss_pct_now"].to_numpy(dtype=float),
        "cvss_base_filled": df["cvss_base_score"].fillna(0.0).to_numpy(dtype=float) / 10.0,
        "cvss_cna_missing": df["cvss_cna_missing"].to_numpy(dtype=float),
    })


def blend_score(df: pd.DataFrame, coefficients: dict) -> np.ndarray:
    X = blend_design(df)
    return X[BLEND_FEATURES].to_numpy() @ np.array([coefficients[c] for c in BLEND_FEATURES])


def fit_blend(val: pd.DataFrame) -> dict:
    X = blend_design(val)
    X["event_time"] = val["event_time"].clip(lower=0.5).to_numpy()
    X["composite_event"] = val["composite_event"].astype(int).to_numpy()
    cph = CoxPHFitter(penalizer=BLEND_PENALIZER)
    cph.fit(X, duration_col="event_time", event_col="composite_event")
    return {"model": "CoxPHFitter (lifelines), fitted on validation", "penalizer": BLEND_PENALIZER,
            "features": BLEND_FEATURES, "coefficients": cph.params_.to_dict(),
            "note": "blindspot omitted: it equals cox_risk_pct - epss_pct_now exactly"}


def rankings(df: pd.DataFrame, priority: np.ndarray, blend: dict) -> dict[str, np.ndarray]:
    return {
        "Fuzzy": fl.ranking_score(priority, df["cox_risk_pct"].to_numpy(), df["epss_pct_now"].to_numpy()),
        "Cox": df["cox_risk_score"].to_numpy(dtype=float),
        "EPSS": df["epss_pct_now"].to_numpy(dtype=float),
        "Linear blend": blend_score(df, blend["coefficients"]),
    }


def main():
    cfg = get_config()
    val = validation_rows(load_inputs(cfg))

    config = fl.fit_cutoffs(val)
    config["rules"] = [{"id": rid, "text": text, "consequent": term} for rid, text, _, term in fl.RULES]
    config["tie_break"] = "priority, then cox_risk_pct, then epss_pct_now (fuzzy_layer.ranking_score)"
    config["linear_blend"] = fit_blend(val)

    worst_step = fl.worst_cox_monotonicity_step(config)
    if worst_step < -1e-9:
        raise RuntimeError(f"rule base not monotone in cox_risk: priority drops by {-worst_step:.4g}")
    config["monotonicity_check"] = {"grid": "cox_risk step 0.001 x 101 epss values x 4 CVSS bands + missing",
                                    "worst_step": worst_step}

    priority, firing = fl.score(fl.model_inputs(val), config)
    scores = rankings(val, priority, config["linear_blend"])
    config["validation"] = {
        "rows": len(val), "cves": int(val["cve_id"].nunique()), "events": int(val["composite_event"].sum()),
        "cox_in_sample_caveat": "frozen Cox was fit on the full train set, which includes these rows",
        "metrics": {name: evaluate_model(val, s, label=f"val {name}", log_every=0).as_dict()
                    for name, s in scores.items()},
        "blind_spot_catch_rate_10pct": evaluate_blind_spot_catch_rate(
            val, {k: v for k, v in scores.items() if k != "EPSS"}, scores["EPSS"], label="val", log_every=0,
        )["per_model"],
        "fuzzy_untied_priority_cindex_note": "C-index of raw priority (ties scored 0.5) is in tie_summary",
        "tie_summary": fl.tie_summary(priority),
        "rule_fire_share": (firing > 0).mean().round(4).to_dict(),
        "priority_quantiles_10_50_90_99": np.quantile(priority, [0.1, 0.5, 0.9, 0.99]).round(3).tolist(),
    }
    config["designed_at_utc"] = datetime.now(timezone.utc).isoformat()
    config["design_data"] = "validation rows only (train split, published 2024-07-01..2024-12-31)"

    with open(cfg.project_root / "models" / "fuzzy_config.json", "w") as f:
        json.dump(config, f, indent=2, default=str)
    print(json.dumps({k: config[k] for k in ("validation_quantiles", "linear_blend", "validation")},
                     indent=2, default=str))


if __name__ == "__main__":
    main()
