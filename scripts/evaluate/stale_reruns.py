"""
Re-runs the two analyses that predated the encoding correction, with the
corrected test encoding and nothing else changed:

1. XGBoost-AFT trajectory ablation: (a) full, (b) minus the 6 EPSS
   trajectory features, (c) minus all EPSS features — the same feature
   sets, metrics and paired comparisons as
   scripts/evaluate/cox_trajectory_ablation.py, with XGBoost-AFT's chosen
   config (final_comparison.XGB_CONFIG, not re-tuned).
2. RSF run-to-run variance: the chosen RSF config refit with
   random_state 0, 1, 2 (final_comparison.step5_rsf_variance).

final_comparison's fit helpers already encode test with encode_for_model;
the recorded runs (scratch/final_comparison_results.json) predate that.

Writes scratch/stale_reruns.json.

Usage: python -m scripts.evaluate.stale_reruns
"""

from __future__ import annotations

import json
import logging

from config.config_schema import get_config
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.evaluate.common import fast_concordance_index, paired_bootstrap_compare, recall_at_budget
from scripts.evaluate.final_comparison import (
    EPSS_FEATURES,
    TRAJECTORY_FEATURES,
    _fit_xgb,
    _prep,
    step5_rsf_variance,
)
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS

logger = get_logger(__name__, category="evaluate")


def xgb_trajectory_ablation(train_df, test_df):
    full_score = _fit_xgb(train_df, test_df, MODEL_FEATURE_COLUMNS)
    b_score = _fit_xgb(train_df, test_df, [c for c in MODEL_FEATURE_COLUMNS if c not in TRAJECTORY_FEATURES])
    c_score = _fit_xgb(train_df, test_df, [c for c in MODEL_FEATURE_COLUMNS if c not in EPSS_FEATURES])

    duration = test_df["event_time"].clip(lower=0.5).values
    event = test_df["composite_event"].values.astype(int)

    results = {}
    for name, s in [("a) full model", full_score), ("b) minus trajectory", b_score), ("c) minus all EPSS", c_score)]:
        results[name] = {
            "cindex": fast_concordance_index(duration, s, event),
            "recall_5pct": recall_at_budget(s, event, 0.05),
            "recall_10pct": recall_at_budget(s, event, 0.10),
        }
    results["paired_a_minus_b"] = paired_bootstrap_compare(test_df, full_score, b_score, label="xgb a minus b")
    results["paired_a_minus_c"] = paired_bootstrap_compare(test_df, full_score, c_score, label="xgb a minus c")
    return results


def main():
    cfg = get_config()
    train_df, test_df = _prep()
    frozen = {m: json.loads((cfg.project_root / "models" / f"{m}_final_metadata.json").read_text())[
        "test_metrics_corrected_encoding"]["test_cindex"] for m in ("xgboost_aft", "rsf")}

    log_with_fields(logger, logging.INFO, "XGBoost-AFT trajectory ablation, corrected encoding")
    xgb_ablation = xgb_trajectory_ablation(train_df, test_df)
    xgb_ablation["frozen_model_cindex_corrected_encoding"] = frozen["xgboost_aft"]

    log_with_fields(logger, logging.INFO, "RSF run-to-run variance, corrected encoding")
    rsf_variance = step5_rsf_variance(train_df, test_df)
    rsf_variance["frozen_model_cindex_corrected_encoding"] = frozen["rsf"]

    out = {"encoding": "corrected", "xgb_trajectory_ablation": xgb_ablation, "rsf_variance": rsf_variance}
    print(json.dumps(out, indent=2, default=str))
    with open(cfg.project_root / "scratch" / "stale_reruns.json", "w") as f:
        json.dump(out, f, indent=2, default=str)


if __name__ == "__main__":
    main()
