"""
Corrected-encoding re-evaluation of the FROZEN models on test. Nothing is
refit, re-tuned or re-featured: the same frozen Cox / RSF / XGBoost-AFT,
the same test rows, the same seed and 200 whole-CVE resamples, through
scripts/evaluate/common.py. Only the test frame's one-hot encoding changes
(scripts/evaluate/features.py::encode_against): "original" dropped the TEST
frame's first category, "corrected" drops relative to the training frame.

Both encodings are computed here, from the same frozen models on the same
resamples, so every original/corrected pair differs only by encoding.
(docs/model_comparison.md's main table came from final_comparison.py
refits; RSF is not run-to-run reproducible, so its frozen-model numbers
differ slightly from that table even under the original encoding.)

Before anything else, the original encoding must reproduce each frozen
model's recorded test C-index exactly; otherwise this refuses to run.

Writes scratch/results_corrected_encoding.json and
docs/figures/calibration_90d_corrected_encoding.png, and ADDS
"test_metrics_corrected_encoding" to each models/*_final_metadata.json
(the recorded "test_metrics" are left as they are).

Usage: python -m scripts.evaluate.corrected_encoding
"""

from __future__ import annotations

import json
import logging

import numpy as np

from config.config_schema import get_config
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.evaluate.common import (
    evaluate_blind_spot_catch_rate,
    evaluate_model,
    evaluate_model_per_landmark,
    paired_bootstrap_compare,
    survival_array,
)
from scripts.evaluate.final_comparison import _prep
from scripts.evaluate.post_freeze_metrics import (
    _check_frozen_metrics,
    censoring_sensitivity,
    load_frozen_predictions,
    step1_time_dependent_auc,
    step2_cox_brier_and_calibration,
    step3_xgb_cindex_vs_epss,
)

logger = get_logger(__name__, category="evaluate")

MODELS = ("Cox", "RSF", "XGBoost-AFT")
METADATA_FILES = {"Cox": "cox_final_metadata.json", "RSF": "rsf_final_metadata.json",
                  "XGBoost-AFT": "xgboost_aft_final_metadata.json"}


def headline_metrics(test_df, scores: dict) -> dict:
    """The docs/model_comparison.md main-table metrics for one encoding."""
    epss = test_df["epss_pct_now"].fillna(0).to_numpy()  # EPSS-alone, as in model_comparison.md
    rankings = {**{m: scores[m] for m in MODELS}, "EPSS-alone": epss}
    out = {
        "metrics": {n: evaluate_model(test_df, s, label=n).as_dict() for n, s in rankings.items()},
        "per_landmark": {n: {str(lm): r.as_dict() for lm, r in
                             evaluate_model_per_landmark(test_df, s, label=n, log_every=0).items()}
                         for n, s in rankings.items()},
        "paired_vs_epss": {m: paired_bootstrap_compare(test_df, scores[m], epss, label=f"{m} vs EPSS")
                           for m in MODELS},
    }
    bs = evaluate_blind_spot_catch_rate(test_df, {m: scores[m] for m in MODELS}, epss, label="blind-spot",
                                        reference="Cox")
    out["blind_spot_catch_rate_10pct"] = bs["per_model"]
    out["blind_spot_paired_vs_cox"] = bs["paired_vs_reference"]
    return out


def post_freeze(test_df, train_df, scores: dict, cox_model, X_cox, y_train, figure_path) -> dict:
    """docs/final_results.md's time-dependent AUC, Brier/IPA/calibration
    and XGBoost-AFT-vs-EPSS numbers for one set of frozen-model scores."""
    log_with_fields(logger, logging.INFO, "post-freeze metrics, corrected encoding")
    return {
        "time_dependent_auc": step1_time_dependent_auc(test_df, scores, y_train),
        "cox_brier_calibration": step2_cox_brier_and_calibration(test_df, train_df, cox_model, X_cox, y_train,
                                                                 figure_path),
        "xgb_cindex_vs_epss": step3_xgb_cindex_vs_epss(test_df, scores),
        "censoring_from_test_sensitivity": censoring_sensitivity(test_df, scores, cox_model, X_cox),
    }


def main():
    cfg = get_config()
    models_dir = cfg.project_root / "models"
    train_df, test_df = _prep()
    y_train = survival_array(train_df["event_time"].clip(lower=0.5).values, train_df["composite_event"].values)

    original, _, _ = load_frozen_predictions(test_df, models_dir, encoding="original")
    _check_frozen_metrics(test_df, original, models_dir)  # raises unless recorded C-indexes reproduce
    corrected, cox_model, X_cox = load_frozen_predictions(test_df, models_dir, encoding="corrected")
    changed = {m: int((np.abs(original[m] - corrected[m]) > 1e-12).sum()) for m in MODELS}
    log_with_fields(logger, logging.INFO, "rows whose score changes with encoding", **changed)

    results = {"rows_with_changed_score": changed}
    for name, scores in (("original", original), ("corrected", corrected)):
        log_with_fields(logger, logging.INFO, "headline metrics", encoding=name)
        results[name] = headline_metrics(test_df, scores)

    results["corrected"].update(post_freeze(
        test_df, train_df, corrected, cox_model, X_cox, y_train,
        cfg.project_root / "docs" / "figures" / "calibration_90d_corrected_encoding.png"))

    with open(cfg.project_root / "scratch" / "results_corrected_encoding.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    for m in MODELS:
        path = models_dir / METADATA_FILES[m]
        meta = json.loads(path.read_text())
        r = results["corrected"]["metrics"][m]
        meta["test_metrics_corrected_encoding"] = {
            "test_cindex": r["cindex"]["point"],
            "test_recall_5pct": r["recall_at_budget"]["5pct"]["point"],
            "test_recall_10pct": r["recall_at_budget"]["10pct"]["point"],
            "note": "Same frozen model, test frame one-hot encoded relative to the TRAINING frame's categories "
                    "(scripts/evaluate/features.py::encode_for_model). 'test_metrics' above were computed with "
                    "the original encoding, which dropped the test frame's own first category. Nothing refit. "
                    "See docs/results_corrected_encoding.md.",
        }
        path.write_text(json.dumps(meta, indent=2, default=str))
    print(json.dumps({k: results[k] for k in ("rows_with_changed_score",)}, indent=2))


if __name__ == "__main__":
    main()
