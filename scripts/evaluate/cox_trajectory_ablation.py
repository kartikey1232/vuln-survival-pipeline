"""
Cox-specific trajectory ablation on test (reporting only, no tuning):
(a) full Cox, (b) minus EPSS trajectory features, (c) minus all EPSS
features. C-index and recall at 5%/10%, with paired bootstrap CIs for
(a)-(b) and (a)-(c), 200 resamples. Reuses the fit/feature-set helpers
already defined in scripts/evaluate/final_comparison.py.

The reduced-feature models have to be fit, so this refits all three
(penalizer 0.1, deterministic). The original run (docs/model_comparison.md)
used the buggy test encoding (--encoding original reproduces it); the
default is the corrected one (docs/results_corrected_encoding.md).

Usage: python -m scripts.evaluate.cox_trajectory_ablation [--encoding original]
"""

from __future__ import annotations

import json
import logging

from config.config_schema import get_config
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.evaluate.common import fast_concordance_index, paired_bootstrap_compare, recall_at_budget
from scripts.evaluate.final_comparison import EPSS_FEATURES, TRAJECTORY_FEATURES, _fit_cox, _prep
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS

logger = get_logger(__name__, category="evaluate")


def cox_trajectory_ablation(train_df, test_df, encoding="corrected"):
    full_score = _fit_cox(train_df, test_df, MODEL_FEATURE_COLUMNS, encoding=encoding)
    b_cols = [c for c in MODEL_FEATURE_COLUMNS if c not in TRAJECTORY_FEATURES]
    b_score = _fit_cox(train_df, test_df, b_cols, encoding=encoding)
    c_cols = [c for c in MODEL_FEATURE_COLUMNS if c not in EPSS_FEATURES]
    c_score = _fit_cox(train_df, test_df, c_cols, encoding=encoding)

    duration = test_df["event_time"].clip(lower=0.5).values
    event = test_df["composite_event"].values.astype(int)

    results = {}
    for name, s in [("a) full model", full_score), ("b) minus trajectory", b_score), ("c) minus all EPSS", c_score)]:
        results[name] = {
            "cindex": fast_concordance_index(duration, s, event),
            "recall_5pct": recall_at_budget(s, event, 0.05),
            "recall_10pct": recall_at_budget(s, event, 0.10),
        }

    results["paired_a_minus_b"] = paired_bootstrap_compare(test_df, full_score, b_score, label="cox a minus b", n_resamples=200)
    results["paired_a_minus_c"] = paired_bootstrap_compare(test_df, full_score, c_score, label="cox a minus c", n_resamples=200)
    return results


def main(encoding="corrected"):
    cfg = get_config()
    train_df, test_df = _prep()

    log_with_fields(logger, logging.INFO, "Cox trajectory ablation", encoding=encoding)
    out = cox_trajectory_ablation(train_df, test_df, encoding)
    out["encoding"] = encoding

    print(json.dumps(out, indent=2, default=str))
    suffix = "" if encoding == "corrected" else "_original_encoding"
    with open(cfg.project_root / "scratch" / f"cox_trajectory_ablation{suffix}.json", "w") as f:
        json.dump(out, f, indent=2, default=str)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--encoding", choices=["corrected", "original"], default="corrected",
                        help="test-frame encoding; 'original' reproduces the numbers in docs/model_comparison.md")
    main(parser.parse_args().encoding)
