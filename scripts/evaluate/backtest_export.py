"""
Exports the corrected-encoding backtest (docs/results_corrected_encoding.md)
as a committed artifact the API serves at GET /backtest and the dashboard's
backtesting view reads: the model-comparison table, paired differences vs
EPSS, blind-spot rates, the fuzzy-vs-reference table, and a recall-at-budget
curve (point estimates on the budget grid of scripts/eda/recall_at_budget_figure.py).

Nothing is fit. Curve scores come from the FROZEN models with the corrected
test encoding (and the fuzzy ranking from data/training/fuzzy_priority.parquet,
the corrected evaluate_fuzzy run). Tables are copied from
scratch/results_corrected_encoding.json and scratch/fuzzy_evaluation.json.
Refuses to write unless the frozen Cox reproduces the corrected C-index.

Usage: python -m scripts.evaluate.backtest_export
"""

from __future__ import annotations

import json

import numpy as np
import pandas as pd

from config.config_schema import get_config
from scripts.evaluate.common import fast_concordance_index, recall_at_budget
from scripts.evaluate.final_comparison import _prep
from scripts.evaluate.post_freeze_metrics import load_frozen_predictions

BUDGETS = np.concatenate([np.arange(0.005, 0.05, 0.005), np.arange(0.05, 0.31, 0.01)])
MODELS = ("Cox", "RSF", "XGBoost-AFT", "EPSS-alone")


def main():
    cfg = get_config()
    root = cfg.project_root
    _, test_df = _prep()
    event = test_df["composite_event"].to_numpy().astype(int)
    duration = test_df["event_time"].clip(lower=0.5).to_numpy()

    scores, _, _ = load_frozen_predictions(test_df, root / "models", encoding="corrected")
    scores["EPSS-alone"] = test_df["epss_pct_now"].fillna(0).to_numpy()
    expected = json.loads((root / "models" / "cox_final_metadata.json").read_text())[
        "test_metrics_corrected_encoding"]["test_cindex"]
    if abs(fast_concordance_index(duration, scores["Cox"], event) - expected) > 1e-9:
        raise RuntimeError("frozen Cox does not reproduce the corrected test C-index")

    fuzzy = pd.read_parquet(root / "data" / "training" / "fuzzy_priority.parquet")
    fuzzy = fuzzy[fuzzy["split"] == "test"][["cve_id", "landmark_day", "fuzzy_rank_score"]]
    keyed = test_df[["cve_id", "landmark_day"]].astype({"landmark_day": int}).merge(
        fuzzy, on=["cve_id", "landmark_day"], how="left", validate="one_to_one")
    if keyed["fuzzy_rank_score"].isna().any():
        raise RuntimeError("fuzzy_priority.parquet does not cover every test row")
    curve_scores = {**{m: scores[m] for m in MODELS}, "Fuzzy (explanation layer)": keyed["fuzzy_rank_score"].to_numpy()}

    results = json.loads((root / "scratch" / "results_corrected_encoding.json").read_text())["corrected"]
    fuzzy_eval = json.loads((root / "scratch" / "fuzzy_evaluation.json").read_text())
    if fuzzy_eval.get("encoding") != "corrected":
        raise RuntimeError("scratch/fuzzy_evaluation.json is not the corrected-encoding run")

    out = {
        "source": "docs/results_corrected_encoding.md (frozen models, corrected test encoding, nothing refit)",
        "test_rows": len(test_df), "test_cves": int(test_df["cve_id"].nunique()), "test_events": int(event.sum()),
        "bootstrap": "200 whole-CVE resamples, seed 20260922",
        "models": {m: {"cindex": results["metrics"][m]["cindex"],
                       "recall_at_budget": results["metrics"][m]["recall_at_budget"],
                       "per_landmark_cindex": {lm: r["cindex"]["point"] for lm, r in results["per_landmark"][m].items()}}
                   for m in MODELS},
        "paired_vs_epss": results["paired_vs_epss"],
        "blind_spot_catch_rate_10pct": results["blind_spot_catch_rate_10pct"],
        "time_dependent_auc_pooled": {m: {h: v["point"] for h, v in d.items()}
                                      for m, d in results["time_dependent_auc"]["pooled"].items()},
        "fuzzy": {"metrics": fuzzy_eval["metrics"], "paired_fuzzy_minus_reference": fuzzy_eval["paired_fuzzy_minus_reference"],
                  "blind_spot_catch_rate_10pct": fuzzy_eval["blind_spot_catch_rate_10pct"]},
        "recall_curve": {"budgets": [round(float(b), 4) for b in BUDGETS],
                         "recall": {m: [float(recall_at_budget(s, event, b)) for b in BUDGETS]
                                    for m, s in curve_scores.items()}},
    }
    path = root / "models" / "backtest_corrected_encoding.json"
    path.write_text(json.dumps(out, indent=2, default=str))
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
