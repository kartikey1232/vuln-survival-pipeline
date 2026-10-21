"""
One-time TEST evaluation of the fuzzy ranking layer, run after its design
(models/fuzzy_config.json, from scripts/fuzzy/design.py on validation only)
was final and committed. Nothing here changes the design.

Through scripts/evaluate/common.py (shared seed, 200 whole-CVE resamples):
- recall at 1/5/10% and C-index for the fuzzy ranking and three references:
  (a) Cox alone (frozen partial hazard, the 0.849 model),
  (b) EPSS alone (epss_pct_now, as in docs/model_comparison.md),
  (c) the linear blend of the same inputs fitted on validation;
- paired bootstrap differences fuzzy - reference for each;
- blind-spot catch rate at 10%, with paired differences vs (a) and (c)
  (EPSS's own catch rate is 0 by definition).

Also writes the per-row explanation (priority + every rule's firing
strength) for validation and test rows to
data/training/fuzzy_priority.parquet — what the dashboard reads.

Usage: python -m scripts.fuzzy.evaluate_fuzzy
"""

from __future__ import annotations

import json
import logging

import pandas as pd

from config.config_schema import get_config
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.evaluate.common import evaluate_blind_spot_catch_rate, evaluate_model, paired_bootstrap_compare
from scripts.fuzzy import fuzzy_layer as fl
from scripts.fuzzy.design import load_inputs, rankings, validation_rows

logger = get_logger(__name__, category="fuzzy")

REFERENCES = ("Cox", "EPSS", "Linear blend")


def explanation_frame(df: pd.DataFrame, split: str, priority, firing: pd.DataFrame, rank) -> pd.DataFrame:
    out = df[["cve_id", "as_of_date", "landmark_day", "cox_risk_pct", "epss_pct_now",
              "cvss_base_score", "cvss_cna_missing"]].reset_index(drop=True).copy()
    out["blindspot"] = out["cox_risk_pct"] - out["epss_pct_now"]
    out["split"] = split
    out["priority"] = priority
    out["fuzzy_rank_score"] = rank
    out = pd.concat([out, firing.add_prefix("fire_").reset_index(drop=True)], axis=1)
    out["rules_fired"] = fl.explanation_strings(firing)
    return out


def main():
    cfg = get_config()
    config_path = cfg.project_root / "models" / "fuzzy_config.json"
    if not config_path.exists():
        raise RuntimeError("models/fuzzy_config.json missing: run scripts.fuzzy.design (validation only) first")
    config = json.loads(config_path.read_text())
    if config.get("monotonicity_check", {}).get("worst_step", -1) < -1e-9:
        raise RuntimeError("frozen fuzzy config has no passing monotonicity check")

    inputs = load_inputs(cfg)
    test = inputs[inputs["split"] == "test"].reset_index(drop=True)
    val = validation_rows(inputs)

    log_with_fields(logger, logging.INFO, "scoring test rows", rows=len(test))
    priority, firing = fl.score(fl.model_inputs(test), config)
    scores = rankings(test, priority, config["linear_blend"])

    results = {
        "test_rows": len(test), "test_cves": int(test["cve_id"].nunique()),
        "test_events": int(test["composite_event"].sum()),
        "metrics": {name: evaluate_model(test, s, label=f"test {name}").as_dict() for name, s in scores.items()},
        "paired_fuzzy_minus_reference": {
            ref: paired_bootstrap_compare(test, scores["Fuzzy"], scores[ref], label=f"Fuzzy vs {ref}")
            for ref in REFERENCES
        },
        "blind_spot_catch_rate_10pct": {},
        "tie_summary": {f"top_{int(b * 100)}pct": fl.tie_summary(priority, b) for b in (0.01, 0.05, 0.10)},
        "rule_fire_share": (firing > 0).mean().round(4).to_dict(),
        "priority_quantiles_10_50_90_99": pd.Series(priority).quantile([0.1, 0.5, 0.9, 0.99]).round(3).tolist(),
    }
    for ref in ("Cox", "Linear blend"):
        bs = evaluate_blind_spot_catch_rate(
            test, {"Fuzzy": scores["Fuzzy"], ref: scores[ref]}, scores["EPSS"], label=f"test vs {ref}", reference=ref,
        )
        results["blind_spot_catch_rate_10pct"].setdefault("per_model", {}).update(bs["per_model"])
        results["blind_spot_catch_rate_10pct"][f"paired_fuzzy_minus_{ref}"] = bs["paired_vs_reference"]["Fuzzy"]

    val_priority, val_firing = fl.score(fl.model_inputs(val), config)
    explanations = pd.concat([
        explanation_frame(val, "val", val_priority, val_firing,
                          fl.ranking_score(val_priority, val["cox_risk_pct"].to_numpy(), val["epss_pct_now"].to_numpy())),
        explanation_frame(test, "test", priority, firing, scores["Fuzzy"]),
    ], ignore_index=True)
    out_path = cfg.project_root / "data" / "training" / "fuzzy_priority.parquet"
    explanations.to_parquet(out_path, index=False)
    log_with_fields(logger, logging.INFO, "fuzzy explanations written", path=str(out_path), rows=len(explanations))

    with open(cfg.project_root / "scratch" / "fuzzy_evaluation.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
