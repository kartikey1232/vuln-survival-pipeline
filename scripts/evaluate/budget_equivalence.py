"""
Budget equivalence (a computation on the recall-at-budget curves, not new
modelling): for Cox's recall at a 1% / 5% / 10% budget on the default test
set, the smallest EPSS-alone budget that reaches the same recall, and the
ratio of effort (EPSS budget / Cox budget). Frozen Cox, corrected encoding,
pooled over landmarks, the same top-k rule as recall_at_budget
(np.argsort(-score); EPSS ties are broken by that sort, as in every
reported EPSS recall). CIs: CVE-level bootstrap (common._bootstrap_rows,
same seed and 200 resamples as every other metric).

Writes scratch/budget_equivalence.json.

Usage: python -m scripts.evaluate.budget_equivalence
"""

from __future__ import annotations

import json

import numpy as np

from config.config_schema import get_config
from scripts.evaluate.common import (
    DEFAULT_BUDGETS,
    DEFAULT_SEED,
    _bootstrap_rows,
    _summarize,
    fast_concordance_index,
    recall_at_budget,
)
from scripts.evaluate.final_comparison import _prep
from scripts.evaluate.sensitivity import frozen_cox_scores


def matching_budget(score: np.ndarray, event: np.ndarray, target_recall: float) -> float:
    """Smallest budget b (as a fraction of rows) at which ranking by `score`
    reaches `target_recall`: the top ceil(b * n) rows hold that share of
    events, with rows ordered as recall_at_budget orders them."""
    cum = np.cumsum(event[np.argsort(-score)]) / event.sum()
    n_rows = int(np.argmax(cum >= target_recall - 1e-12)) + 1
    return n_rows / len(score)


def equivalence(cox: np.ndarray, epss: np.ndarray, event: np.ndarray) -> np.ndarray:
    out = []
    for b in DEFAULT_BUDGETS:
        r = recall_at_budget(cox, event, b)
        eb = matching_budget(epss, event, r)
        out += [r, recall_at_budget(epss, event, b), eb, eb / b]
    return np.array(out)


def main():
    cfg = get_config()
    models_dir = cfg.project_root / "models"
    _, test_df = _prep()
    cox = frozen_cox_scores(test_df, models_dir)
    epss = test_df["epss_pct_now"].fillna(0).to_numpy()
    event = test_df["composite_event"].values.astype(int)
    recorded = json.loads((models_dir / "cox_final_metadata.json").read_text())[
        "test_metrics_corrected_encoding"]["test_cindex"]
    if abs(fast_concordance_index(test_df["event_time"].clip(lower=0.5).values, cox, event) - recorded) > 1e-9:
        raise RuntimeError("frozen Cox does not reproduce its recorded corrected-encoding C-index")

    names = [f"{s}_{int(b * 100)}pct" for b in DEFAULT_BUDGETS
             for s in ("cox_recall", "epss_recall", "epss_budget_to_match", "effort_ratio")]
    point = equivalence(cox, epss, event)
    samples = _bootstrap_rows(test_df["cve_id"].values, lambda idx: equivalence(cox[idx], epss[idx], event[idx]),
                              len(names), n_resamples=200, seed=DEFAULT_SEED, log_every=50,
                              log_label="budget equivalence")
    out = {n: _summarize(point[j], samples[:, j]).as_dict() for j, n in enumerate(names)}
    with open(cfg.project_root / "scratch" / "budget_equivalence.json", "w") as f:
        json.dump(out, f, indent=2)
    for n, r in out.items():
        print(f"{n:32s} {r['point']:.4f} ({r['ci_lower']:.4f}-{r['ci_upper']:.4f})")


if __name__ == "__main__":
    main()
