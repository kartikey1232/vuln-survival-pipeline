"""
Generates docs/figures/recall_at_budget.png — recall-at-alert-budget
curves for all four rankings (EPSS-alone, Cox, RSF, XGBoost-AFT) on test,
across a range of budgets. Refits each model with its already-chosen
config (reusing scripts/evaluate/final_comparison.py's fit helpers), no
tuning. One-off, not a pipeline stage.

Usage: python -m scripts.eda.recall_at_budget_figure
"""

from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from config.config_schema import get_config
from scripts.evaluate.common import recall_at_budget
from scripts.evaluate.final_comparison import _fit_cox, _fit_rsf, _fit_xgb, _prep
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS


def main() -> None:
    cfg = get_config()
    train_df, test_df = _prep()

    scores = {
        "EPSS-alone": test_df["epss_pct_now"].fillna(0).values,
        "Cox": _fit_cox(train_df, test_df, MODEL_FEATURE_COLUMNS),
        "RSF": _fit_rsf(train_df, test_df, MODEL_FEATURE_COLUMNS),
        "XGBoost-AFT": _fit_xgb(train_df, test_df, MODEL_FEATURE_COLUMNS),
    }
    event = test_df["composite_event"].values.astype(int)

    budgets = np.concatenate([np.arange(0.005, 0.05, 0.005), np.arange(0.05, 0.31, 0.01)])

    fig, ax = plt.subplots(figsize=(9, 6))
    for name, s in scores.items():
        recalls = [recall_at_budget(s, event, b) for b in budgets]
        ax.plot(budgets * 100, recalls, label=name, linewidth=2 if name != "EPSS-alone" else 1.5,
                linestyle="--" if name == "EPSS-alone" else "-")

    for b in (0.01, 0.05, 0.10):
        ax.axvline(b * 100, color="gray", linewidth=0.5, linestyle=":")

    ax.set_xlabel("Alert budget (% of test rows, by descending risk score)")
    ax.set_ylabel("Recall (fraction of true KEV events caught)")
    ax.set_title("Recall at alert budget — test set, all landmarks pooled")
    ax.legend()
    fig.tight_layout()

    out_path = cfg.project_root / "docs" / "figures" / "recall_at_budget.png"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
