"""
Lead-time analysis: POST-HOC and DESCRIPTIVE, not a pre-registered metric.
Frozen Cox and EPSS-alone (epss_pct_now) on the default test set,
corrected encoding; nothing is fit.

For every test CVE that is later KEV-listed, over its landmark rows
(7/14/30; a row exists only while the CVE is still unlisted):
  - a model "catches" the CVE at a landmark if that row is in the model's
    top 10% of THAT landmark's test rows (same top-k rule as
    recall_at_budget);
  - lead time = days from the earliest catching landmark's as_of_date to
    the KEV listing (the row's event_time);
  - a model that never catches the CVE gets lead time 0 (no warning
    before the listing), so Cox's lead over EPSS (lead_cox - lead_epss) is
    defined for every CVE at least one model caught. The both-caught subset
    is reported separately.
Blind-spot subgroup: listed CVEs EPSS never placed in its top 10% at any of
their landmarks.

The top-10% thresholds use the whole test period's rows at each landmark,
i.e. a retrospective budget, not one a defender would have had in real
time. CIs: CVE-level bootstrap (common._bootstrap_rows, same seed, 200
resamples) over the listed CVEs, with the thresholds held fixed.

Writes scratch/lead_time.json.

Usage: python -m scripts.evaluate.lead_time
"""

from __future__ import annotations

import json

import numpy as np
import pandas as pd

from config.config_schema import get_config
from scripts.evaluate.common import (
    DEFAULT_SEED,
    _bootstrap_rows,
    _summarize,
    fast_concordance_index,
)
from scripts.evaluate.final_comparison import _prep
from scripts.evaluate.sensitivity import frozen_cox_scores

BUDGET = 0.10


def top_budget_per_landmark(df: pd.DataFrame, score: np.ndarray, budget: float = BUDGET) -> np.ndarray:
    flag = np.zeros(len(df), dtype=bool)
    for lm in df["landmark_day"].unique():
        idx = np.flatnonzero((df["landmark_day"] == lm).to_numpy())
        n_top = max(1, int(np.ceil(len(idx) * budget)))
        flag[idx[np.argsort(-score[idx])[:n_top]]] = True
    return flag


def per_cve_table(test_df: pd.DataFrame, cox: np.ndarray) -> pd.DataFrame:
    epss = test_df["epss_pct_now"].fillna(0).to_numpy()
    rows = test_df.assign(cox_top=top_budget_per_landmark(test_df, cox),
                          epss_top=top_budget_per_landmark(test_df, epss),
                          landmark=test_df["landmark_day"].astype(int),
                          days_to_kev=np.floor(test_df["event_time"]).astype(int))
    rows = rows[rows["composite_event"].astype(bool)]

    def first_catch(g: pd.DataFrame, col: str):
        hit = g[g[col]].sort_values("landmark")
        return (int(hit["landmark"].iloc[0]), int(hit["days_to_kev"].iloc[0])) if len(hit) else (None, 0)

    out = []
    for cve, g in rows.groupby("cve_id"):
        cox_lm, cox_lead = first_catch(g, "cox_top")
        epss_lm, epss_lead = first_catch(g, "epss_top")
        out.append({"cve_id": cve, "n_landmarks": len(g), "cox_landmark": cox_lm, "cox_lead_days": cox_lead,
                    "epss_landmark": epss_lm, "epss_lead_days": epss_lead})
    t = pd.DataFrame(out)
    t["cox_caught"], t["epss_caught"] = t["cox_landmark"].notna(), t["epss_landmark"].notna()
    t["cox_minus_epss_days"] = t["cox_lead_days"] - t["epss_lead_days"]
    return t


STAT_NAMES = [
    "either_median", "either_q25", "either_q75", "either_mean",
    "both_median", "both_q25", "both_q75",
    "n_cox_only", "n_epss_only", "n_both", "n_neither",
    "blind_n", "blind_cox_caught", "blind_cox_catch_rate", "blind_cox_lead_median", "blind_cox_lead_q25",
    "blind_cox_lead_q75",
]


def stats(t: pd.DataFrame) -> np.ndarray:
    either = t[t["cox_caught"] | t["epss_caught"]]["cox_minus_epss_days"]
    both = t[t["cox_caught"] & t["epss_caught"]]["cox_minus_epss_days"]
    blind = t[~t["epss_caught"]]
    blind_lead = blind.loc[blind["cox_caught"], "cox_lead_days"]

    def q(s, p):
        return float(np.percentile(s, p)) if len(s) else np.nan

    return np.array([
        q(either, 50), q(either, 25), q(either, 75), float(either.mean()) if len(either) else np.nan,
        q(both, 50), q(both, 25), q(both, 75),
        int((t["cox_caught"] & ~t["epss_caught"]).sum()), int((~t["cox_caught"] & t["epss_caught"]).sum()),
        int((t["cox_caught"] & t["epss_caught"]).sum()), int((~t["cox_caught"] & ~t["epss_caught"]).sum()),
        len(blind), int(blind["cox_caught"].sum()), blind["cox_caught"].mean() if len(blind) else np.nan,
        q(blind_lead, 50), q(blind_lead, 25), q(blind_lead, 75),
    ], dtype=float)


def lead_time_results(test_df: pd.DataFrame, cox: np.ndarray) -> tuple[dict, pd.DataFrame]:
    t = per_cve_table(test_df, cox)
    point = stats(t)
    samples = _bootstrap_rows(t["cve_id"].to_numpy(), lambda idx: stats(t.iloc[idx]), len(STAT_NAMES),
                              n_resamples=200, seed=DEFAULT_SEED, log_every=50, log_label="lead time")
    out = {
        "n_listed_cves": len(t),
        "stats": {n: _summarize(point[j], samples[:, j]).as_dict() for j, n in enumerate(STAT_NAMES)},
        "first_catch_landmark": {
            m: {str(k): int(v) for k, v in t[f"{m}_landmark"].value_counts(dropna=False).sort_index().items()}
            for m in ("cox", "epss")},
        "lead_days_distribution": {
            "cox_given_caught": t.loc[t["cox_caught"], "cox_lead_days"].describe().to_dict(),
            "epss_given_caught": t.loc[t["epss_caught"], "epss_lead_days"].describe().to_dict()},
    }
    return out, t


def main():
    cfg = get_config()
    models_dir = cfg.project_root / "models"
    _, test_df = _prep()
    cox = frozen_cox_scores(test_df, models_dir)
    recorded = json.loads((models_dir / "cox_final_metadata.json").read_text())[
        "test_metrics_corrected_encoding"]["test_cindex"]
    got = fast_concordance_index(test_df["event_time"].clip(lower=0.5).values, cox,
                                 test_df["composite_event"].values.astype(int))
    if abs(got - recorded) > 1e-9:
        raise RuntimeError(f"frozen Cox C-index {got} != recorded corrected-encoding {recorded}")

    out, t = lead_time_results(test_df, cox)
    t.to_csv(cfg.project_root / "scratch" / "lead_time_per_cve.csv", index=False)
    with open(cfg.project_root / "scratch" / "lead_time.json", "w") as f:
        json.dump(out, f, indent=2, default=str)
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
