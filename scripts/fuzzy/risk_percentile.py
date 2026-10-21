"""
Fuzzy-layer input prep: maps the frozen Cox model's risk score to a
percentile (cox_risk_pct) against a TRAINING-period reference
distribution, one reference per landmark (7/14/30).

Why percentiles, not probabilities: frozen Cox's predicted P(KEV <= 90d)
spans only 0.078%-0.184% across all test rows (see STATUS.md's post-freeze
addendum), so there's no usable spread for fuzzy membership functions,
while the ranking itself is sound. EPSS's input is epss_pct_now, already a
percentile, so both fuzzy inputs end up on the same [0, 1] footing.

Definition: cox_risk_pct(x) = #(reference scores <= x) / n_reference, the
same "same or lower" convention as EPSS's own percentile. The reference
is the frozen Cox model's partial hazard on the full train set (the rows
it was fit on), split by landmark_day. A row is NEVER ranked against the
other rows being scored (e.g. within test) — at deployment time only the
training-period distribution exists.

Outputs:
- models/cox_risk_reference.npz (+ _metadata.json): the per-landmark
  sorted training scores. A deployment artifact tied to cox_final.pkl.
- data/training/cox_risk_pct.parquet: cox_risk_pct and epss_pct_now for
  every train and test row (regenerable, not committed).

Usage: python -m scripts.fuzzy.risk_percentile
"""

from __future__ import annotations

import json
import logging
import pickle
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from config.config_schema import get_config
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.evaluate.common import fast_concordance_index
from scripts.evaluate.features import one_hot
from scripts.evaluate.final_comparison import _prep
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS

logger = get_logger(__name__, category="fuzzy")

REFERENCE_FILENAME = "cox_risk_reference.npz"


@dataclass
class RiskReference:
    """Sorted training-period risk scores, one array per landmark day."""

    sorted_scores: dict[int, np.ndarray]

    @classmethod
    def from_scores(cls, scores, landmarks) -> "RiskReference":
        scores = np.asarray(scores, dtype=float)
        landmarks = np.asarray(landmarks).astype(int)
        if np.isnan(scores).any():
            raise ValueError("reference scores contain NaN")
        return cls({int(lm): np.sort(scores[landmarks == lm]) for lm in np.unique(landmarks)})

    def percentile(self, scores, landmarks) -> np.ndarray:
        """Fraction of the row's own-landmark reference with score <= the
        row's score. Monotonic non-decreasing in score within a landmark;
        0.0 below the reference minimum, 1.0 at/above its maximum."""
        scores = np.asarray(scores, dtype=float)
        landmarks = np.asarray(landmarks).astype(int)
        if np.isnan(scores).any():
            raise ValueError("scores contain NaN")
        unknown = set(np.unique(landmarks).tolist()) - set(self.sorted_scores)
        if unknown:
            raise ValueError(f"no reference distribution for landmark(s) {sorted(unknown)}")
        out = np.empty(len(scores), dtype=float)
        for lm, ref in self.sorted_scores.items():
            mask = landmarks == lm
            out[mask] = np.searchsorted(ref, scores[mask], side="right") / len(ref)
        return out

    def save(self, path: Path) -> None:
        np.savez_compressed(path, **{f"landmark_{lm}": ref for lm, ref in self.sorted_scores.items()})

    @classmethod
    def load(cls, path: Path) -> "RiskReference":
        with np.load(path) as data:
            return cls({int(k.removeprefix("landmark_")): data[k] for k in data.files})


def _cox_scores(df: pd.DataFrame, cox: dict) -> np.ndarray:
    """Frozen Cox partial hazard, prepared exactly as at freeze time."""
    X = one_hot(df, MODEL_FEATURE_COLUMNS).reindex(columns=cox["one_hot_columns"], fill_value=0)
    return cox["model"].predict_partial_hazard(X.drop(columns=cox["dropped_const_cols"])).values


def main():
    cfg = get_config()
    models_dir = cfg.project_root / "models"
    train_df, test_df = _prep()

    with open(models_dir / "cox_final.pkl", "rb") as f:
        cox = pickle.load(f)
    with open(models_dir / "cox_final_metadata.json") as f:
        cox_meta = json.load(f)

    train_score = _cox_scores(train_df, cox)
    test_score = _cox_scores(test_df, cox)

    # Refuse to proceed unless the loaded model is the one whose test
    # C-index was recorded at freeze time.
    got = fast_concordance_index(test_df["event_time"].clip(lower=0.5).values, test_score,
                                 test_df["composite_event"].values.astype(int))
    recorded = cox_meta["test_metrics"]["test_cindex"]
    if abs(got - recorded) > 1e-9:
        raise RuntimeError(f"frozen Cox gives test C-index {got}, metadata records {recorded}")

    reference = RiskReference.from_scores(train_score, train_df["landmark_day"])
    reference.save(models_dir / REFERENCE_FILENAME)
    with open(models_dir / "cox_risk_reference_metadata.json", "w") as f:
        json.dump({
            "built_at_utc": datetime.now(timezone.utc).isoformat(),
            "source_model": "cox_final.pkl",
            "source_model_git_commit_hash": cox_meta["git_commit_hash"],
            "dataset_version": cox_meta["dataset_version"],
            "reference_period": "full train set (published < 2025-01-01)",
            "score": "CoxPHFitter.predict_partial_hazard",
            "percentile_definition": "#(reference scores <= x) / n_reference, per landmark_day",
            "n_reference_rows": {str(lm): len(ref) for lm, ref in reference.sorted_scores.items()},
        }, f, indent=2)

    frames = []
    for split, df, score in [("train", train_df, train_score), ("test", test_df, test_score)]:
        if df["epss_pct_now"].isna().any():
            raise RuntimeError(f"{split}: epss_pct_now has missing values")
        frames.append(pd.DataFrame({
            "cve_id": df["cve_id"].values,
            "as_of_date": df["as_of_date"].values,
            "landmark_day": df["landmark_day"].astype(int).values,
            "split": split,
            "cox_risk_score": score,
            "cox_risk_pct": reference.percentile(score, df["landmark_day"]),
            "epss_pct_now": df["epss_pct_now"].values.astype(float),
            "event_time": df["event_time"].values,
            "composite_event": df["composite_event"].values.astype(bool),
        }))
    out = pd.concat(frames, ignore_index=True)
    out_dir = cfg.project_root / "data" / "training"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "cox_risk_pct.parquet"
    out.to_parquet(out_path, index=False)
    log_with_fields(logger, logging.INFO, "cox_risk_pct written", path=str(out_path), rows=len(out))

    summary = {}
    for (split, lm), g in out.groupby(["split", "landmark_day"]):
        summary[f"{split}_landmark_{lm}"] = {
            "rows": len(g),
            "events": int(g["composite_event"].sum()),
            "cox_risk_pct_quantiles_10_50_90": g["cox_risk_pct"].quantile([0.1, 0.5, 0.9]).round(4).tolist(),
            "share_rows_pct_ge_0.9": round(float((g["cox_risk_pct"] >= 0.9).mean()), 4),
            "events_with_pct_ge_0.9": int(g.loc[g["cox_risk_pct"] >= 0.9, "composite_event"].sum()),
        }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
