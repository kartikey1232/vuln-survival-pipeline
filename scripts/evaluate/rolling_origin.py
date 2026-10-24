"""
Rolling-origin consistency check for Cox vs EPSS-alone. The frozen
2025-01-01 Cox model stays the headline; the other folds are a consistency
check, not competing results.

For each cutoff k: refit Cox under the SAME recipe as the frozen model
(final_comparison._fit_cox: penalizer 0.1, MODEL_FEATURE_COLUMNS, one-hot
on train, constant columns dropped, test encoded with encode_for_model,
train-median imputation). No hyperparameter, feature or design choice
changes; this is a refit, not re-tuning.

  TRAIN  CVEs published before k, rows with as_of_date before k (the
         build's condition 3 at k), labels censored at k
         (data_splits._relabel).
  TEST   CVEs published in [k, k + 6 months), labels observed to the data
         cutoff 2026-09-20. Test windows are disjoint. Every window ends by
         2026-01-01, so every test CVE is inside the build's 180-day
         minimum follow-up (STUDY_END = 2026-03-24).

Rows come from ONE in-memory rebuild of the full landmark grid
(build(train_test_cutoff=STUDY_START): no condition-3 drops, every label
observed to the data cutoff), version-transition rows excluded as in the
default export. training.training_dataset lacks rows whose as_of_date
crosses 2025-01-01 for CVEs published before it, which would truncate the
2024-07-01 fold's test window. The rebuild is first checked to reproduce
training_dataset exactly (features and labels, train rows relabeled at
2025-01-01) or the script refuses to run.

build() reads the current KEV catalog, which lists 6 test CVEs the stored
table's catalog did not (scripts/evaluate/label_corrections.py). main()
gives those rows their stored labels, so the recorded numbers stay
reproducible; scripts/evaluate/corrected_labels.py runs the folds with the
corrected ones.

Sanity check: the 2025-01-01 refit must reproduce the frozen model's scores
and its recorded corrected-encoding headline C-index on the full test set.

Writes scratch/rolling_origin.json.

Usage: python -m scripts.evaluate.rolling_origin
"""

from __future__ import annotations

import json
import logging

import numpy as np
import pandas as pd

from config.config_schema import get_config
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.evaluate.common import evaluate_model, fast_concordance_index, paired_bootstrap_compare
from scripts.evaluate.data_splits import VAL_CUTOFF, _relabel, load_full_train_and_test
from scripts.evaluate.features import impute_numeric, prepare_raw
from scripts.evaluate.final_comparison import _fit_cox
from scripts.evaluate.label_corrections import set_labels
from scripts.evaluate.sensitivity import frozen_cox_scores
from scripts.features.build_landmark_dataset import (
    MODEL_FEATURE_COLUMNS,
    STUDY_END,
    STUDY_START,
    build,
    round_to_storage,
)
from scripts.models.xgboost_aft import _fix_zero_durations

logger = get_logger(__name__, category="evaluate")

CUTOFFS = [pd.Timestamp(d) for d in ("2024-01-01", "2024-07-01", "2025-01-01", "2025-07-01")]
WINDOW = pd.DateOffset(months=6)
HEADLINE_CUTOFF = VAL_CUTOFF  # 2025-01-01
CHECK_COLUMNS = [c for c in MODEL_FEATURE_COLUMNS if c != "landmark_day"] + [
    "event_time", "composite_event", "epss_score_at_asof_raw"]


def full_grid() -> pd.DataFrame:
    df = build(train_test_cutoff=STUDY_START)
    df = round_to_storage(df[~df["spans_version_transition"]].reset_index(drop=True))
    df["composite_event"] = df["event_observed"].astype(bool)
    return df


def _check_against_training_dataset(grid: pd.DataFrame, td: pd.DataFrame | None = None) -> None:
    """The headline split rebuilt from the grid must equal training_dataset
    (or `td`, a relabelled copy of it)."""
    if td is None:
        td = pd.concat(load_full_train_and_test(), ignore_index=True)
    train = _relabel(grid[(grid["published_date"] < HEADLINE_CUTOFF) & (grid["as_of_date"] < HEADLINE_CUTOFF)],
                     HEADLINE_CUTOFF)
    test = grid[grid["published_date"] >= HEADLINE_CUTOFF]
    rebuilt = pd.concat([train, test], ignore_index=True)
    if len(rebuilt) != len(td):
        raise RuntimeError(f"rebuilt headline split has {len(rebuilt)} rows, training_dataset {len(td)}")
    key = ["cve_id", "landmark_day"]
    m = td[key + CHECK_COLUMNS].merge(rebuilt[key + CHECK_COLUMNS], on=key, suffixes=("", "_rb"),
                                      validate="one_to_one")
    if len(m) != len(td):
        raise RuntimeError(f"only {len(m)} of {len(td)} training_dataset rows found in the rebuild")
    for c in CHECK_COLUMNS:
        a, b = m[c], m[f"{c}_rb"]
        same = (a == b) | (a.isna() & b.isna())
        if pd.api.types.is_numeric_dtype(a) and pd.api.types.is_numeric_dtype(b) and a.dtype != bool:
            same |= np.isclose(a.astype(float), b.astype(float), rtol=0, atol=1e-12)
        if not same.all():
            raise RuntimeError(f"rebuild differs from training_dataset on {c}: {int((~same).sum())} rows")


def _counts(df: pd.DataFrame) -> dict:
    ev = df["composite_event"].astype(bool)
    return {"n_rows": len(df), "n_cves": int(df["cve_id"].nunique()), "n_events": int(ev.sum()),
            "n_event_cves": int(df.loc[ev, "cve_id"].nunique())}


def fold_frames(grid: pd.DataFrame, k: pd.Timestamp):
    train = _relabel(grid[(grid["published_date"] < k) & (grid["as_of_date"] < k)], k).reset_index(drop=True)
    test = grid[(grid["published_date"] >= k) & (grid["published_date"] < k + WINDOW)].reset_index(drop=True)
    assert test["published_date"].max() <= pd.Timestamp(STUDY_END)  # 180-day follow-up rule
    train = _fix_zero_durations(prepare_raw(train), f"train<{k.date()}")
    test = _fix_zero_durations(prepare_raw(test), f"test {k.date()}")
    return impute_numeric(train, test)


def evaluate_fold(test: pd.DataFrame, cox: np.ndarray, label: str) -> dict:
    epss = test["epss_pct_now"].fillna(0).to_numpy()  # EPSS-alone, as everywhere else
    return {"Cox": evaluate_model(test, cox, label=f"Cox {label}").as_dict(),
            "EPSS-alone": evaluate_model(test, epss, label=f"EPSS {label}").as_dict(),
            "paired_cox_minus_epss": paired_bootstrap_compare(test, cox, epss, label=f"Cox vs EPSS {label}")}


def headline_sanity(grid: pd.DataFrame, models_dir) -> dict:
    """The 2025-01-01 refit vs the frozen model, on the FULL headline test."""
    train, _ = fold_frames(grid, HEADLINE_CUTOFF)
    full_test = grid[grid["published_date"] >= HEADLINE_CUTOFF].reset_index(drop=True)
    _, full_test = impute_numeric(train, _fix_zero_durations(prepare_raw(full_test), "headline test"))
    refit = _fit_cox(train, full_test, MODEL_FEATURE_COLUMNS)
    frozen = frozen_cox_scores(full_test, models_dir)
    duration = full_test["event_time"].clip(lower=0.5).values
    event = full_test["composite_event"].values.astype(int)
    recorded = json.loads((models_dir / "cox_final_metadata.json").read_text())[
        "test_metrics_corrected_encoding"]["test_cindex"]
    out = {"n_rows": len(full_test), "n_events": int(event.sum()),
           "max_rel_score_diff": float(np.max(np.abs(refit - frozen) / np.abs(frozen))),
           "refit_cindex": fast_concordance_index(duration, refit, event),
           "frozen_cindex": fast_concordance_index(duration, frozen, event), "recorded_cindex": recorded}
    if abs(out["refit_cindex"] - recorded) > 1e-9 or out["max_rel_score_diff"] > 1e-6:
        raise RuntimeError(f"2025-01-01 refit does not reproduce the frozen model: {out}")
    return out


def evaluate_folds(grid: pd.DataFrame, models_dir) -> dict:
    folds = {}
    for k in CUTOFFS:
        train, test = fold_frames(grid, k)
        cox = _fit_cox(train, test, MODEL_FEATURE_COLUMNS)
        label = str(k.date())
        fold = {"train_cutoff": label, "test_window": [label, str((k + WINDOW).date())],
                "train": _counts(train), "test": _counts(test), **evaluate_fold(test, cox, label)}
        if k == HEADLINE_CUTOFF:  # same rows, frozen model: must be identical
            fold["frozen_model_on_fold_rows"] = evaluate_model(test, frozen_cox_scores(test, models_dir),
                                                               label="frozen Cox 2025-01-01 fold").as_dict()
        folds[label] = fold
        p = fold["paired_cox_minus_epss"]
        print(label, fold["train"], fold["test"], f"Cox C={fold['Cox']['cindex']['point']:.4f}",
              f"EPSS C={fold['EPSS-alone']['cindex']['point']:.4f}",
              {m: (round(v["point_diff"], 4), round(v["ci_lower"], 4), round(v["ci_upper"], 4), v["excludes_zero"])
               for m, v in p.items()})
    return folds


def main():
    cfg = get_config()
    models_dir = cfg.project_root / "models"
    grid, _ = set_labels(full_grid(), "stored")
    _check_against_training_dataset(grid)
    log_with_fields(logger, logging.INFO, "rebuild matches training_dataset", rows=len(grid))

    out = {"headline_sanity": headline_sanity(grid, models_dir)}
    log_with_fields(logger, logging.INFO, "2025-01-01 refit reproduces frozen model", **out["headline_sanity"])
    out["folds"] = evaluate_folds(grid, models_dir)

    with open(cfg.project_root / "scratch" / "rolling_origin.json", "w") as f:
        json.dump(out, f, indent=2, default=str)
    print(json.dumps(out["headline_sanity"], indent=2))


if __name__ == "__main__":
    main()
