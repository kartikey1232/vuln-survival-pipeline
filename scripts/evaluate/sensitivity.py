"""
Test-set sensitivity analyses for the frozen Cox model against EPSS-alone.
Nothing is refit, re-tuned or re-featured: the frozen Cox model, the
corrected encoding (encode_for_model), train-median imputation, the same
seed and 200 whole-CVE resamples, through scripts/evaluate/common.py. Only
the set of test rows changes.

  baseline        the default test set (reproduces the recorded numbers)
  a) +transition  adds back the test rows flagged spans_version_transition
                  (window [published, as_of] contains the 2025-03-17 EPSS
                  v4 release), which the default export drops. They are not
                  in training.training_dataset, so they are rebuilt from the
                  same build's features.temporal_features +
                  features.static_features + training.survival_labels; the
                  rebuild is first checked to reproduce training_dataset
                  exactly on the unflagged test rows.
  b) -VulnCheck   drops CVEs whose CNA (payload sourceIdentifier, the same
                  lookup the feature build uses) is disclosure@vulncheck.com.
  c) CNA CVSS     keeps only rows with a CNA-supplied CVSS score
                  (cvss_cna_missing = false).

For each: Cox and EPSS C-index and recall@1/5/10%, Cox's blind-spot catch
rate at 10% (relative to EPSS's top 10% WITHIN that subset), and the paired
Cox - EPSS difference. Bootstrap resamples are drawn from each subset's
own CVEs with the same seed, so they are not the same CVE sets across
subsets.

Writes scratch/sensitivity.json.

Usage: python -m scripts.evaluate.sensitivity
"""

from __future__ import annotations

import json
import logging
import pickle

import numpy as np
import pandas as pd

from config.config_schema import get_config
from database.engine import get_engine
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.evaluate.common import (
    evaluate_blind_spot_catch_rate,
    evaluate_model,
    fast_concordance_index,
    paired_bootstrap_compare,
)
from scripts.evaluate.data_splits import VAL_CUTOFF, load_full_train_and_test
from scripts.evaluate.features import encode_for_model, impute_numeric, prepare_raw
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS
from scripts.models.xgboost_aft import _fix_zero_durations

logger = get_logger(__name__, category="evaluate")

VULNCHECK_CNA = "disclosure@vulncheck.com"
STATIC_COLUMNS = ["cvss_base_score", "cvss_version", "attack_vector", "attack_complexity", "privileges_required",
                  "user_interaction", "confidentiality_impact", "integrity_impact", "availability_impact"]
TEMPORAL_COLUMNS = [c for c in MODEL_FEATURE_COLUMNS if c not in STATIC_COLUMNS and c != "landmark_day"]
LABEL_COLUMNS = ["event_time", "composite_event"]
CHECK_COLUMNS = [c for c in MODEL_FEATURE_COLUMNS if c != "landmark_day"] + LABEL_COLUMNS + ["epss_score_at_asof_raw"]


def load_rebuilt_test_rows() -> pd.DataFrame:
    """Every test (as_of_date >= 2025-01-01) CVE x landmark row in
    features.temporal_features, flagged or not, joined to its static
    features and label — the same columns training.training_dataset holds."""
    sql = (
        "SELECT t.cve_id, t.checkpoint_day, t.as_of_date, t.spans_version_transition, t.epss_score_at_asof_raw, "
        + ", ".join(f"t.{c}" for c in TEMPORAL_COLUMNS) + ", "
        + ", ".join(f"s.{c}" for c in STATIC_COLUMNS) + ", "
        + ", ".join(f"l.{c}" for c in LABEL_COLUMNS)
        + " FROM features.temporal_features t "
          "JOIN features.static_features s ON s.cve_id = t.cve_id "
          "JOIN training.survival_labels l ON l.cve_id = t.cve_id AND l.checkpoint_day = t.checkpoint_day "
          f"WHERE t.as_of_date >= '{VAL_CUTOFF.date()}'"
    )
    df = pd.read_sql(sql, get_engine(), parse_dates=["as_of_date"])
    df["landmark_day"] = df["checkpoint_day"]
    return df


def _check_rebuild(rebuilt: pd.DataFrame, test_raw: pd.DataFrame) -> None:
    """Refuse to run unless the rebuild matches training_dataset exactly on
    the rows both contain (the unflagged test rows)."""
    unflagged = rebuilt[~rebuilt["spans_version_transition"]]
    key = ["cve_id", "landmark_day"]
    if len(unflagged) != len(test_raw):
        raise RuntimeError(f"rebuilt {len(unflagged)} unflagged test rows, training_dataset has {len(test_raw)}")
    m = test_raw[key + CHECK_COLUMNS].merge(unflagged[key + CHECK_COLUMNS], on=key, suffixes=("", "_rb"),
                                            validate="one_to_one")
    for c in CHECK_COLUMNS:
        a, b = m[c], m[f"{c}_rb"]
        same = (a == b) | (a.isna() & b.isna())
        if pd.api.types.is_float_dtype(a) and pd.api.types.is_float_dtype(b):
            same |= np.isclose(a, b, rtol=0, atol=1e-12)
        if not same.all():
            raise RuntimeError(f"rebuild differs from training_dataset on {c}: {int((~same).sum())} rows")


def cna_by_cve(cve_ids) -> pd.Series:
    src = pd.read_sql(
        "SELECT DISTINCT ON (cve_id) cve_id, payload->>'sourceIdentifier' AS source_identifier "
        "FROM staging.nvd_cve_raw ORDER BY cve_id, fetched_at DESC", get_engine())
    return src.set_index("cve_id")["source_identifier"].reindex(cve_ids)


def frozen_cox_scores(df: pd.DataFrame, models_dir) -> np.ndarray:
    with open(models_dir / "cox_final.pkl", "rb") as f:
        cox = pickle.load(f)
    X = encode_for_model(df, cox["one_hot_columns"]).drop(columns=cox["dropped_const_cols"])
    return cox["model"].predict_partial_hazard(X).values


def _counts(df: pd.DataFrame) -> dict:
    ev = df["composite_event"].astype(bool)
    return {"n_rows": len(df), "n_cves": int(df["cve_id"].nunique()), "n_events": int(ev.sum()),
            "n_event_cves": int(df.loc[ev, "cve_id"].nunique()),
            "per_landmark": {str(lm): {"n_rows": int((df["landmark_day"] == lm).sum()),
                                       "n_events": int(ev[df["landmark_day"] == lm].sum())}
                             for lm in sorted(df["landmark_day"].unique(), key=int)}}


def evaluate_subset(df: pd.DataFrame, cox: np.ndarray, label: str) -> dict:
    df = df.reset_index(drop=True)
    epss = df["epss_pct_now"].fillna(0).to_numpy()  # EPSS-alone, as everywhere else
    log_with_fields(logger, logging.INFO, "sensitivity subset", label=label, rows=len(df))
    return {
        **_counts(df),
        "Cox": evaluate_model(df, cox, label=f"Cox {label}").as_dict(),
        "EPSS-alone": evaluate_model(df, epss, label=f"EPSS {label}").as_dict(),
        "cox_blind_spot_catch_10pct": evaluate_blind_spot_catch_rate(
            df, {"Cox": cox}, epss, label=f"blind-spot {label}")["per_model"]["Cox"],
        "paired_cox_minus_epss": paired_bootstrap_compare(df, cox, epss, label=f"Cox vs EPSS {label}"),
    }


def main():
    cfg = get_config()
    models_dir = cfg.project_root / "models"

    train_raw, test_raw = load_full_train_and_test()
    rebuilt = load_rebuilt_test_rows()
    _check_rebuild(rebuilt, test_raw)
    flagged = rebuilt[rebuilt["spans_version_transition"]]
    log_with_fields(logger, logging.INFO, "transition rows rebuilt", rows=len(flagged))

    # default test rows first (in training_dataset order), flagged rows appended
    test_aug_raw = pd.concat([test_raw, flagged[test_raw.columns.intersection(flagged.columns)]],
                             ignore_index=True)
    is_transition = np.r_[np.zeros(len(test_raw), bool), np.ones(len(flagged), bool)]

    train_df = _fix_zero_durations(prepare_raw(train_raw), "train")
    test_aug = _fix_zero_durations(prepare_raw(test_aug_raw), "test+transition")
    _, test_aug = impute_numeric(train_df, test_aug)
    test_aug["cna"] = cna_by_cve(test_aug["cve_id"]).to_numpy()

    cox = frozen_cox_scores(test_aug, models_dir)

    base = ~is_transition
    recorded = json.loads((models_dir / "cox_final_metadata.json").read_text())[
        "test_metrics_corrected_encoding"]["test_cindex"]
    got = fast_concordance_index(test_aug.loc[base, "event_time"].clip(lower=0.5).values, cox[base],
                                 test_aug.loc[base, "composite_event"].values.astype(int))
    if abs(got - recorded) > 1e-9:
        raise RuntimeError(f"baseline Cox C-index {got} != recorded corrected-encoding {recorded}")

    subsets = {
        "baseline": base,
        "a_with_transition_rows": np.ones(len(test_aug), bool),
        "b_excluding_vulncheck_cna": base & (test_aug["cna"] != VULNCHECK_CNA).to_numpy(),
        "c_cna_cvss_present": base & (test_aug["cvss_cna_missing"] == 0).to_numpy(),
    }
    out = {name: evaluate_subset(test_aug[mask], cox[mask], name) for name, mask in subsets.items()}
    out["a_with_transition_rows"]["added"] = _counts(test_aug[is_transition])
    out["b_excluding_vulncheck_cna"]["removed"] = _counts(
        test_aug[base & (test_aug["cna"] == VULNCHECK_CNA).to_numpy()])
    out["c_cna_cvss_present"]["removed"] = _counts(test_aug[base & (test_aug["cvss_cna_missing"] == 1).to_numpy()])

    with open(cfg.project_root / "scratch" / "sensitivity.json", "w") as f:
        json.dump(out, f, indent=2, default=str)
    for name, r in out.items():
        p = r["paired_cox_minus_epss"]
        print(name, r["n_rows"], r["n_events"], f"Cox C={r['Cox']['cindex']['point']:.4f}",
              f"EPSS C={r['EPSS-alone']['cindex']['point']:.4f}",
              {k: (round(v["point_diff"], 4), round(v["ci_lower"], 4), round(v["ci_upper"], 4), v["excludes_zero"])
               for k, v in p.items()})


if __name__ == "__main__":
    main()
