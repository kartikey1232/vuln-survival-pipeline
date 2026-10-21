"""
Exports what serving needs to prepare a single row for the frozen Cox
model, which cox_final.pkl does not store: the training-set medians used
to impute numeric features (impute_numeric on the full train set, exactly
as at freeze time). Writes models/cox_serving_preprocessing.json.

Verifies before writing:
1. Training rows prepared the serving way (per-row median fill +
   encode_for_model) give EXACTLY the scores of the frozen fit-time design
   matrix (one_hot on the full train frame, whose first categories are the
   training reference categories, so that path was correct).
2. Records the test C-index under correct encoding next to the frozen one:
   they differ because the frozen test evaluation used one_hot on the test
   frame (see scripts/evaluate/features.py::encode_for_model).

Usage: python -m scripts.models.export_serving_preprocessing
"""

from __future__ import annotations

import json
import pickle

import numpy as np

from config.config_schema import get_config
from scripts.evaluate.common import fast_concordance_index
from scripts.evaluate.data_splits import load_full_train_and_test
from scripts.evaluate.features import NUMERIC, encode_for_model, one_hot, prepare_raw
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS


def prepare_rows(raw, medians: dict) -> "pd.DataFrame":  # noqa: F821
    df = prepare_raw(raw)
    for c, m in medians.items():
        df[c] = df[c].fillna(m)
    return df


def main():
    cfg = get_config()
    models_dir = cfg.project_root / "models"
    with open(models_dir / "cox_final.pkl", "rb") as f:
        cox = pickle.load(f)
    with open(models_dir / "cox_final_metadata.json") as f:
        meta = json.load(f)

    train_raw, test_raw = load_full_train_and_test()
    train_prep = prepare_raw(train_raw)
    medians = {c: float(train_prep[c].median()) for c in NUMERIC}

    def scores(X):
        return cox["model"].predict_partial_hazard(X.drop(columns=cox["dropped_const_cols"])).values

    train_serving = scores(encode_for_model(prepare_rows(train_raw, medians), cox["one_hot_columns"]))
    train_frozen = scores(one_hot(prepare_rows(train_raw, medians), MODEL_FEATURE_COLUMNS)
                          .reindex(columns=cox["one_hot_columns"], fill_value=0).astype(float))
    if not np.array_equal(train_serving, train_frozen):
        raise RuntimeError(f"serving path differs from fit-time path on train: max diff "
                           f"{np.abs(train_serving - train_frozen).max()}")

    test_serving = scores(encode_for_model(prepare_rows(test_raw, medians), cox["one_hot_columns"]))
    corrected = fast_concordance_index(test_raw["event_time"].clip(lower=0.5).values, test_serving,
                                       test_raw["composite_event"].values.astype(int))
    out = {
        "source_model": "cox_final.pkl",
        "source_model_git_commit_hash": meta["git_commit_hash"],
        "dataset_version": meta["dataset_version"],
        "numeric_medians_from": "full train set after prepare_raw (as scripts/evaluate/features.py::impute_numeric)",
        "numeric_medians": medians,
        "encoding": "scripts/evaluate/features.py::encode_for_model",
        "verified_identical_to_fit_time_scores_on_train_rows": len(train_raw),
        "test_cindex_frozen_metadata": meta["test_metrics"]["test_cindex"],
        "test_cindex_correct_encoding": corrected,
    }
    with open(models_dir / "cox_serving_preprocessing.json", "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
