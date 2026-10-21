"""
Regression tests for the test-time one-hot encoding bug
(docs/results_corrected_encoding.md): a non-training frame must be encoded
relative to the TRAINING frame's category set, identically whether a row is
encoded alone or inside a batch.
"""

from __future__ import annotations

import pickle
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from scripts.evaluate.features import (
    BOOLEAN, CATEGORICAL, NUMERIC, encode_against, encode_for_model, one_hot,
)
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS

CATS = [c for c in CATEGORICAL if c in MODEL_FEATURE_COLUMNS]
TRAIN_LEVELS = {c: ["A_first", "B", "C"] for c in CATS}
TRAIN_LEVELS["cvss_version"] = ["2.0", "3.0", "3.1"]
# The real failure: the test frame lacks the training frame's first level,
# so its own first level is a different, real training column.
TEST_LEVELS = {c: levels[1:] for c, levels in TRAIN_LEVELS.items()}


def _frame(levels, n, seed):
    rng = np.random.default_rng(seed)
    df = pd.DataFrame({c: rng.normal(size=n) for c in NUMERIC})
    for c in BOOLEAN:
        df[c] = rng.integers(0, 2, n)
    for c in CATS:
        df[c] = rng.choice(levels[c], n).astype(str)
        df.loc[: len(levels[c]) - 1, c] = levels[c]  # every level present
    return df


@pytest.fixture()
def frames():
    train = _frame(TRAIN_LEVELS, 300, 0)
    test = _frame(TEST_LEVELS, 60, 1)
    return train, test, list(one_hot(train, MODEL_FEATURE_COLUMNS).columns)  # the fit-time columns


def test_single_row_and_batch_encoding_are_identical(frames):
    train, test, columns = frames
    batch = encode_for_model(test, columns)
    for i in range(len(test)):
        pd.testing.assert_frame_equal(encode_for_model(test.iloc[[i]], columns), batch.iloc[[i]])
    pd.testing.assert_frame_equal(encode_for_model(train, columns),
                                  one_hot(train, MODEL_FEATURE_COLUMNS).astype(float))  # fit-time path


def test_categories_are_dropped_relative_to_the_training_frame(frames):
    train, test, columns = frames
    for df in (train, test, test.iloc[[0]]):
        X = encode_for_model(df, columns)
        for c in CATS:
            reference = sorted(TRAIN_LEVELS[c])[0]
            dummies = [col for col in columns if col.startswith(f"{c}_")]
            assert f"{c}_{reference}" not in columns
            for i, value in enumerate(df[c]):
                row = X.iloc[i][dummies]
                if value == reference:
                    assert row.sum() == 0
                else:
                    assert row[f"{c}_{value}"] == 1 and row.sum() == 1


def test_unseen_level_encodes_as_all_zeros(frames):
    _, test, columns = frames
    row = test.iloc[[0]].copy()
    row["cvss_version"] = "4.0"
    X = encode_for_model(row, columns)
    assert X[[c for c in columns if c.startswith("cvss_version_")]].to_numpy().sum() == 0


def test_original_path_still_reproduces_the_bug(frames):
    """encoding="original" must stay as it was, so pre-fix numbers remain
    reproducible: it encodes the test frame's own first level (3.0) as the
    training reference (2.0)."""
    _, test, columns = frames
    rows_30 = (test["cvss_version"] == "3.0").to_numpy()
    original = encode_against(test, columns, encoding="original")
    corrected = encode_against(test, columns, encoding="corrected")
    assert original.loc[rows_30, "cvss_version_3.0"].sum() == 0
    assert (corrected.loc[rows_30, "cvss_version_3.0"] == 1).all()
    pd.testing.assert_frame_equal(original, one_hot(test, MODEL_FEATURE_COLUMNS, align_to=columns))
    with pytest.raises(ValueError, match="encoding"):
        encode_against(test, columns, encoding="neither")


def test_frozen_cox_columns_encode_a_lone_row_correctly():
    """With the real frozen Cox columns, a single cvss_version 3.0 row
    (3,947 test rows were 3.0) keeps its own category."""
    with open(Path(__file__).resolve().parents[2] / "models" / "cox_final.pkl", "rb") as f:
        columns = pickle.load(f)["one_hot_columns"]
    assert "cvss_version_3.0" in columns and "cvss_version_2.0" not in columns
    row = _frame({c: ["2.0", "3.0", "3.1"] if c == "cvss_version" else ["x"] for c in CATS}, 3, 2)
    row = row[row["cvss_version"] == "3.0"].iloc[[0]]
    assert encode_for_model(row, columns)["cvss_version_3.0"].iloc[0] == 1
    assert encode_against(row, columns, encoding="original")["cvss_version_3.0"].iloc[0] == 0
