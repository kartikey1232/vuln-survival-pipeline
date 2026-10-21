"""
Frozen artifacts the API serves from, loaded once per process. Nothing in
the API fits anything: the Cox model is only ever asked to predict, the
percentile reference and fuzzy config are read-only, and the numeric
imputation medians come from models/cox_serving_preprocessing.json
(written by scripts/models/export_serving_preprocessing.py).
"""

from __future__ import annotations

import json
import pickle
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from lifelines import CoxPHFitter

from config.config_schema import get_config
from scripts.fuzzy.risk_percentile import REFERENCE_FILENAME, RiskReference


@dataclass(frozen=True)
class FrozenArtifacts:
    cox: CoxPHFitter
    one_hot_columns: list[str]
    dropped_const_cols: list[str]
    numeric_medians: dict[str, float]
    reference: RiskReference
    fuzzy_config: dict
    metadata: dict  # file stem -> parsed JSON, for GET /model


def _read_json(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def load_artifacts(models_dir: Path) -> FrozenArtifacts:
    with open(models_dir / "cox_final.pkl", "rb") as f:
        cox = pickle.load(f)
    preprocessing = _read_json(models_dir / "cox_serving_preprocessing.json")
    metadata = {stem: _read_json(models_dir / f"{stem}.json") for stem in (
        "cox_final_metadata", "rsf_final_metadata", "xgboost_aft_final_metadata",
        "cox_risk_reference_metadata", "cox_serving_preprocessing", "fuzzy_config",
        "backtest_corrected_encoding",
    )}
    return FrozenArtifacts(
        cox=cox["model"],
        one_hot_columns=cox["one_hot_columns"],
        dropped_const_cols=cox["dropped_const_cols"],
        numeric_medians=preprocessing["numeric_medians"],
        reference=RiskReference.load(models_dir / REFERENCE_FILENAME),
        fuzzy_config=metadata["fuzzy_config"],
        metadata=metadata,
    )


@lru_cache(maxsize=1)
def get_artifacts() -> FrozenArtifacts:
    return load_artifacts(get_config().project_root / "models")
