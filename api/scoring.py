"""
Request-time scoring with the frozen artifacts: Cox partial hazard,
cox_risk_pct against the training reference of the row's landmark, the
Cox survival curve, and the fuzzy priority with its fired rules. Works for
any number of rows, including one (see encode_for_model for why the
frozen batch path can't be used here).
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from api.artifacts import FrozenArtifacts
from scripts.evaluate.features import NUMERIC, encode_for_model, prepare_raw
from scripts.fuzzy import fuzzy_layer as fl

SURVIVAL_CURVE_DAYS = (1, 7, 14, 30, 60, 90, 180, 365)


def design_matrix(rows: pd.DataFrame, art: FrozenArtifacts) -> pd.DataFrame:
    df = prepare_raw(rows)
    for c in NUMERIC:
        df[c] = df[c].fillna(art.numeric_medians[c])
    return encode_for_model(df, art.one_hot_columns).drop(columns=art.dropped_const_cols)


def cox_scores(rows: pd.DataFrame, art: FrozenArtifacts) -> np.ndarray:
    if rows.empty:
        return np.empty(0)
    return art.cox.predict_partial_hazard(design_matrix(rows, art)).to_numpy()


def cox_risk_pct(scores: np.ndarray, landmarks, art: FrozenArtifacts) -> np.ndarray:
    return art.reference.percentile(scores, np.asarray(landmarks).astype(int))


def survival_curves(rows: pd.DataFrame, art: FrozenArtifacts, days=SURVIVAL_CURVE_DAYS) -> np.ndarray:
    """rows x len(days): P(not KEV-listed by as_of_date + day)."""
    surv = art.cox.predict_survival_function(design_matrix(rows, art), times=list(days))
    return surv.T.to_numpy()


def fuzzy_explanations(rows: pd.DataFrame, pct: np.ndarray, art: FrozenArtifacts) -> list[dict]:
    """Priority and fired rules (strongest first) per row. Explanation
    only — the API never ranks by it."""
    if rows.empty:
        return []
    inputs = fl.model_inputs(pd.DataFrame({
        "cox_risk_pct": pct,
        "epss_pct_now": rows["epss_pct_now"].to_numpy(dtype=float),
        "cvss_base_score": rows["cvss_base_score"].where(~rows["cvss_cna_missing"].astype(bool)).to_numpy(dtype=float),
        "cvss_cna_missing": rows["cvss_cna_missing"].astype(bool).to_numpy(),
    }))
    priority, firing = fl.score(inputs, art.fuzzy_config)
    rules = {r["id"]: r for r in art.fuzzy_config["rules"]}
    out = []
    for i in range(len(rows)):
        strengths = firing.iloc[i]
        fired = strengths[strengths > 1e-9].sort_values(ascending=False)
        out.append({
            "priority": float(priority[i]),
            "blindspot": float(inputs["blindspot"][i]),
            "rules_fired": [{"id": rid, "text": rules[rid]["text"], "consequent": rules[rid]["consequent"],
                             "strength": float(s), "affects_score": rid not in fl.EXPLANATION_ONLY_RULES}
                            for rid, s in fired.items()],
        })
    return out
