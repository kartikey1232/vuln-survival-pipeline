"""
Shared evaluation module for every survival model in this project (Cox,
RSF, XGBoost-AFT, and the EPSS-alone reference). Every model MUST be
scored through `evaluate_model` so that C-index / recall-at-budget are
computed identically across models — same test rows, same bootstrap CVE
resamples (same seed), same budget definitions — which is what makes the
model-comparison table in docs/model_comparison.md an apples-to-apples
comparison rather than four independently-computed numbers.

Bootstrap design: the caller fits its model and produces a risk_score
array ONCE (higher = higher risk = shorter predicted survival) for the
fixed test set. This module never fits anything — it only resamples TEST
CVE IDs (not rows) with replacement, so a CVE's up-to-3 landmark rows
always move together, and recomputes C-index / recall-at-budget on each
resampled row multiset. This is the cheap, standard way to bootstrap a
fixed model's evaluation metric.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from lifelines.utils import concordance_index

from scripts.common.logging_utils import get_logger, log_with_fields

logger = get_logger(__name__, category="evaluate")

DEFAULT_BUDGETS = (0.01, 0.05, 0.10)
DEFAULT_SEED = 20260922


@dataclass
class BootstrapResult:
    point_estimate: float
    mean: float
    ci_lower: float
    ci_upper: float
    n_resamples: int

    def as_dict(self) -> dict:
        return {
            "point": self.point_estimate, "mean": self.mean,
            "ci_lower": self.ci_lower, "ci_upper": self.ci_upper, "n": self.n_resamples,
        }


@dataclass
class EvaluationResult:
    label: str
    n_test_rows: int
    n_test_cves: int
    n_events: int
    cindex: BootstrapResult
    recall_at_budget: dict[float, BootstrapResult] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "n_test_rows": self.n_test_rows,
            "n_test_cves": self.n_test_cves,
            "n_events": self.n_events,
            "cindex": self.cindex.as_dict(),
            "recall_at_budget": {f"{int(b*100)}pct": r.as_dict() for b, r in self.recall_at_budget.items()},
        }


def recall_at_budget(risk_score: np.ndarray, event: np.ndarray, budget: float) -> float:
    """Of the top `budget` fraction of rows by risk_score (descending),
    what fraction of all true events (event==1) fall inside it."""
    n_top = max(1, int(np.ceil(len(risk_score) * budget)))
    order = np.argsort(-risk_score)
    top_idx = order[:n_top]
    total_events = event.sum()
    if total_events == 0:
        return np.nan
    return event[top_idx].sum() / total_events


def _resampled_row_index(cve_ids: np.ndarray, unique_cves: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    sample_cves = rng.choice(unique_cves, size=len(unique_cves), replace=True)
    rows_by_cve: dict = {}
    idx = np.arange(len(cve_ids))
    for cve in np.unique(sample_cves):
        rows_by_cve[cve] = idx[cve_ids == cve]
    return np.concatenate([rows_by_cve[c] for c in sample_cves])


def bootstrap_metric(
    cve_ids: np.ndarray,
    duration: np.ndarray,
    event: np.ndarray,
    risk_score: np.ndarray,
    *,
    budgets: tuple[float, ...] = DEFAULT_BUDGETS,
    n_resamples: int = 200,
    seed: int = DEFAULT_SEED,
    log_every: int = 20,
    log_label: str = "",
) -> tuple[BootstrapResult, dict[float, BootstrapResult]]:
    """Bootstraps C-index and recall-at-budget for one risk_score ranking
    against fixed (cve_ids, duration, event) test data. Logs progress every
    `log_every` resamples. Returns (cindex_result, {budget: recall_result})."""
    rng = np.random.default_rng(seed)
    unique_cves = np.unique(cve_ids)

    point_cindex = concordance_index(duration, -risk_score, event)
    point_recall = {b: recall_at_budget(risk_score, event, b) for b in budgets}

    cindex_samples = []
    recall_samples: dict[float, list[float]] = {b: [] for b in budgets}

    for i in range(n_resamples):
        row_idx = _resampled_row_index(cve_ids, unique_cves, rng)
        d, e, s = duration[row_idx], event[row_idx], risk_score[row_idx]
        cindex_samples.append(concordance_index(d, -s, e))
        for b in budgets:
            recall_samples[b].append(recall_at_budget(s, e, b))

        if log_every and (i + 1) % log_every == 0:
            log_with_fields(
                logger, logging.INFO, "bootstrap progress",
                label=log_label, resample=i + 1, n_resamples=n_resamples,
            )

    def _summarize(point: float, samples: list[float]) -> BootstrapResult:
        arr = np.array(samples)
        arr = arr[~np.isnan(arr)]
        return BootstrapResult(
            point_estimate=point, mean=float(np.mean(arr)),
            ci_lower=float(np.percentile(arr, 2.5)), ci_upper=float(np.percentile(arr, 97.5)),
            n_resamples=len(arr),
        )

    cindex_result = _summarize(point_cindex, cindex_samples)
    recall_results = {b: _summarize(point_recall[b], recall_samples[b]) for b in budgets}
    return cindex_result, recall_results


def evaluate_model(
    test_df: pd.DataFrame,
    risk_score: np.ndarray,
    *,
    label: str,
    cve_id_col: str = "cve_id",
    duration_col: str = "event_time",
    event_col: str = "composite_event",
    budgets: tuple[float, ...] = DEFAULT_BUDGETS,
    n_resamples: int = 200,
    seed: int = DEFAULT_SEED,
    log_every: int = 20,
) -> EvaluationResult:
    """Evaluates one model's risk_score (higher = higher risk = shorter
    predicted survival) against `test_df`, pooled over all rows. Use
    `evaluate_model_per_landmark` for the per-landmark breakdown."""
    cve_ids = test_df[cve_id_col].values
    duration = test_df[duration_col].clip(lower=0.5).values
    event = test_df[event_col].values.astype(int)

    cindex, recall = bootstrap_metric(
        cve_ids, duration, event, risk_score,
        budgets=budgets, n_resamples=n_resamples, seed=seed, log_every=log_every, log_label=label,
    )
    return EvaluationResult(
        label=label, n_test_rows=len(test_df), n_test_cves=len(np.unique(cve_ids)),
        n_events=int(event.sum()), cindex=cindex, recall_at_budget=recall,
    )


def evaluate_model_per_landmark(
    test_df: pd.DataFrame,
    risk_score: np.ndarray,
    *,
    label: str,
    landmark_col: str = "landmark_day",
    cve_id_col: str = "cve_id",
    duration_col: str = "event_time",
    event_col: str = "composite_event",
    budgets: tuple[float, ...] = DEFAULT_BUDGETS,
    n_resamples: int = 200,
    seed: int = DEFAULT_SEED,
    log_every: int = 20,
) -> dict[int, EvaluationResult]:
    """Same as evaluate_model but broken down per landmark. `risk_score`
    must be aligned (same order/index) with `test_df`."""
    results = {}
    for landmark in sorted(test_df[landmark_col].unique()):
        mask = (test_df[landmark_col] == landmark).values
        results[landmark] = evaluate_model(
            test_df[mask], risk_score[mask], label=f"{label} (landmark={landmark})",
            cve_id_col=cve_id_col, duration_col=duration_col, event_col=event_col,
            budgets=budgets, n_resamples=n_resamples, seed=seed, log_every=log_every,
        )
    return results
