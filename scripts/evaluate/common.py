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

Performance note (found the hard way): the actual bottleneck in an
earlier version of this module was NOT concordance_index — it was
rebuilding a cve_id -> row-indices lookup FROM SCRATCH on every single
resample (an O(unique_cves * n) linear scan repeated per resample: on the
real 178k-row test set this measured at 52.8 SECONDS for one resample).
Building that lookup ONCE per evaluate_model* call (see
`_build_cve_row_index`) and reusing it drops that to ~0.02s/resample — a
~2500x fix, and the actual explanation for "20 resamples took 15+
minutes." fast_concordance_index below is a smaller, separate win
(~2x over lifelines.utils.concordance_index at this scale) validated to
match lifelines exactly (see tests/test_evaluate/test_fast_concordance.py) —
real speedup came overwhelmingly from the resampling fix, not this.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

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


def fast_concordance_index(duration: np.ndarray, risk_score: np.ndarray, event: np.ndarray) -> float:
    """Harrell's C, vectorized over event rows only — O(n_events * n)
    instead of iterating all pairs, using numpy vectorized comparisons per
    event row. `risk_score`: higher = higher risk = shorter predicted
    survival (this project's convention throughout).

    Reproduces lifelines.utils.concordance_index(duration, -risk_score,
    event) EXACTLY (validated to 1e-9 on real data, random vectors, and
    bootstrap-resampled — i.e. duplicated-row — data; see
    tests/test_evaluate/test_fast_concordance.py), including its
    tie-handling rules, reverse-engineered from lifelines' own behavior on
    small controlled cases rather than assumed:
      - A pair is comparable if the earlier-time member is an OBSERVED
        EVENT (regardless of the later member's status) — standard rule.
      - Two rows tied in time where BOTH are events: NOT comparable at all
        (can't order simultaneous events) — confirmed via a lifelines
        ZeroDivisionError on a dataset containing only such a pair.
      - Two rows tied in time where one is an event and the other is
        censored: comparable — a censoring at the exact instant of the
        event is treated as "survived at least that long," same as any
        other later-time comparison (normal concordant/discordant/
        tied-score scoring, no special partial credit).
      - Tied risk_score among comparable pairs: standard 0.5 credit.
    """
    duration = np.asarray(duration, dtype=float)
    risk_score = np.asarray(risk_score, dtype=float)
    event = np.asarray(event).astype(bool)
    event_idx = np.where(event)[0]

    concordant = 0.0
    comparable = 0.0

    for i in event_idx:
        ti = duration[i]
        ri = risk_score[i]
        later_or_tied_censored = (duration > ti) | ((duration == ti) & (~event))
        rj = risk_score[later_or_tied_censored]
        comparable += rj.shape[0]
        concordant += (ri > rj).sum() + 0.5 * (ri == rj).sum()

    return concordant / comparable if comparable else float("nan")


def _build_cve_row_index(cve_ids: np.ndarray) -> dict:
    """Built ONCE per evaluate_model* call, not per resample — see the
    module docstring's performance note for why this matters (a
    per-resample rebuild measured at 52.8s/resample on the real test set;
    this reduces that to ~0.02s/resample)."""
    return pd.Series(np.arange(len(cve_ids)), index=cve_ids).groupby(level=0).apply(lambda s: s.to_numpy()).to_dict()


def _resampled_row_index(cve_row_index: dict, unique_cves: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    sample_cves = rng.choice(unique_cves, size=len(unique_cves), replace=True)
    return np.concatenate([cve_row_index[c] for c in sample_cves])


def _summarize(point: float, samples) -> BootstrapResult:
    arr = np.asarray(samples, dtype=float)
    arr = arr[~np.isnan(arr)]
    return BootstrapResult(
        point_estimate=float(point), mean=float(np.mean(arr)),
        ci_lower=float(np.percentile(arr, 2.5)), ci_upper=float(np.percentile(arr, 97.5)),
        n_resamples=len(arr),
    )


def _summarize_diff(point_diff: float, samples) -> dict:
    arr = np.asarray(samples, dtype=float)
    arr = arr[~np.isnan(arr)]
    ci_lower, ci_upper = float(np.percentile(arr, 2.5)), float(np.percentile(arr, 97.5))
    return {
        "point_diff": float(point_diff), "mean_diff": float(np.mean(arr)),
        "ci_lower": ci_lower, "ci_upper": ci_upper,
        "excludes_zero": bool(ci_lower > 0 or ci_upper < 0),
        "n": len(arr),
    }


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
    cve_row_index = _build_cve_row_index(cve_ids)

    point_cindex = fast_concordance_index(duration, risk_score, event)
    point_recall = {b: recall_at_budget(risk_score, event, b) for b in budgets}

    cindex_samples = []
    recall_samples: dict[float, list[float]] = {b: [] for b in budgets}

    for i in range(n_resamples):
        row_idx = _resampled_row_index(cve_row_index, unique_cves, rng)
        d, e, s = duration[row_idx], event[row_idx], risk_score[row_idx]
        cindex_samples.append(fast_concordance_index(d, s, e))
        for b in budgets:
            recall_samples[b].append(recall_at_budget(s, e, b))

        if log_every and (i + 1) % log_every == 0:
            log_with_fields(
                logger, logging.INFO, "bootstrap progress",
                label=log_label, resample=i + 1, n_resamples=n_resamples,
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


def paired_bootstrap_compare(
    test_df: pd.DataFrame,
    risk_score_model: np.ndarray,
    risk_score_baseline: np.ndarray,
    *,
    label: str,
    cve_id_col: str = "cve_id",
    duration_col: str = "event_time",
    event_col: str = "composite_event",
    budgets: tuple[float, ...] = DEFAULT_BUDGETS,
    n_resamples: int = 200,
    seed: int = DEFAULT_SEED,
    log_every: int = 20,
) -> dict:
    """Paired bootstrap: on each resample, computes BOTH risk_score_model's
    and risk_score_baseline's metrics on the IDENTICAL resampled row set,
    then the per-resample DIFFERENCE (model - baseline). CI is taken on
    that difference distribution directly, which correctly accounts for
    the correlation between the two rankings' errors on the same data
    (a paired design gives tighter, more honest CIs than differencing two
    independently-computed CIs would). Returns
    {"cindex": {...}, "recall_1pct": {...}, ...} each with
    mean_diff/ci_lower/ci_upper/excludes_zero."""
    cve_ids = test_df[cve_id_col].values
    duration = test_df[duration_col].clip(lower=0.5).values
    event = test_df[event_col].values.astype(int)
    unique_cves = np.unique(cve_ids)
    cve_row_index = _build_cve_row_index(cve_ids)
    rng = np.random.default_rng(seed)

    diffs: dict[str, list[float]] = {"cindex": []}
    for b in budgets:
        diffs[f"recall_{int(b*100)}pct"] = []

    point_diffs = {"cindex": fast_concordance_index(duration, risk_score_model, event)
                   - fast_concordance_index(duration, risk_score_baseline, event)}
    for b in budgets:
        point_diffs[f"recall_{int(b*100)}pct"] = (
            recall_at_budget(risk_score_model, event, b) - recall_at_budget(risk_score_baseline, event, b)
        )

    for i in range(n_resamples):
        row_idx = _resampled_row_index(cve_row_index, unique_cves, rng)
        d, e = duration[row_idx], event[row_idx]
        sm, sb = risk_score_model[row_idx], risk_score_baseline[row_idx]

        diffs["cindex"].append(fast_concordance_index(d, sm, e) - fast_concordance_index(d, sb, e))
        for b in budgets:
            diffs[f"recall_{int(b*100)}pct"].append(recall_at_budget(sm, e, b) - recall_at_budget(sb, e, b))

        if log_every and (i + 1) % log_every == 0:
            log_with_fields(
                logger, logging.INFO, "paired bootstrap progress",
                label=label, resample=i + 1, n_resamples=n_resamples,
            )

    return {metric: _summarize_diff(point_diffs[metric], samples) for metric, samples in diffs.items()}


# --- Post-freeze secondary metrics: time-dependent AUC, Brier, calibration ---
#
# Same contract as everything above: the caller produces predictions ONCE
# from an already-fitted model, and this module only resamples TEST CVEs.
# `_bootstrap_rows` draws from the same RNG stream as bootstrap_metric /
# paired_bootstrap_compare (same seed, same unique-CVE order, same
# rng.choice call), so for a given test_df and seed every metric here is
# computed on exactly the same 200 resampled CVE sets as the C-index and
# recall numbers.
#
# IPCW (inverse probability of censoring weighting) metrics take the
# TRAINING survival array for the censoring distribution, per sksurv's
# design. They are only defined while (a) every test time is within the
# training follow-up (the censoring KM is undefined past it) and (b) each
# horizon lies inside the test follow-up. `check_ipcw_horizons` raises
# HorizonOutOfRangeError instead of clipping, so an out-of-range horizon
# gets reported, not silently replaced by a different one.

DEFAULT_AUC_HORIZONS = (30, 90, 180)


class HorizonOutOfRangeError(ValueError):
    pass


def survival_array(duration, event) -> np.ndarray:
    from sksurv.util import Surv
    return Surv.from_arrays(event=np.asarray(event).astype(bool), time=np.asarray(duration, dtype=float))


def check_ipcw_horizons(train_duration, test_duration, horizons) -> None:
    train_max = float(np.max(train_duration))
    test_min, test_max = float(np.min(test_duration)), float(np.max(test_duration))
    if test_max > train_max:
        raise HorizonOutOfRangeError(
            f"test follow-up (max {test_max}) extends past training follow-up (max {train_max}); "
            "censoring weights are undefined there"
        )
    out_of_range = [h for h in horizons if not (test_min <= h < test_max)]
    if out_of_range:
        raise HorizonOutOfRangeError(
            f"horizons {out_of_range} fall outside test follow-up [{test_min}, {test_max})"
        )


def _bootstrap_rows(
    cve_ids: np.ndarray, stat_fn, n_stats: int, *, n_resamples: int, seed: int, log_every: int, log_label: str,
) -> np.ndarray:
    """(n_resamples, n_stats) array of stat_fn(row_idx) over CVE-level
    resamples. A resample where stat_fn raises ValueError (e.g. one with no
    event before a horizon) records NaN; the summaries drop NaNs and report
    how many resamples survived as n_resamples / n."""
    rng = np.random.default_rng(seed)
    unique_cves = np.unique(cve_ids)
    cve_row_index = _build_cve_row_index(cve_ids)

    samples = np.full((n_resamples, n_stats), np.nan)
    for i in range(n_resamples):
        row_idx = _resampled_row_index(cve_row_index, unique_cves, rng)
        try:
            samples[i] = stat_fn(row_idx)
        except ValueError as exc:
            log_with_fields(logger, logging.WARNING, "bootstrap resample skipped",
                            label=log_label, resample=i + 1, error=str(exc))
        if log_every and (i + 1) % log_every == 0:
            log_with_fields(logger, logging.INFO, "bootstrap progress",
                            label=log_label, resample=i + 1, n_resamples=n_resamples)
    return samples


def _test_arrays(test_df, cve_id_col, duration_col, event_col):
    cve_ids = test_df[cve_id_col].values
    duration = test_df[duration_col].clip(lower=0.5).values.astype(float)
    event = test_df[event_col].values.astype(bool)
    return cve_ids, duration, event


def time_dependent_auc(survival_train, survival_test, risk_score, horizons) -> np.ndarray:
    """Cumulative/dynamic AUC at each horizon (sksurv, IPCW-weighted).
    `risk_score`: higher = higher risk, same convention as the C-index."""
    from sksurv.metrics import cumulative_dynamic_auc
    auc, _ = cumulative_dynamic_auc(survival_train, survival_test, risk_score, list(horizons))
    return np.asarray(auc, dtype=float)


def evaluate_time_dependent_auc(
    test_df: pd.DataFrame,
    risk_score: np.ndarray,
    *,
    survival_train: np.ndarray,
    label: str,
    horizons: tuple[int, ...] = DEFAULT_AUC_HORIZONS,
    cve_id_col: str = "cve_id",
    duration_col: str = "event_time",
    event_col: str = "composite_event",
    n_resamples: int = 200,
    seed: int = DEFAULT_SEED,
    log_every: int = 20,
) -> dict[int, BootstrapResult]:
    """Time-dependent AUC per horizon with a CVE-clustered bootstrap CI.
    Raises HorizonOutOfRangeError if any horizon can't be evaluated."""
    cve_ids, duration, event = _test_arrays(test_df, cve_id_col, duration_col, event_col)
    check_ipcw_horizons(survival_train["time"], duration, horizons)
    y_test = survival_array(duration, event)

    point = time_dependent_auc(survival_train, y_test, risk_score, horizons)
    samples = _bootstrap_rows(
        cve_ids, lambda idx: time_dependent_auc(survival_train, y_test[idx], risk_score[idx], horizons),
        len(horizons), n_resamples=n_resamples, seed=seed, log_every=log_every, log_label=f"{label} td-AUC",
    )
    return {h: _summarize(point[j], samples[:, j]) for j, h in enumerate(horizons)}


def paired_time_dependent_auc_compare(
    test_df: pd.DataFrame,
    risk_score_model: np.ndarray,
    risk_score_baseline: np.ndarray,
    *,
    survival_train: np.ndarray,
    label: str,
    horizons: tuple[int, ...] = DEFAULT_AUC_HORIZONS,
    cve_id_col: str = "cve_id",
    duration_col: str = "event_time",
    event_col: str = "composite_event",
    n_resamples: int = 200,
    seed: int = DEFAULT_SEED,
    log_every: int = 20,
) -> dict[int, dict]:
    """Paired (model - baseline) time-dependent AUC difference per horizon,
    both computed on the identical resampled rows — same design as
    paired_bootstrap_compare."""
    cve_ids, duration, event = _test_arrays(test_df, cve_id_col, duration_col, event_col)
    check_ipcw_horizons(survival_train["time"], duration, horizons)
    y_test = survival_array(duration, event)

    def diff(idx):
        return (time_dependent_auc(survival_train, y_test[idx], risk_score_model[idx], horizons)
                - time_dependent_auc(survival_train, y_test[idx], risk_score_baseline[idx], horizons))

    point = diff(np.arange(len(test_df)))
    samples = _bootstrap_rows(cve_ids, diff, len(horizons), n_resamples=n_resamples, seed=seed,
                              log_every=log_every, log_label=f"{label} paired td-AUC")
    return {h: _summarize_diff(point[j], samples[:, j]) for j, h in enumerate(horizons)}


def evaluate_brier(
    test_df: pd.DataFrame,
    surv_prob: np.ndarray,
    times: np.ndarray,
    *,
    survival_train: np.ndarray,
    reference_surv_prob: np.ndarray,
    label: str,
    point_horizons: tuple[int, ...] = DEFAULT_AUC_HORIZONS,
    cve_id_col: str = "cve_id",
    duration_col: str = "event_time",
    event_col: str = "composite_event",
    n_resamples: int = 200,
    seed: int = DEFAULT_SEED,
    log_every: int = 20,
) -> dict[str, BootstrapResult]:
    """IPCW Brier score at `point_horizons` and integrated over
    [times[0], times[-1]], for a model's predicted survival
    `surv_prob` (n_rows x len(times), S(t|x) on the `times` grid, which
    must contain every point horizon).

    With a rare event (well under 1% of rows), any Brier score is close to
    zero no matter how good the model is, so the raw number is
    uninformative alone. Every Brier value is therefore paired with the
    same score for `reference_surv_prob` (len(times),) — a covariate-free
    prediction, e.g. the training Kaplan-Meier curve given to every row —
    and the index of prediction accuracy IPA = 1 - BS_model / BS_reference,
    computed per resample. IPA > 0 means the model beats knowing only the
    base rate; 0 means no better; negative means worse.

    Integrated Brier = trapezoid over the grid / (times[-1] - times[0]),
    identical to sksurv.metrics.integrated_brier_score (it's the same
    formula on the same brier_score output; computed directly here so one
    brier_score call per resample serves both the point and integrated
    values)."""
    from sksurv.metrics import brier_score

    times = np.asarray(times, dtype=float)
    horizon_pos = [int(np.flatnonzero(times == h)[0]) for h in point_horizons]
    cve_ids, duration, event = _test_arrays(test_df, cve_id_col, duration_col, event_col)
    check_ipcw_horizons(survival_train["time"], duration, (times[0], times[-1]))
    y_test = survival_array(duration, event)
    reference_surv_prob = np.asarray(reference_surv_prob, dtype=float)

    names = ["ibs", "ibs_reference", "ipa_ibs"]
    for h in point_horizons:
        names += [f"brier_{h}d", f"brier_{h}d_reference", f"ipa_{h}d"]

    def stats(idx):
        bs = brier_score(survival_train, y_test[idx], surv_prob[idx], times)[1]
        ref = np.broadcast_to(reference_surv_prob, (len(idx), len(times)))
        bs_ref = brier_score(survival_train, y_test[idx], ref, times)[1]
        width = times[-1] - times[0]
        ibs, ibs_ref = np.trapezoid(bs, times) / width, np.trapezoid(bs_ref, times) / width
        out = [ibs, ibs_ref, 1 - ibs / ibs_ref]
        for p in horizon_pos:
            out += [bs[p], bs_ref[p], 1 - bs[p] / bs_ref[p]]
        return np.array(out)

    point = stats(np.arange(len(test_df)))
    samples = _bootstrap_rows(cve_ids, stats, len(names), n_resamples=n_resamples, seed=seed,
                              log_every=log_every, log_label=f"{label} Brier")
    return {name: _summarize(point[j], samples[:, j]) for j, name in enumerate(names)}


def km_event_probability(duration: np.ndarray, event: np.ndarray, horizon: float) -> float:
    """1 - S_KM(horizon): Kaplan-Meier-estimated probability of the event by
    `horizon`, accounting for censoring (a raw event fraction would
    understate it, since rows censored before the horizon count as
    non-events)."""
    from sksurv.nonparametric import kaplan_meier_estimator
    km_times, km_surv = kaplan_meier_estimator(np.asarray(event).astype(bool), np.asarray(duration, dtype=float))
    pos = np.searchsorted(km_times, horizon, side="right") - 1
    return float(1.0 - km_surv[pos]) if pos >= 0 else 0.0


def km_calibration_table(
    test_df: pd.DataFrame,
    predicted_event_prob: np.ndarray,
    horizon: float,
    *,
    label: str,
    n_bins: int = 10,
    cve_id_col: str = "cve_id",
    duration_col: str = "event_time",
    event_col: str = "composite_event",
    n_resamples: int = 200,
    seed: int = DEFAULT_SEED,
    log_every: int = 20,
) -> pd.DataFrame:
    """Calibration of predicted P(event by `horizon`) against the
    Kaplan-Meier observed rate, in `n_bins` equal-count bins of the
    prediction (bin 1 = lowest). Bins are assigned ONCE on the full test
    set and rows keep their bin through resampling; the observed-rate CI is
    the same CVE-clustered bootstrap as every other metric here (a per-bin
    Greenwood CI would treat a CVE's landmark rows as independent). The
    last row, bin "all", is calibration-in-the-large over every row.
    `ratio` = mean_predicted / observed (>1: over-predicts risk)."""
    cve_ids, duration, event = _test_arrays(test_df, cve_id_col, duration_col, event_col)
    p = np.asarray(predicted_event_prob, dtype=float)
    bins = pd.qcut(pd.Series(p).rank(method="first"), n_bins, labels=False).to_numpy()

    def observed(idx):
        d, e, b = duration[idx], event[idx], bins[idx]
        per_bin = [km_event_probability(d[b == k], e[b == k], horizon) for k in range(n_bins)]
        return np.array(per_bin + [km_event_probability(d, e, horizon)])

    point = observed(np.arange(len(p)))
    samples = _bootstrap_rows(cve_ids, observed, n_bins + 1, n_resamples=n_resamples, seed=seed,
                              log_every=log_every, log_label=f"{label} calibration")

    rows = []
    for k in range(n_bins + 1):
        mask = bins == k if k < n_bins else np.ones(len(p), dtype=bool)
        obs = _summarize(point[k], samples[:, k])
        mean_pred = float(p[mask].mean())
        rows.append({
            "bin": str(k + 1) if k < n_bins else "all",
            "n_rows": int(mask.sum()),
            "n_events_by_horizon": int((event[mask] & (duration[mask] <= horizon)).sum()),
            "pred_min": float(p[mask].min()), "pred_max": float(p[mask].max()),
            "mean_predicted": mean_pred,
            "observed": obs.point_estimate, "observed_ci_lower": obs.ci_lower, "observed_ci_upper": obs.ci_upper,
            "ratio": mean_pred / obs.point_estimate if obs.point_estimate > 0 else float("inf"),
        })
    return pd.DataFrame(rows)


# --- Blind-spot catch rate ---
#
# A blind spot is a test event that EPSS-alone leaves OUTSIDE its top
# `budget` of rows; the catch rate is the fraction of those a ranking puts
# INSIDE its own top `budget`. Same top-k rule as recall_at_budget. Same
# definition as final_comparison.py's step4 (which predates this function),
# drawn here from _bootstrap_rows, i.e. the same CVE resamples as every
# other metric in this module.

def blind_spot_catch_rate(risk_score: np.ndarray, epss_score: np.ndarray, event: np.ndarray,
                          budget: float = 0.10) -> float:
    n_top = max(1, int(np.ceil(len(epss_score) * budget)))
    in_epss_top = np.zeros(len(epss_score), dtype=bool)
    in_epss_top[np.argsort(-epss_score)[:n_top]] = True
    blind = (np.asarray(event) == 1) & ~in_epss_top
    if not blind.any():
        return np.nan
    in_model_top = np.zeros(len(risk_score), dtype=bool)
    in_model_top[np.argsort(-risk_score)[:n_top]] = True
    return (blind & in_model_top).sum() / blind.sum()


def evaluate_blind_spot_catch_rate(
    test_df: pd.DataFrame,
    risk_scores: dict[str, np.ndarray],
    epss_score: np.ndarray,
    *,
    label: str,
    budget: float = 0.10,
    reference: str | None = None,
    cve_id_col: str = "cve_id",
    event_col: str = "composite_event",
    n_resamples: int = 200,
    seed: int = DEFAULT_SEED,
    log_every: int = 20,
) -> dict:
    """Catch rate for every ranking in `risk_scores` on the same CVE
    resamples. If `reference` names one of them, also the paired
    difference (other - reference) per resample, like
    paired_bootstrap_compare. Returns {"per_model": {name: {...}},
    "paired_vs_reference": {name: {...}}}."""
    cve_ids = test_df[cve_id_col].values
    event = test_df[event_col].values.astype(int)
    epss_score = np.asarray(epss_score, dtype=float)
    names = list(risk_scores)

    def stats(idx):
        return [blind_spot_catch_rate(risk_scores[n][idx], epss_score[idx], event[idx], budget) for n in names]

    point = stats(np.arange(len(event)))
    samples = _bootstrap_rows(cve_ids, stats, len(names), n_resamples=n_resamples, seed=seed,
                              log_every=log_every, log_label=f"{label} blind-spot")
    out = {"per_model": {n: _summarize(point[k], samples[:, k]).as_dict() for k, n in enumerate(names)},
           "paired_vs_reference": {}}
    if reference is not None:
        r = names.index(reference)
        for k, n in enumerate(names):
            if k != r:
                out["paired_vs_reference"][n] = _summarize_diff(point[k] - point[r], samples[:, k] - samples[:, r])
    return out
