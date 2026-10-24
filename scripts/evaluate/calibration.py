"""
Evaluated-and-rejected display recalibration of frozen Cox's P(KEV within
90 days). Cox's raw probabilities are under-dispersed (docs/final_results.md:
top decile under-predicted ~6x). This tests whether a monotone map fit on
the validation period alone makes them usable as displayed probabilities.
The frozen model, its partial hazard and every ranking are untouched.

Result (docs/robustness.md, section 3): it does not. Isotonic over-predicts
on test (IPA < 0) and Platt is effectively the identity, so NO calibrated
value is shipped: the API and dashboard show the raw probability only.
Nothing is written to models/.

Fit on VALIDATION only (train CVEs published 2024-07-01..2024-12-31, labels
censored at 2025-01-01, scripts/evaluate/data_splits.py). That censoring
leaves many validation rows with under 90 days of follow-up, so the binary
target "KEV-listed within 90 days" is fit with IPCW weights (censoring
Kaplan-Meier on validation): an event by 90d gets 1/G(T-), a row followed
past 90d without an event gets 1/G(90), a row censored before 90d without
an event gets 0.

The pre-stated validation-only rule (isotonic unless Platt has the lower
IPCW Brier@90d under 5-fold CVE-grouped cross-validation) is recorded, and
BOTH calibrators are evaluated once on test. Neither is chosen on test.

Caveat: validation rows are in-sample for the frozen Cox model (it was refit
on the full train set), so the maps are fit on Cox's in-sample predictions.

Writes scratch/calibration_90d.json and
docs/figures/calibration_90d_calibrated.png.

Usage: python -m scripts.evaluate.calibration
"""

from __future__ import annotations

import json
import logging
import pickle

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold
from sksurv.nonparametric import kaplan_meier_estimator

from config.config_schema import get_config
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.evaluate.common import (
    evaluate_brier_at_horizon,
    evaluate_model,
    km_calibration_table,
    survival_array,
)
from scripts.evaluate.data_splits import FIT_CUTOFF, VAL_CUTOFF
from scripts.evaluate.features import encode_for_model
from scripts.evaluate.final_comparison import _prep
from scripts.evaluate.post_freeze_metrics import _km_curve_on_grid

logger = get_logger(__name__, category="evaluate")

HORIZON = 90
N_CV_FOLDS = 5


def ipcw_targets(duration: np.ndarray, event: np.ndarray, horizon: float = HORIZON):
    """(y, w): y = 1 if the event happened by `horizon`; w the IPCW weight
    from the censoring Kaplan-Meier of (duration, event) itself."""
    duration = np.asarray(duration, dtype=float)
    event = np.asarray(event).astype(bool)
    c_times, c_surv = kaplan_meier_estimator(~event, duration)

    def G(t, side):
        pos = np.searchsorted(c_times, t, side=side) - 1
        return np.where(pos >= 0, c_surv[np.clip(pos, 0, None)], 1.0)

    y = (event & (duration <= horizon)).astype(float)
    w = np.zeros(len(duration))
    w[y == 1] = 1.0 / G(duration[y == 1], "left")  # G(T-)
    followed = duration > horizon
    w[followed] = 1.0 / G(np.array([horizon]), "right")[0]
    return y, w


def _logit(p):
    p = np.clip(np.asarray(p, dtype=float), 1e-12, 1 - 1e-12)
    return np.log(p / (1 - p))


def fit_calibrator(kind: str, p, y, w) -> dict:
    keep = w > 0
    p, y, w = np.asarray(p)[keep], y[keep], w[keep]
    if kind == "isotonic":
        iso = IsotonicRegression(y_min=0.0, y_max=1.0, increasing=True, out_of_bounds="clip")
        iso.fit(p, y, sample_weight=w)
        return {"method": "isotonic", "x": iso.X_thresholds_.tolist(), "y": iso.y_thresholds_.tolist()}
    if kind == "platt":
        lr = LogisticRegression(penalty=None, max_iter=1000)
        lr.fit(_logit(p)[:, None], y, sample_weight=w)
        return {"method": "platt", "a": float(lr.coef_[0, 0]), "b": float(lr.intercept_[0])}
    raise ValueError(kind)


def apply_calibration(cal: dict, p) -> np.ndarray:
    """Raw Cox P(KEV within 90d) -> recalibrated. Isotonic: sklearn's
    piecewise-linear interpolation between thresholds, clipped at the ends
    (identical to IsotonicRegression.predict with out_of_bounds="clip")."""
    p = np.asarray(p, dtype=float)
    if cal["method"] == "isotonic":
        return np.interp(p, cal["x"], cal["y"])
    if cal["method"] == "platt":
        return 1.0 / (1.0 + np.exp(-(cal["a"] * _logit(p) + cal["b"])))
    raise ValueError(cal["method"])


def _weighted_brier(pred, y, w):
    return float(np.sum(w * (pred - y) ** 2) / len(y))


def cross_validate(p, y, w, groups) -> dict:
    out = {"raw": [], "isotonic": [], "platt": []}
    for fit_idx, held_idx in GroupKFold(n_splits=N_CV_FOLDS).split(p, y, groups):
        out["raw"].append(_weighted_brier(p[held_idx], y[held_idx], w[held_idx]))
        for kind in ("isotonic", "platt"):
            cal = fit_calibrator(kind, p[fit_idx], y[fit_idx], w[fit_idx])
            out[kind].append(_weighted_brier(apply_calibration(cal, p[held_idx]), y[held_idx], w[held_idx]))
    return {k: {"folds": v, "mean": float(np.mean(v))} for k, v in out.items()}


def cox_p90(df: pd.DataFrame, cox: dict) -> tuple[np.ndarray, np.ndarray]:
    X = encode_for_model(df, cox["one_hot_columns"]).drop(columns=cox["dropped_const_cols"])
    hazard = cox["model"].predict_partial_hazard(X).to_numpy()
    p90 = 1.0 - cox["model"].predict_survival_function(X, times=[HORIZON]).T.to_numpy()[:, 0]
    return hazard, p90


def _ranking_check(test_df, scores: dict) -> dict:
    out = {}
    for name, s in scores.items():
        r = evaluate_model(test_df, s, label=name)
        out[name] = {"cindex": r.cindex.as_dict(), "recall_10pct": r.recall_at_budget[0.10].as_dict(),
                     "n_distinct_values": int(len(np.unique(s)))}
    return out


def run(train_df: pd.DataFrame, test_df: pd.DataFrame, cox: dict, figure_path) -> dict:
    published = train_df["as_of_date"] - pd.to_timedelta(train_df["landmark_day"].astype(int), unit="D")
    val_df = train_df[(published >= FIT_CUTOFF) & (published < VAL_CUTOFF)].reset_index(drop=True)

    _, p_val = cox_p90(val_df, cox)
    test_hazard, p_test = cox_p90(test_df, cox)

    y, w = ipcw_targets(val_df["event_time"].clip(lower=0.5).values, val_df["composite_event"].values)
    groups = val_df["cve_id"].to_numpy()
    val_summary = {"n_rows": len(val_df), "n_cves": int(val_df["cve_id"].nunique()),
                   "n_events": int(val_df["composite_event"].sum()), "n_events_by_90d": int(y.sum()),
                   "n_rows_zero_weight": int((w == 0).sum())}
    log_with_fields(logger, logging.INFO, "validation calibration set", **val_summary)

    cv = cross_validate(p_val, y, w, groups)
    chosen = "isotonic" if cv["isotonic"]["mean"] <= cv["platt"]["mean"] else "platt"
    calibrators = {k: fit_calibrator(k, p_val, y, w) for k in ("isotonic", "platt")}
    log_with_fields(logger, logging.INFO, "validation-rule choice (not shipped)", chosen=chosen,
                    cv_isotonic=cv["isotonic"]["mean"], cv_platt=cv["platt"]["mean"], cv_raw=cv["raw"]["mean"])

    # ---- test: report only, both calibrators ----
    preds = {"raw": p_test, **{k: apply_calibration(c, p_test) for k, c in calibrators.items()}}
    y_train = survival_array(train_df["event_time"].clip(lower=0.5).values, train_df["composite_event"].values)
    ref90 = 1.0 - float(_km_curve_on_grid(train_df["event_time"].clip(lower=0.5).values,
                                          train_df["composite_event"].values, np.array([float(HORIZON)]))[0])

    brier = {name: {k: v.as_dict() for k, v in evaluate_brier_at_horizon(
        test_df, p, HORIZON, survival_train=y_train, reference_event_prob=ref90, label=name).items()}
        for name, p in preds.items()}
    deciles = {name: km_calibration_table(test_df, p, HORIZON, label=name, bin_score=p_test)
               for name, p in preds.items()}
    ranking = _ranking_check(test_df, {"cox_partial_hazard": test_hazard,
                                       **{f"{k}_p90": v for k, v in preds.items()}})

    _plot(deciles, figure_path)

    out = {"validation_rule_choice": chosen, "shipped": None, "calibrators": calibrators,
           "validation": val_summary, "cv": cv, "reference_p90_train_km": ref90, "test_brier_90d": brier,
           "test_deciles": {k: v.to_dict(orient="records") for k, v in deciles.items()},
           "test_ranking_check": ranking,
           "test_p90_range": {k: [float(v.min()), float(v.max())] for k, v in preds.items()}}
    return out


def main():
    cfg = get_config()
    with open(cfg.project_root / "models" / "cox_final.pkl", "rb") as f:
        cox = pickle.load(f)
    train_df, test_df = _prep()
    out = run(train_df, test_df, cox, cfg.project_root / "docs" / "figures" / "calibration_90d_calibrated.png")
    with open(cfg.project_root / "scratch" / "calibration_90d.json", "w") as f:
        json.dump(out, f, indent=2, default=str)
    print(json.dumps({k: out[k] for k in ("validation_rule_choice", "validation", "cv", "test_brier_90d",
                                          "test_ranking_check", "test_p90_range")}, indent=2, default=str))


def _plot(deciles: dict, path):
    """Same layout as post_freeze_metrics._plot_calibration, with both
    rejected recalibrations added. Deciles are of the RAW prediction for all
    three, so each decile holds the same rows."""
    bins = {k: t[t["bin"] != "all"].reset_index(drop=True) for k, t in deciles.items()}
    floor = 1e-5
    ink, muted, grid, observed_c = "#0b0b0b", "#52514e", "#e5e4e0", "#2a78d6"
    styles = {"raw": dict(marker="o", color=muted, markerfacecolor="white", label="Raw Cox (shipped)"),
              "isotonic": dict(marker="D", color="#d0571c", markerfacecolor="#d0571c",
                               label="Isotonic, fit on validation (rejected)"),
              "platt": dict(marker="s", color="#7a5bc4", markerfacecolor="#7a5bc4",
                            label="Platt, fit on validation (rejected)")}
    raw = bins["raw"]
    obs = raw["observed"].clip(lower=floor)
    yerr = [obs - raw["observed_ci_lower"].clip(lower=floor), raw["observed_ci_upper"].clip(lower=floor) - obs]

    fig, (ax_l, ax_r) = plt.subplots(1, 2, figsize=(12, 5.5))
    ax_l.plot([floor, 1], [floor, 1], color=muted, linewidth=1, linestyle="--", zorder=1)
    ax_l.text(0.02, 0.028, "perfect calibration", color=muted, fontsize=9, rotation=45, ha="center")
    x = np.arange(1, len(raw) + 1)
    for name, st in styles.items():
        pred = bins[name]["mean_predicted"].clip(lower=floor)
        ax_l.errorbar(pred, obs, yerr=yerr, fmt=st["marker"], color=st["color"], markersize=6, elinewidth=0.8,
                      capsize=0, markerfacecolor=st["markerfacecolor"], markeredgewidth=1.3, label=st["label"],
                      zorder=3)
        ax_r.plot(x, pred, st["marker"], color=st["color"], markersize=6, markerfacecolor=st["markerfacecolor"],
                  markeredgewidth=1.5, label=st["label"] + ", mean predicted", zorder=4)
    ax_r.errorbar(x, obs, yerr=yerr, fmt="o", color=observed_c, markersize=8, elinewidth=1.5, capsize=0,
                  markeredgecolor="white", markeredgewidth=1.5, label="Observed (Kaplan-Meier), 95% CI", zorder=3)
    ax_l.set_xscale("log")
    ax_l.set_xlim(floor, 1)
    ax_l.set_xlabel("Mean predicted P(KEV within 90 days)", color=ink)
    ax_l.set_title("Per decile of raw Cox risk: neither recalibration fixes it", color=ink, loc="left", fontsize=11)
    ax_l.legend(frameon=False, loc="upper left", labelcolor=ink, fontsize=8)
    ax_r.set_xticks(x)
    ax_r.set_xlabel("Decile of raw predicted risk (1 = lowest)", color=ink)
    ax_r.set_title("Isotonic over-shoots the top; Platt is ~raw", color=ink, loc="left", fontsize=11)
    ax_r.legend(frameon=False, loc="upper left", labelcolor=ink, fontsize=8)

    for ax in (ax_l, ax_r):
        ax.set_yscale("log")
        ax.set_ylim(floor, 1 if ax is ax_l else 5e-2)
        ax.grid(True, which="major", color=grid, linewidth=0.8)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        for side in ("left", "bottom"):
            ax.spines[side].set_color("#c3c2b7")
        ax.tick_params(colors=muted)
    ax_l.set_ylabel("Observed P(KEV within 90 days), test set", color=ink)
    fig.suptitle("Cox 90-day calibration on test: raw vs two validation-fitted recalibrations, both evaluated and "
                 "rejected (CIs: 200 CVE-clustered bootstrap resamples; values at 0 drawn at the axis floor)",
                 color=muted, fontsize=9, x=0.01, ha="left")
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    main()
