"""
Post-freeze secondary metrics (docs/evaluation_plan.md's time-dependent
AUC, plus Brier score and calibration for Cox), computed on the FROZEN
models in models/ — nothing is refit, retuned, or re-featured here. These
numbers were produced after the freeze and cannot have influenced model
selection.

1. Time-dependent AUC at 30/90/180 days from each row's as_of_date, for
   Cox, RSF, XGBoost-AFT and EPSS raw score alone, pooled and per
   landmark, with paired differences vs EPSS.
2. Cox only: IPCW Brier score at 30/90/180 days, integrated Brier over
   30-180 days, index of prediction accuracy vs a covariate-free
   reference (training Kaplan-Meier), and decile calibration of
   P(KEV within 90 days) -> docs/figures/calibration_90d.png.
3. The outstanding paired C-index check: XGBoost-AFT vs EPSS-alone.

EPSS gets no Brier score: EPSS's raw score is a probability of observed
exploitation ACTIVITY in the next 30 days, not of KEV listing, and says
nothing about 90 or 180 days. Any mapping to P(KEV by t) would be a new
fitted model, not EPSS.

Usage: python -m scripts.evaluate.post_freeze_metrics
"""

from __future__ import annotations

import json
import logging
import pickle

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import xgboost as xgb
from sksurv.nonparametric import kaplan_meier_estimator

from config.config_schema import get_config
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.evaluate.common import (
    DEFAULT_AUC_HORIZONS,
    HorizonOutOfRangeError,
    evaluate_brier,
    evaluate_time_dependent_auc,
    km_calibration_table,
    paired_bootstrap_compare,
    paired_time_dependent_auc_compare,
    survival_array,
    time_dependent_auc,
)
from scripts.evaluate.features import encode_against
from scripts.evaluate.final_comparison import _prep
from scripts.features.build_landmark_dataset import MODEL_FEATURE_COLUMNS

logger = get_logger(__name__, category="evaluate")

BRIER_TIMES = np.arange(30, 181, dtype=float)  # daily grid for the integrated Brier score
CALIBRATION_HORIZON = 90


def load_frozen_predictions(test_df, models_dir, *, encoding="original"):
    """Risk scores (higher = higher risk) from the three frozen models, plus
    the frozen Cox model and its test design matrix for survival curves.
    encoding="original" reproduces the recorded numbers (and this script's
    own outputs); "corrected" is what scripts/evaluate/corrected_encoding.py
    uses — see scripts/evaluate/features.py::encode_against."""
    with open(models_dir / "cox_final.pkl", "rb") as f:
        cox = pickle.load(f)
    X_cox = encode_against(test_df, cox["one_hot_columns"], encoding=encoding).drop(columns=cox["dropped_const_cols"])

    with open(models_dir / "rsf_final.pkl", "rb") as f:
        rsf = pickle.load(f)
    X_rsf = encode_against(test_df, rsf["one_hot_columns"], encoding=encoding)

    booster = xgb.Booster()
    booster.load_model(str(models_dir / "xgboost_aft_final.json"))
    with open(models_dir / "xgboost_aft_final_columns.json") as f:
        xgb_cols = json.load(f)["one_hot_columns"]
    X_xgb = encode_against(test_df, xgb_cols, encoding=encoding)

    scores = {
        "Cox": cox["model"].predict_partial_hazard(X_cox).values,
        "RSF": rsf["model"].predict(X_rsf),
        "XGBoost-AFT": -booster.predict(xgb.DMatrix(X_xgb)),  # AFT predicts a time: negate
        "EPSS raw": test_df["epss_score_at_asof_raw"].values.astype(float),
    }
    return scores, cox["model"], X_cox


def _check_frozen_metrics(test_df, scores, models_dir):
    """Refuse to report anything if the loaded models don't reproduce the
    test C-index recorded at freeze time."""
    from scripts.evaluate.common import fast_concordance_index
    duration = test_df["event_time"].clip(lower=0.5).values
    event = test_df["composite_event"].values.astype(int)
    for name, stem in [("Cox", "cox"), ("RSF", "rsf"), ("XGBoost-AFT", "xgboost_aft")]:
        with open(models_dir / f"{stem}_final_metadata.json") as f:
            recorded = json.load(f)["test_metrics"]["test_cindex"]
        got = fast_concordance_index(duration, scores[name], event)
        if abs(got - recorded) > 1e-9:
            raise RuntimeError(f"{name}: frozen model gives C-index {got}, metadata records {recorded}")


def step1_time_dependent_auc(test_df, scores, y_train):
    out = {"pooled": {}, "per_landmark": {}, "paired_vs_epss": {}, "out_of_range": []}
    subsets = [("pooled", np.ones(len(test_df), dtype=bool))] + [
        (f"landmark_{lm}", (test_df["landmark_day"] == lm).values)
        for lm in sorted(test_df["landmark_day"].unique(), key=int)
    ]
    for subset, mask in subsets:
        sub = test_df[mask].reset_index(drop=True)
        target = out["pooled"] if subset == "pooled" else out["per_landmark"].setdefault(subset, {})
        for name, s in scores.items():
            try:
                res = evaluate_time_dependent_auc(sub, s[mask], survival_train=y_train, label=f"{name} {subset}")
            except HorizonOutOfRangeError as exc:
                out["out_of_range"].append({"subset": subset, "model": name, "error": str(exc)})
                continue
            target[name] = {str(h): r.as_dict() for h, r in res.items()}
        paired = out["paired_vs_epss"].setdefault(subset, {})
        for name, s in scores.items():
            if name == "EPSS raw":
                continue
            try:
                res = paired_time_dependent_auc_compare(sub, s[mask], scores["EPSS raw"][mask],
                                                        survival_train=y_train, label=f"{name} vs EPSS {subset}")
            except HorizonOutOfRangeError as exc:
                out["out_of_range"].append({"subset": subset, "model": f"{name} vs EPSS", "error": str(exc)})
                continue
            paired[name] = {str(h): r for h, r in res.items()}
    return out


def _km_curve_on_grid(duration, event, times):
    km_times, km_surv = kaplan_meier_estimator(event.astype(bool), duration.astype(float))
    pos = np.searchsorted(km_times, times, side="right") - 1
    return np.where(pos >= 0, km_surv[np.clip(pos, 0, None)], 1.0)


def step2_cox_brier_and_calibration(test_df, train_df, cox_model, X_cox, y_train, figure_path):
    surv = cox_model.predict_survival_function(X_cox, times=BRIER_TIMES).T.values  # n_rows x len(times)
    reference = _km_curve_on_grid(train_df["event_time"].clip(lower=0.5).values,
                                  train_df["composite_event"].values, BRIER_TIMES)

    brier = evaluate_brier(test_df, surv, BRIER_TIMES, survival_train=y_train,
                           reference_surv_prob=reference, label="Cox")

    p90 = 1.0 - surv[:, int(np.flatnonzero(BRIER_TIMES == CALIBRATION_HORIZON)[0])]
    calib = km_calibration_table(test_df, p90, CALIBRATION_HORIZON, label="Cox")
    _plot_calibration(calib, figure_path)

    return {
        "brier": {k: v.as_dict() for k, v in brier.items()},
        "reference_surv_prob_at": {str(int(h)): float(reference[BRIER_TIMES == h][0]) for h in DEFAULT_AUC_HORIZONS},
        "calibration_90d": calib.to_dict(orient="records"),
    }


def _plot_calibration(calib, path):
    """Left: predicted vs observed on the full probability scale (shows how
    compressed the predictions are). Right: the same deciles side by side,
    predicted vs observed, so the per-decile gap is readable."""
    bins = calib[calib["bin"] != "all"].reset_index(drop=True)
    floor = 1e-5
    ink, muted, grid, series = "#0b0b0b", "#52514e", "#e5e4e0", "#2a78d6"
    obs = bins["observed"].clip(lower=floor)
    yerr = [obs - bins["observed_ci_lower"].clip(lower=floor), bins["observed_ci_upper"].clip(lower=floor) - obs]
    point_style = dict(fmt="o", color=series, markersize=8, elinewidth=1.5, capsize=0, zorder=3,
                       markeredgecolor="white", markeredgewidth=1.5)

    fig, (ax_l, ax_r) = plt.subplots(1, 2, figsize=(12, 5.5))

    ax_l.plot([floor, 1], [floor, 1], color=muted, linewidth=1, linestyle="--", zorder=1)
    ax_l.text(0.02, 0.028, "perfect calibration", color=muted, fontsize=9, rotation=45, ha="center")
    ax_l.errorbar(bins["mean_predicted"], obs, yerr=yerr, **point_style)
    ax_l.set_xscale("log")
    ax_l.set_xlim(floor, 1)
    ax_l.set_xlabel("Mean predicted P(KEV within 90 days)", color=ink)
    ax_l.set_title("All deciles fall in 0.08%-0.11% predicted", color=ink, loc="left", fontsize=11)

    x = np.arange(1, len(bins) + 1)
    ax_r.plot(x, bins["mean_predicted"], "o", color=muted, markersize=8, markerfacecolor="white",
              markeredgewidth=2, label="Mean predicted (Cox)", zorder=3)
    ax_r.errorbar(x, obs, yerr=yerr, label="Observed (Kaplan-Meier), 95% CI", **point_style)
    ax_r.set_xticks(x)
    ax_r.set_xlabel("Decile of predicted risk (1 = lowest)", color=ink)
    ax_r.set_title("Low deciles over-predicted, top decile under-predicted ~6x", color=ink, loc="left", fontsize=11)
    ax_r.legend(frameon=False, loc="upper left", labelcolor=ink)

    for ax in (ax_l, ax_r):
        ax.set_yscale("log")
        ax.set_ylim(floor, 1 if ax is ax_l else 2e-2)
        ax.grid(True, which="major", color=grid, linewidth=0.8)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        for side in ("left", "bottom"):
            ax.spines[side].set_color("#c3c2b7")
        ax.tick_params(colors=muted)
    ax_l.set_ylabel("Observed P(KEV within 90 days), test set", color=ink)
    fig.suptitle("Cox calibration at 90 days — test set, deciles of predicted risk "
                 "(CIs: 200 CVE-clustered bootstrap resamples; lower bounds at 0 drawn at the axis floor)",
                 color=muted, fontsize=9, x=0.01, ha="left")
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)


def step3_xgb_cindex_vs_epss(test_df, scores):
    """The report's EPSS-alone baseline is epss_pct_now; checked against
    the raw score too."""
    xgb_score = scores["XGBoost-AFT"]
    return {
        "vs_epss_pct_now": paired_bootstrap_compare(test_df, xgb_score, test_df["epss_pct_now"].fillna(0).values,
                                                    label="XGBoost-AFT vs EPSS pct")["cindex"],
        "vs_epss_raw": paired_bootstrap_compare(test_df, xgb_score, scores["EPSS raw"],
                                                label="XGBoost-AFT vs EPSS raw")["cindex"],
    }


def censoring_sensitivity(test_df, scores, cox_model, X_cox):
    """Point estimates only: the same metrics with the censoring
    distribution estimated from TEST instead of train. Train rows have up to
    ~3 years of follow-up and test rows at most ~620 days, so the two
    censoring distributions differ; if the headline numbers moved a lot
    under this swap, the IPCW weights would be doing the work."""
    from sksurv.metrics import integrated_brier_score
    y_test = survival_array(test_df["event_time"].clip(lower=0.5).values, test_df["composite_event"].values)
    out = {name: dict(zip(map(str, DEFAULT_AUC_HORIZONS),
                          time_dependent_auc(y_test, y_test, s, DEFAULT_AUC_HORIZONS).tolist()))
           for name, s in scores.items()}
    surv = cox_model.predict_survival_function(X_cox, times=BRIER_TIMES).T.values
    out["Cox_ibs"] = float(integrated_brier_score(y_test, y_test, surv, BRIER_TIMES))
    return out


def main():
    cfg = get_config()
    models_dir = cfg.project_root / "models"
    train_df, test_df = _prep()
    y_train = survival_array(train_df["event_time"].clip(lower=0.5).values, train_df["composite_event"].values)

    scores, cox_model, X_cox = load_frozen_predictions(test_df, models_dir)
    _check_frozen_metrics(test_df, scores, models_dir)

    log_with_fields(logger, logging.INFO, "STEP 1: time-dependent AUC")
    step1 = step1_time_dependent_auc(test_df, scores, y_train)

    log_with_fields(logger, logging.INFO, "STEP 2: Cox Brier + calibration")
    step2 = step2_cox_brier_and_calibration(test_df, train_df, cox_model, X_cox, y_train,
                                            cfg.project_root / "docs" / "figures" / "calibration_90d.png")

    log_with_fields(logger, logging.INFO, "STEP 3: XGBoost-AFT C-index vs EPSS")
    step3 = step3_xgb_cindex_vs_epss(test_df, scores)

    sensitivity = censoring_sensitivity(test_df, scores, cox_model, X_cox)

    out = {"time_dependent_auc": step1, "cox_brier_calibration": step2,
           "xgb_cindex_vs_epss": step3, "censoring_from_test_sensitivity": sensitivity}
    with open(cfg.project_root / "scratch" / "post_freeze_metrics.json", "w") as f:
        json.dump(out, f, indent=2, default=str)
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
