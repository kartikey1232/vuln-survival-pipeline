# Robustness pass

Sensitivity analyses and recomputations. **No design choice, hyperparameter
or frozen model changes here.** Every number uses the corrected test
encoding (`encode_for_model`), train-median imputation, seed 20260922 and
200 whole-CVE resamples, through `scripts/evaluate/common.py`. This is a new
record; nothing earlier is overwritten.

## Summary

| # | Check | Outcome |
|---|---|---|
| 1a | Re-add the 6,755 version-transition test rows (16 events) | Cox > EPSS holds (ΔC +0.097, ΔR@10% +0.180, both CIs exclude 0) |
| 1b | Exclude VulnCheck-CNA CVEs (2,564 test CVEs, 26 events; *not* 46/3, which is train) | Holds (ΔC +0.108, ΔR@10% +0.132) |
| 1c | CNA CVSS present only (138,956 rows, 225 events) | Holds (ΔC +0.094, ΔR@10% +0.178): CVSS presence doesn't drive the result |
| 2a | XGBoost-AFT trajectory ablation, corrected | C-index null like Cox. At R@10% the full model is *worse* (−0.060, CI excludes 0). H1 stays rejected |
| 2b | RSF seed variance, corrected | Spread 0.0106, std 0.0046 (wider than 0.0062) |
| 3 | Display calibration (isotonic / Platt, fit on validation) | **Rejected:** isotonic IPA −0.42, Platt ≈ identity. Nothing shipped; Cox is for ranking only, now a tested finding |
| 4 | Dashboard screenshots | `docs/figures/dashboard_{cve_lookup,watchlist,backtest}.png` |

**Notation.** 95% CIs are in parentheses. In paired-difference tables,
**bold** means the interval excludes zero. "Recall@k%" is the share of a
subset's KEV events caught in the top k% of that subset's rows. EPSS-alone
is `epss_pct_now`, as everywhere else.

## 1. Sensitivity analyses (frozen Cox vs EPSS-alone, test)

`python -m scripts.evaluate.sensitivity` → `scratch/sensitivity.json`.

Each subset is resampled over its own CVEs with the same seed, so its
resamples are not the same CVE sets as the baseline's. Blind-spot catch is
measured against EPSS's top 10% *within* the subset. The script refuses to
run unless the baseline reproduces the recorded corrected-encoding Cox
C-index (0.850085), which it does.

| Subset | Rows | CVEs | KEV events (rows / CVEs) |
|---|---|---|---|
| Baseline (default test set) | 178,756 | 60,962 | 268 / 108 |
| a) + `spans_version_transition` rows | 185,511 | 61,856 | 284 / 113 |
| b) − CNA `disclosure@vulncheck.com` | 171,071 | 58,398 | 242 / 97 |
| c) CNA CVSS present only (`cvss_cna_missing = false`) | 138,956 | 47,203 | 225 / 93 |

| Subset | Cox C-index | EPSS C-index | Cox R@10% | EPSS R@10% | Cox blind-spot catch @10% |
|---|---|---|---|---|---|
| Baseline | 0.850 (0.810–0.887) | 0.750 (0.687–0.804) | 0.631 (0.529–0.718) | 0.459 (0.374–0.544) | 0.338 (0.210–0.458) |
| a) + transition rows | 0.852 (0.816–0.887) | 0.755 (0.705–0.807) | 0.637 (0.560–0.710) | 0.458 (0.383–0.554) | 0.351 (0.245–0.480) |
| b) − VulnCheck CNA | 0.844 (0.805–0.882) | 0.736 (0.681–0.791) | 0.603 (0.490–0.684) | 0.471 (0.374–0.557) | 0.297 (0.182–0.416) |
| c) CNA CVSS present | 0.872 (0.827–0.906) | 0.778 (0.727–0.827) | 0.689 (0.592–0.774) | 0.511 (0.412–0.616) | 0.391 (0.247–0.519) |

Recall at the other budgets:

| Subset | Cox R@1% | EPSS R@1% | Cox R@5% | EPSS R@5% |
|---|---|---|---|---|
| Baseline | 0.231 (0.149–0.298) | 0.190 (0.130–0.251) | 0.496 (0.398–0.591) | 0.369 (0.282–0.469) |
| a) + transition rows | 0.229 (0.165–0.293) | 0.201 (0.144–0.281) | 0.496 (0.417–0.577) | 0.370 (0.300–0.462) |
| b) − VulnCheck CNA | 0.244 (0.169–0.318) | 0.165 (0.100–0.228) | 0.492 (0.396–0.569) | 0.384 (0.283–0.466) |
| c) CNA CVSS present | 0.231 (0.158–0.317) | 0.222 (0.149–0.301) | 0.520 (0.429–0.617) | 0.404 (0.316–0.495) |

Paired Cox − EPSS-alone:

| Subset | ΔC-index | ΔRecall@1% | ΔRecall@5% | ΔRecall@10% |
|---|---|---|---|---|
| Baseline | **+0.100 (+0.069, +0.139)** | +0.041 (-0.022, +0.095) | **+0.127 (+0.055, +0.184)** | **+0.172 (+0.095, +0.236)** |
| a) + transition rows | **+0.097 (+0.065, +0.137)** | +0.028 (-0.037, +0.082) | **+0.127 (+0.050, +0.185)** | **+0.180 (+0.107, +0.262)** |
| b) − VulnCheck CNA | **+0.108 (+0.071, +0.149)** | **+0.079 (+0.023, +0.142)** | **+0.107 (+0.046, +0.175)** | **+0.132 (+0.060, +0.199)** |
| c) CNA CVSS present | **+0.094 (+0.062, +0.133)** | +0.009 (-0.036, +0.072) | **+0.116 (+0.035, +0.193)** | **+0.178 (+0.100, +0.254)** |

**No sensitivity flips the conclusion.** Cox's advantage over EPSS-alone on
C-index, recall@5% and recall@10% excludes zero in every subset, and the
point estimates stay within about 0.01 (C-index) and 0.04 (recall@10%) of
baseline. Recall@1% is not significant at baseline. It stays
non-significant in (a) and (c) and becomes significant in (b).

### a) Version-transition rows

These rows are test CVE × landmark rows whose window [published, as_of]
contains the 2025-03-17 EPSS model release. The default export drops them,
so they are not in `training.training_dataset`. The script rebuilds them
from the same build's `features.temporal_features`,
`features.static_features` and `training.survival_labels` (all stamped
2026-09-22 09:33:18). Before it uses them, it checks that the same rebuild
reproduces `training_dataset` exactly on all 178,756 unflagged test rows,
for every model feature, the label and `epss_score_at_asof_raw`.

- **Added: 6,755 rows** (4,018 CVEs) and **16 row-level events** (7
  CVEs). Per landmark: day 7 894 rows / 5 events, day 14 1,845 / 6, day 30
  4,016 / 5.
- Only test rows are added. The frozen model was trained without the
  training-period transition rows, and that is not changed.
- Cox's C-index and recall are slightly *higher* with the rows included.
  Excluding them does not flatter the result.

### b) VulnCheck as CNA

**The brief's count (46 CVEs, 3 positives) is the training-period
population.** On test, `disclosure@vulncheck.com` is the CNA for **2,564
CVEs** (7,685 rows, 26 row-level events from 11 CVEs). That is about 10% of
test events, far more than limitation 11 in `final_results.md` implied.
The CNA comes from the same `payload->>'sourceIdentifier'` lookup the
feature build uses.

- Excluding them lowers both models' C-index (Cox 0.850 → 0.844, EPSS 0.750
  → 0.736). The paired gap widens slightly on C-index and recall@1% and
  narrows on recall@10% (+0.172 → +0.132), and stays significant on all
  three.
- Cox's blind-spot catch drops 0.338 → 0.297. Some of Cox's blind-spot
  catches are VulnCheck-CNA CVEs. The interval overlaps baseline heavily.
- **The result does not depend on VulnCheck-reported CVEs.**

### c) Rows with a CNA-supplied CVSS score

This test addresses the residual CVSS-presence gap: train −2.76pp
(positives *more* often missing a CNA-CVSS score), test +6.23pp (positives
*less* often missing one), at landmark-row level. *[Corrected 2026-10-23;
originally quoted as "(2.8pp train / 6.2pp test)" with no sign or level.
See `docs/STATUS.md`, "Correction: residual CNA-CVSS presence gap".]* It keeps 138,956 rows (47,203 CVEs) with 225 events (93 CVEs) and
removes 39,800 rows and 43 events.

- Within this subset `cvss_cna_missing` is constant, so Cox cannot use CVSS
  presence to rank at all.
- **Cox's advantage holds at full size**: ΔC-index +0.094, ΔR@10% +0.178.
  Both models score higher here than at baseline.
- **CVSS presence is not what drives Cox's advantage over EPSS.** What
  this subset does *not* test is whether the presence gap inflates
  validation metrics relative to test. *[Corrected 2026-10-23: that caveat
  is **not established**. It assumed a larger same-direction gap on train,
  and the train gap is smaller and opposite in sign. Originally: "That
  caveat is about validation and stays as stated."]*

## 2. Re-runs of the two stale analyses (corrected encoding)

`python -m scripts.evaluate.stale_reruns` → `scratch/stale_reruns.json`.
`final_comparison.py`'s fit helpers already encoded test with
`encode_for_model` (since f457d0c). Only the recorded runs predated that.

### a) XGBoost-AFT trajectory ablation

These use the same feature sets as the Cox ablation: (b) drops the 6
trajectory features and keeps `epss_pct_now`; (c) drops all EPSS
features. XGBoost-AFT keeps its chosen config (not re-tuned). The
reduced-feature models are refits; the full model reproduces the frozen
model's corrected-encoding C-index exactly (0.785218).

| Feature set | C-index | Recall@5% | Recall@10% |
|---|---|---|---|
| a) full model | 0.7852 | 0.425 | 0.504 |
| b) minus trajectory | 0.8168 | 0.466 | 0.563 |
| c) minus all EPSS | 0.8164 | 0.429 | 0.545 |

| Paired | ΔC-index | ΔRecall@1% | ΔRecall@5% | ΔRecall@10% |
|---|---|---|---|---|
| (a) − (b) | -0.0316 (-0.0772, +0.0045) | -0.026 (-0.082, +0.047) | -0.041 (-0.100, +0.014) | **-0.060 (-0.114, -0.012)** |
| (a) − (c) | -0.0312 (-0.0732, +0.0028) | +0.041 (-0.029, +0.147) | -0.004 (-0.058, +0.068) | -0.041 (-0.102, +0.030) |

**This does not exactly match Cox's null result.**

- **C-index agrees with Cox:** the (a) − (b) interval spans zero.
- **Recall@10% does not agree:** the full XGBoost-AFT model is *worse*
  than the trajectory-free one by 6.0 points, with an interval excluding
  zero. This is essentially the original-encoding result (−0.0597).
- **Under the corrected encoding, the original-encoding finding stands.**
- **For H1 this changes nothing.** Neither model shows trajectory features
  *improving* discrimination, so H1 stays rejected.
- **Read the XGBoost-AFT finding narrowly.** It is evidence that adding
  trajectory features to this tuned XGBoost-AFT configuration hurts its
  top-10% ranking. It is not evidence that trajectory carries negative
  signal in general. Three reasons:
  - The configuration was tuned on mis-encoded validation inputs
    (limitation 2), and with the full feature set.
  - The reduced models reuse that configuration untuned.
  - Dropping *all* EPSS features also scores higher than the full model on
    C-index and recall@10% (not significant). That points to the full
    configuration over-fitting EPSS-derived inputs rather than to
    trajectory specifically.
- XGBoost-AFT is not the ranking model, and its gain over EPSS is not
  significant on any metric.

### b) RSF run-to-run variance

The chosen RSF config was refit 3 times, varying only `random_state`, with
`n_jobs=-1`. Test C-index, corrected encoding:

| random_state | Test C-index |
|---|---|
| 0 | 0.8121 |
| 1 | 0.8098 |
| 2 | 0.8204 |

- **Spread 0.0106, std 0.0046, mean 0.8141.** The original-encoding study
  reported a spread of 0.0062 and std of 0.0025, so the corrected spread
  is wider.
- Read any RSF number as **≈0.81 ± 0.01**. Differences between RSF and
  another model smaller than about 0.01 C-index are within RSF's own seed
  noise.
- The `random_state=0` refit matched the frozen RSF's corrected-encoding
  C-index exactly (0.812099) in this run. That is one match, not evidence
  of reproducibility. Rule 8 in `CLAUDE.md` stands.

## 3. Display calibration: evaluated and rejected (tested negative result)

`python -m scripts.evaluate.calibration` → `scratch/calibration_90d.json`,
`docs/figures/calibration_90d_calibrated.png`.

**Outcome: no calibrated probability is shipped.** The API and dashboard
show the raw Cox probability only, with the existing under-dispersion
note. This is a tested result, not a skipped step. Both calibrators were
fit on validation only and evaluated once on test, and both failed. The
choice was not between variants on test; that would be selection leakage.
It was whether to ship a component whose evaluation failed.

### What was fit

The input is frozen Cox's P(KEV within 90 days) = 1 − S(90 | x). This is
strictly increasing in the partial hazard, so it ranks identically.

- **Fit on validation only:** train CVEs published 2024-07-01..2024-12-31,
  53,674 rows / 18,973 CVEs, 55 events, 51 of them within 90 days.
- **IPCW weights:** validation labels are censored at 2025-01-01, so
  31,573 rows have under 90 days of follow-up and no event. The target
  "listed within 90 days" is therefore fit with censoring weights from
  validation's censoring Kaplan-Meier.
- **Two calibrators:** isotonic regression, and Platt (logistic on
  logit p).
- **Validation-only selection rule, stated before test:** isotonic unless
  Platt has the lower IPCW Brier@90d under 5-fold CVE-grouped
  cross-validation. Results (×10⁻³): raw 1.1760, isotonic 1.1404, Platt
  1.1760. **The rule picked isotonic.**

### Test results (200 whole-CVE resamples, same seed)

| | Brier@90d | IPA vs training KM | Range of P(KEV ≤90d) on test | Calibration-in-the-large (pred/obs) |
|---|---|---|---|---|
| Raw Cox | 0.001037 (0.000815–0.001265) | 0.00035 (0.00028–0.00042) | 0.078–0.191% | 0.93 |
| Isotonic (validation rule's pick) | 0.001476 (0.001253–0.001699) | **−0.423 (−0.562, −0.322)** | 0.000–25.7% | 3.23 |
| Platt | 0.001037 (0.000815–0.001265) | 0.00035 (0.00019–0.00046) | 0.097–0.228% | 1.16 |

90-day calibration per decile of **raw** Cox risk (the same rows in every
column; observed = test Kaplan-Meier):

| Decile | Events by 90d | Observed | Raw pred (ratio) | Isotonic pred (ratio) | Platt pred (ratio) |
|---|---|---|---|---|---|
| 1 | 1 | 0.006% (0.000–0.017%) | 0.083% (14.79) | 0.000% (0.00) | 0.103% (18.41) |
| 2 | 2 | 0.011% (0.000–0.034%) | 0.085% (7.61) | 0.000% (0.00) | 0.106% (9.46) |
| 3 | 1 | 0.006% (0.000–0.017%) | 0.087% (15.55) | 0.000% (0.00) | 0.108% (19.31) |
| 4 | 1 | 0.006% (0.000–0.017%) | 0.088% (15.78) | 0.001% (0.14) | 0.110% (19.58) |
| 5 | 13 | 0.073% (0.022–0.134%) | 0.090% (1.23) | 0.027% (0.37) | 0.111% (1.53) |
| 6 | 4 | 0.022% (0.000–0.057%) | 0.091% (4.06) | 0.027% (1.20) | 0.113% (5.04) |
| 7 | 9 | 0.050% (0.011–0.106%) | 0.093% (1.85) | 0.027% (0.53) | 0.115% (2.28) |
| 8 | 19 | 0.106% (0.039–0.179%) | 0.096% (0.90) | 0.034% (0.32) | 0.118% (1.11) |
| 9 | 14 | 0.078% (0.034–0.142%) | 0.101% (1.28) | 0.319% (4.07) | 0.124% (1.58) |
| 10 | 113 | 0.632% (0.465–0.809%) | 0.112% (0.18) | 2.767% (4.38) | 0.137% (0.22) |
| all | 177 | 0.099% (0.078–0.121%) | 0.093% (0.93) | 0.320% (3.23) | 0.115% (1.16) |

- **Isotonic over-predicts.** It is about 3.2× too high overall and puts
  the top decile at about 2.8% against 0.63% observed. It also predicts
  exactly 0 for the bottom ~40% of rows. Its top step (25.7%) was learned
  from 62 validation rows, 10 of which had events. On test it is worse than
  the covariate-free base rate.
- **Platt is effectively the identity** (slope 0.95 on the logit scale).
  IPA is unchanged and the predictions stay under-dispersed (0.10–0.23%).
  Calibration-in-the-large gets slightly worse (1.16 vs 0.93).

### Ranking invariance check

| Score ranked by | C-index | Recall@10% | Distinct values on test |
|---|---|---|---|
| Cox partial hazard (the ranking) | 0.8501 (0.810–0.887) | 0.631 (0.529–0.718) | 121,454 |
| Raw P(KEV ≤90d) | 0.8501 (0.810–0.887) | 0.631 (0.529–0.718) | 121,454 |
| Platt | 0.8501 (0.810–0.887) | 0.631 (0.529–0.718) | 121,454 |
| Isotonic | 0.8359 (0.795–0.869) | 0.586 (0.495–0.687) | 345 |

- **Strictly increasing maps leave ranking unchanged.** Raw P(KEV ≤90d)
  and Platt give identical C-index and recall to the partial hazard.
- **Isotonic is not strictly increasing.** It is a step function that
  collapses 121,454 distinct scores into 345 values, and the resulting ties
  cost 0.014 C-index and 4.5 points of recall@10%. "A monotone transform
  cannot alter the ranking" is true only for *strictly* monotone
  transforms. A tie-producing calibrator could only ever be displayed, never
  ranked by.

### Conclusion

**A validation-fitted monotone recalibration does not transfer to the test
period.**

- This ties to the train → test distribution shift (limitation 10): the
  shift is large enough to break calibration transfer, not only to move
  percentiles.
- Two effects are mixed here, and these data cannot separate them:
  1. **Period shift.** The base rate shifts between validation and test,
     though only modestly in the large (90-day KM 0.118% vs 0.099%).
  2. **In-sample fit.** Validation is in-sample for the frozen Cox model
     (limitation 1), so its top-end separation on validation is sharper
     than it is out of sample. This is what the isotonic top step
     captured.
- Either way, the under-dispersion is **not correctable by a post-hoc
  transformation fitted on this data's validation period**. "Use Cox for
  ranking, not as calibrated probabilities" is now a tested finding, not
  only a design decision.
- The figure keeps both recalibration curves next to the raw one, labelled
  as evaluated and rejected. The original
  `calibration_90d_corrected_encoding.png` is unchanged.

## 4. Dashboard screenshots

Captured from the running local API and dashboard (`api/` + `dashboard/`,
unchanged by this pass) with headless Chrome, 1440 px wide at 2× device
scale (2880 px images):

- `docs/figures/dashboard_cve_lookup.png`: **CVE-2025-24472** (Fortinet
  FortiOS/FortiProxy auth bypass, KEV-listed 2025-03-18, known ransomware
  use). This is the clearest blind-spot example. Cox places it at the 92nd
  / 89th / 88th training percentile at landmarks 7 / 14 / 30, while its
  EPSS percentile sits at ~12% until the KEV listing.
- `docs/figures/dashboard_watchlist.png`: the 10% budget, pooled, page 2
  (Cox ranks 51–69 visible). Cox's top 50 contains no EPSS blind spots;
  page 2 shows two highlighted "EPSS ranks low" rows (ranks 62 and 67) among
  rows EPSS also ranks highly. Across the whole 10% budget, 4,982 of 17,876
  selected rows (28%) are EPSS blind spots.
- `docs/figures/dashboard_backtest.png`: the corrected-encoding backtest
  view.

The CVE view shows the raw Cox probability only, per section 3.
