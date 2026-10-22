# Final results

Every number the report and deck need, in one place.

**Encoding.** Every number here uses the **corrected test encoding**
(`docs/results_corrected_encoding.md`): the same frozen models, the same
seed (20260922) and the same 200 whole-CVE resamples, through
`scripts/evaluate/common.py`. The original-encoding numbers stay in
`docs/model_comparison.md` and `docs/fuzzy_layer.md`, marked as such.

**Robustness.** Sensitivity analyses, the corrected re-runs of the RSF
variance study and the XGBoost-AFT trajectory ablation, and the
display-calibration test are in **`docs/robustness.md`**. Their headline
numbers are summarised below under "Robustness".

**Notation.** 95% CIs are in parentheses. In paired-difference tables,
**bold** means the interval excludes zero. "Recall@k%" is the share of all
test KEV events caught in the top k% of rows.

**Generated from:**
`scratch/results_corrected_encoding.json`, `scratch/fuzzy_evaluation.json`,
`scratch/cox_trajectory_ablation.json`, `models/fuzzy_config.json` and the
model metadata. The robustness numbers come from `scratch/sensitivity.json`,
`scratch/stale_reruns.json` and `scratch/calibration_90d.json`, computed in
`docs/robustness.md`. Budget equivalence comes from
`scratch/budget_equivalence.json` (`scripts/evaluate/budget_equivalence.py`).

**Further analyses.** `docs/rolling_origin.md` is a rolling-origin
consistency check over four disjoint 6-month windows. `docs/lead_time.md`
is a post-hoc, descriptive lead-time analysis. Both are summarised under
"Robustness" below; neither replaces a headline number.

## Population and volume

| | Rows | CVEs | KEV events |
|---|---|---|---|
| Train (published < 2025-01-01; labels censored 2025-01-01) | 268,944 | 92,141 | 441 |
| … of which validation (published 2024-07-01..2024-12-31) | 53,674 | 18,973 | 55 |
| Test (published ≥ 2025-01-01; observed to 2026-09-20) | 178,756 | 60,962 | 268 |

| Landmark | Train rows | Train events | Test rows | Test events |
|---|---|---|---|---|
| day 7 | 91,447 | 171 | 60,961 | 108 |
| day 14 | 90,867 | 151 | 59,990 | 87 |
| day 30 | 86,630 | 119 | 57,805 | 73 |

Per-landmark counts and the 441 training events come from the recorded
`scripts/fuzzy/risk_percentile.py` run (commit 18d1548). Row counts are
independent of encoding. A row is a CVE × landmark that was still
unlisted, with an EPSS observation, at the landmark. A CVE contributes up
to 3 rows.

Other counts:

- 62% of KEV listings happen within 30 days of publication. This is why
  the design uses landmarks 7/14/30.
- 177 of the test events fall within 90 days of their landmark. This is
  the base for calibration.
- 84,684 test rows were mis-encoded by the original test encoding, and all
  53,674 validation rows were mis-encoded (one feature each).
- Data: NVD/EPSS backfill 2021-11-01 → 2026-09-20; dataset version
  `landmark_v20260922`; 23 model features.

## Model comparison

| Model | C-index | Recall@1% | Recall@5% | Recall@10% | Blind-spot catch @10% |
|---|---|---|---|---|---|
| **Cox** (ranking model) | 0.850 (0.810–0.887) | 0.231 (0.149–0.298) | 0.496 (0.398–0.591) | 0.631 (0.529–0.718) | 0.338 (0.210–0.458) |
| RSF | 0.812 (0.757–0.854) | 0.287 (0.214–0.366) | 0.504 (0.414–0.578) | 0.582 (0.482–0.667) | 0.379 (0.253–0.506) |
| XGBoost-AFT | 0.785 (0.734–0.825) | 0.231 (0.165–0.315) | 0.425 (0.330–0.504) | 0.504 (0.413–0.592) | 0.428 (0.297–0.545) |
| EPSS-alone | 0.750 (0.687–0.804) | 0.190 (0.130–0.251) | 0.369 (0.282–0.469) | 0.459 (0.374–0.544) | 0 (by definition) |

Blind-spot catch rate is the share of test events outside EPSS-alone's top
10% that a model places in its own top 10%. Paired against Cox: RSF +0.041 (-0.037, +0.134), XGBoost-AFT +0.090 (-0.032, +0.206).
Neither excludes zero.

### Paired difference vs EPSS-alone (`epss_pct_now`)

| Model | ΔC-index | ΔRecall@1% | ΔRecall@5% | ΔRecall@10% |
|---|---|---|---|---|
| Cox | **+0.100 (+0.069, +0.139)** | +0.041 (-0.022, +0.095) | **+0.127 (+0.055, +0.184)** | **+0.172 (+0.095, +0.236)** |
| RSF | **+0.062 (+0.003, +0.124)** | **+0.097 (+0.036, +0.157)** | **+0.134 (+0.049, +0.231)** | **+0.123 (+0.028, +0.234)** |
| XGBoost-AFT | +0.035 (-0.029, +0.105) | +0.041 (-0.043, +0.128) | +0.056 (-0.040, +0.150) | +0.045 (-0.066, +0.161) |

**XGBoost-AFT vs EPSS is not significant on any metric.** Against raw
EPSS its ΔC-index is +0.037 (-0.023, +0.106).

### Budget equivalence (Cox vs EPSS-alone)

The table answers one question: what alert budget does EPSS-alone need to
match Cox's recall? It is read off the test recall-at-budget curves, pooled
over landmarks, with the same top-k rule as recall@k. CIs come from the same
200 whole-CVE resamples.

| Cox budget | Cox recall | EPSS recall at same budget | EPSS budget needed to match Cox | Effort ratio (EPSS / Cox) |
|---|---|---|---|---|
| 1% | 0.231 (0.149–0.298) | 0.190 (0.130–0.251) | 1.7% (0.5–2.9%) | 1.7× (0.5–2.9×) |
| 5% | 0.496 (0.398–0.591) | 0.369 (0.282–0.469) | 10.8% (6.3–14.6%) | **2.2× (1.3–2.9×)** |
| 10% | 0.631 (0.529–0.718) | 0.459 (0.374–0.544) | 23.5% (17.6–37.4%) | **2.3× (1.8–3.7×)** |

- **At 5% and 10%, EPSS-alone needs a bit over twice the triage effort to
  reach Cox's recall.** Both intervals exclude 1×.
- At 1% the ratio's interval includes 1×, matching the non-significant
  ΔRecall@1%.
- This is a computation on the existing curves, not new modelling.

### Per-landmark C-index

| Landmark | Cox | RSF | XGBoost-AFT | EPSS-alone |
|---|---|---|---|---|
| day 7 | 0.857 (0.822–0.890) | 0.813 (0.763–0.854) | 0.761 (0.702–0.808) | 0.761 (0.705–0.803) |
| day 14 | 0.858 (0.811–0.897) | 0.815 (0.756–0.862) | 0.786 (0.727–0.842) | 0.766 (0.697–0.819) |
| day 30 | 0.831 (0.782–0.883) | 0.805 (0.749–0.860) | 0.838 (0.786–0.884) | 0.714 (0.634–0.796) |

## Time-dependent AUC (cumulative/dynamic; censoring weights from train)

Pooled, with paired differences vs raw EPSS:

| Model | AUC 30d | AUC 90d | AUC 180d | ΔAUC 30d | ΔAUC 90d | ΔAUC 180d |
|---|---|---|---|---|---|---|
| Cox | 0.851 (0.796–0.899) | 0.850 (0.806–0.889) | 0.853 (0.814–0.888) | **+0.115 (+0.066, +0.172)** | **+0.114 (+0.070, +0.163)** | **+0.119 (+0.084, +0.165)** |
| RSF | 0.824 (0.755–0.878) | 0.815 (0.746–0.865) | 0.822 (0.767–0.861) | **+0.088 (+0.003, +0.167)** | **+0.080 (+0.010, +0.160)** | **+0.087 (+0.030, +0.149)** |
| XGBoost-AFT | 0.758 (0.693–0.824) | 0.777 (0.713–0.828) | 0.787 (0.732–0.830) | +0.023 (-0.053, +0.109) | +0.042 (-0.034, +0.123) | +0.053 (-0.014, +0.123) |
| EPSS raw | 0.736 (0.668–0.808) | 0.736 (0.663–0.802) | 0.734 (0.670–0.798) | — | — | — |

Per landmark (point AUC; bold = paired Δ vs raw EPSS excludes zero):

| Landmark | Horizon | EPSS raw | Cox | RSF | XGBoost-AFT |
|---|---|---|---|---|---|
| day 7 | 30d | 0.787 | **0.876** | 0.824 | 0.752 |
| day 7 | 90d | 0.766 | **0.869** | 0.818 | 0.745 |
| day 7 | 180d | 0.749 | **0.861** | **0.822** | 0.767 |
| day 14 | 30d | 0.770 | **0.868** | 0.836 | 0.762 |
| day 14 | 90d | 0.748 | **0.857** | 0.823 | 0.783 |
| day 14 | 180d | 0.748 | **0.856** | **0.821** | 0.791 |
| day 30 | 30d | 0.615 | **0.794** | **0.805** | **0.825** |
| day 30 | 90d | 0.673 | **0.813** | **0.798** | **0.826** |
| day 30 | 180d | 0.695 | **0.837** | **0.819** | **0.837** |

Cox beats EPSS at every horizon, pooled and at every landmark.
XGBoost-AFT beats EPSS only at landmark 30. Out-of-range horizons: none.

## Brier score and calibration (Cox)

| Metric | Cox | Reference (training KM, no covariates) | IPA |
|---|---|---|---|
| Brier 30d | 0.000558 (0.000421–0.000729) | 0.000558 (0.000421–0.000729) | 0.000172 (0.000127–0.000223) |
| Brier 90d | 0.001037 (0.000815–0.001265) | 0.001038 (0.000815–0.001266) | 0.000349 (0.000277–0.000422) |
| Brier 180d | 0.001325 (0.001049–0.001626) | 0.001326 (0.001049–0.001627) | 0.000538 (0.000425–0.000631) |
| Integrated 30–180d | 0.001036 (0.000835–0.001268) | 0.001037 (0.000836–0.001269) | 0.000383 (0.000300–0.000458) |

IPA is significantly above zero but tiny, because KEV listing is rare.

90-day calibration by decile of predicted risk:

| Decile | Mean predicted | Observed (KM) | Ratio pred/obs | Events by 90d |
|---|---|---|---|---|
| 1 | 0.083% | 0.006% (0.000–0.017%) | 14.79 | 1 |
| 2 | 0.085% | 0.011% (0.000–0.034%) | 7.61 | 2 |
| 3 | 0.087% | 0.006% (0.000–0.017%) | 15.55 | 1 |
| 4 | 0.088% | 0.006% (0.000–0.017%) | 15.78 | 1 |
| 5 | 0.090% | 0.073% (0.022–0.134%) | 1.23 | 13 |
| 6 | 0.091% | 0.022% (0.000–0.057%) | 4.06 | 4 |
| 7 | 0.093% | 0.050% (0.011–0.106%) | 1.85 | 9 |
| 8 | 0.096% | 0.106% (0.039–0.179%) | 0.90 | 19 |
| 9 | 0.101% | 0.078% (0.034–0.142%) | 1.28 | 14 |
| 10 | 0.112% | 0.632% (0.465–0.809%) | 0.18 | 113 |
| all | 0.093% | 0.099% (0.078–0.121%) | 0.93 | 177 |

- **Predicted P(KEV ≤ 90d) is under-dispersed.** It spans only
  0.078–0.191% across all test rows.
- The top decile is under-predicted about 6×. Calibration-in-the-large is
  fine.
- Use Cox for ordering, not as calibrated probabilities. **This is now a
  tested finding.** Isotonic and Platt recalibrations fit on validation
  both failed on test (isotonic IPA −0.42; Platt ≈ identity), so no
  calibrated probability is shipped (`docs/robustness.md` §3).
- Figures: `docs/figures/calibration_90d_corrected_encoding.png`, and
  `docs/figures/calibration_90d_calibrated.png` (adds both rejected
  recalibrations).

## Trajectory ablation (H1)

**H1:** *"adding EPSS trajectory features improves discrimination over a
model using only the current EPSS value."* **Rejected: no evidence they
help.**

Cox, penalizer 0.1. The feature sets are: (b) drops the 6 trajectory
features (`epss_pct_7d_ago`, `epss_pct_7d_ago_missing`,
`epss_pct_delta_7d`, `epss_pct_first`, `epss_pct_max_to_date`,
`days_to_first_epss`) and keeps `epss_pct_now`; (c) drops all EPSS
features. These are refits of reduced-feature models; the feature sets and
settings are the same as in the original run.

| Feature set | C-index | Recall@5% | Recall@10% |
|---|---|---|---|
| a) full model | 0.8501 | 0.496 | 0.631 |
| b) minus trajectory | 0.8556 | 0.511 | 0.616 |
| c) minus all EPSS | 0.8329 | 0.425 | 0.556 |

| Paired | ΔC-index | ΔRecall@1% | ΔRecall@5% | ΔRecall@10% |
|---|---|---|---|---|
| (a) − (b) | -0.0055 (-0.0147, +0.0049) | -0.019 (-0.071, +0.029) | -0.015 (-0.084, +0.035) | +0.015 (-0.027, +0.054) |
| (a) − (c) | +0.0172 (-0.0103, +0.0441) | +0.022 (-0.060, +0.096) | +0.071 (-0.025, +0.162) | **+0.075 (+0.008, +0.139)** |

- **Trajectory features show no measurable benefit** (a null result): the
  (a) − (b) intervals all span zero.
- The point estimates split by metric: trimmed is higher on C-index, full
  Cox leads at recall@10% (0.631 vs 0.616). The trimmed model is not
  superior.
- **EPSS's current level carries real signal.** Full Cox beats
  Cox-without-any-EPSS at recall@10%, with an interval excluding zero. Its
  trajectory adds nothing measurable on top.

## Fuzzy layer vs Cox / EPSS / linear blend

The fuzzy layer is the **explanation layer**; the system ranks by Cox.
Its design was fixed on validation before test (`models/fuzzy_config.json`).
The linear blend is a Cox PH model on the same inputs, fitted on
validation.

| Ranking | C-index | Recall@1% | Recall@5% | Recall@10% | Blind-spot catch @10% |
|---|---|---|---|---|---|
| Fuzzy | 0.841 (0.802–0.876) | 0.213 (0.145–0.280) | 0.448 (0.358–0.542) | 0.534 (0.444–0.616) | 0.207 (0.121–0.287) |
| Cox | 0.850 (0.810–0.887) | 0.231 (0.149–0.298) | 0.496 (0.398–0.591) | 0.631 (0.529–0.718) | 0.338 (0.210–0.458) |
| EPSS | 0.750 (0.687–0.804) | 0.190 (0.130–0.251) | 0.369 (0.282–0.469) | 0.459 (0.374–0.544) | 0 (by definition) |
| Linear blend | 0.836 (0.787–0.870) | 0.201 (0.138–0.267) | 0.470 (0.376–0.557) | 0.582 (0.493–0.660) | 0.317 (0.209–0.447) |

| Fuzzy minus | ΔC-index | ΔRecall@1% | ΔRecall@5% | ΔRecall@10% | ΔBlind-spot @10% |
|---|---|---|---|---|---|
| Cox | -0.009 (-0.015, +0.000) | -0.019 (-0.051, +0.011) | -0.049 (-0.103, +0.014) | **-0.097 (-0.154, -0.031)** | **-0.131 (-0.229, -0.024)** |
| EPSS | **+0.092 (+0.056, +0.130)** | +0.022 (-0.028, +0.077) | **+0.078 (+0.032, +0.129)** | **+0.075 (+0.022, +0.145)** | — (EPSS catch rate is 0 by definition) |
| Linear blend | +0.006 (-0.010, +0.026) | +0.011 (-0.034, +0.061) | -0.022 (-0.098, +0.055) | -0.049 (-0.135, +0.029) | -0.110 (-0.231, +0.000) |

- **No better than the linear blend:** no paired difference excludes zero.
- **Worse than Cox:** at recall@10% and on the blind-spot catch rate, both
  with intervals excluding zero.
- **Better than EPSS alone.**
- Its contribution is per-row interpretability: the rules that fired and
  their strengths.
- 76.4% of test rows share their
  fuzzy priority with another row. The top plateau (79.52) holds
  11,886 test rows, so the top 1% and 5%
  are ordered by the tie-break.

## Robustness (`docs/robustness.md`)

**Sensitivity of Cox vs EPSS-alone on test** (frozen Cox, same seed and
resamples). No subset flips the conclusion:

| Subset | Rows / events | Cox C-index | ΔC-index vs EPSS | ΔRecall@10% vs EPSS | Cox blind-spot catch @10% |
|---|---|---|---|---|---|
| Baseline | 178,756 / 268 | 0.850 | **+0.100 (+0.069, +0.139)** | **+0.172 (+0.095, +0.236)** | 0.338 |
| + version-transition rows | 185,511 / 284 | 0.852 | **+0.097 (+0.065, +0.137)** | **+0.180 (+0.107, +0.262)** | 0.351 |
| − VulnCheck-CNA CVEs | 171,071 / 242 | 0.844 | **+0.108 (+0.071, +0.149)** | **+0.132 (+0.060, +0.199)** | 0.297 |
| CNA CVSS present only | 138,956 / 225 | 0.872 | **+0.094 (+0.062, +0.133)** | **+0.178 (+0.100, +0.254)** | 0.391 |

**RSF run-to-run variance (corrected encoding).** The same RSF config was
refit with 3 seeds:
random_state 0: 0.8121 | random_state 1: 0.8098 | random_state 2: 0.8204.
Spread 0.0106, std 0.0046 (the original encoding gave 0.0062 / 0.0025).
Read any RSF number as ≈0.81 ± 0.01.

**XGBoost-AFT trajectory ablation (corrected encoding).**

- (a) − (b) ΔC-index is −0.032 (−0.077, +0.005), spanning zero, as with
  Cox.
- ΔRecall@10% is **−0.060 (−0.114, −0.012)**: the full model is *worse*
  than the trajectory-free one, the same as under the original encoding.
- Neither model shows trajectory features helping, so H1 stays rejected.
- The XGBoost-AFT result is specific to its config, which was tuned for the
  full feature set and reused untuned for the reduced ones.

**Display calibration: evaluated and rejected** (see "Brier score and
calibration" above).

**Rolling-origin consistency check** (`docs/rolling_origin.md`). Cox was
refit at each cutoff under the frozen recipe (no re-tuning) and tested on
the next 6 months. The 2025-01-01 refit reproduces the frozen model exactly
(C-index 0.850085 on the headline test).

| Cutoff | Test events | Cox C-index | EPSS C-index | ΔC-index | ΔRecall@10% |
|---|---|---|---|---|---|
| 2024-01-01 | 97 | 0.857 | 0.706 | **+0.151 (+0.092, +0.227)** | **+0.196 (+0.081, +0.337)** |
| 2024-07-01 | 125 | 0.804 | 0.621 | **+0.183 (+0.117, +0.260)** | **+0.160 (+0.071, +0.265)** |
| 2025-01-01 | 126 | 0.863 | 0.764 | **+0.099 (+0.055, +0.154)** | **+0.167 (+0.068, +0.289)** |
| 2025-07-01 | 103 | 0.858 | 0.750 | **+0.107 (+0.050, +0.177)** | **+0.146 (+0.021, +0.299)** |

The headline remains the frozen 2025-01-01 model; these folds are a
consistency check.

**Lead time (post-hoc, descriptive; `docs/lead_time.md`).** Out of 108
later-listed test CVEs, at a 10% per-landmark budget:

- When both models flag a CVE, they almost always do so at the same
  landmark (51 of 54).
- Cox flags 19 CVEs that EPSS never does. All are blind spots, flagged a
  median of 48 days (IQR 20–147.5) before listing.
- EPSS flags 2 that Cox never does.

## Limitations

1. **Validation is in-sample for Cox.** The frozen Cox model was refit on
   the full train set, which contains the validation rows. Fuzzy-layer
   validation metrics and the linear-blend weights are therefore
   optimistic. The fuzzy cut-offs are label-free quantiles and are not
   affected.
2. **RSF and XGBoost-AFT were tuned on mis-encoded validation inputs.**
   `epss_model_version_at_asof` was mis-encoded on all 53,674 validation
   rows: every row carried v2023.03.01 but was encoded as the
   `unversioned` reference. Their configurations may be suboptimal. They
   were not re-tuned, because test results are known and re-tuning would
   be selection leakage.
3. **Cox, the headline model, has no fit/validation tuning step.**
   `penalizer=0.1` was a fixed value, never compared on validation, so
   Cox is unaffected by limitation 2.
4. **Cox probabilities are badly under-dispersed** (top decile
   under-predicted about 6×). Cox is used for ranking only; the survival
   curves are not calibrated risk. *Tested:* validation-fitted isotonic and
   Platt recalibrations do not transfer to test, so this cannot be fixed by
   a post-hoc monotone map on this data (`docs/robustness.md` §3).
5. **Fuzzy top-end tie.** VeryHigh saturates at the validation 95th
   percentile, which ties about 6–7% of test rows at one score. The top
   1–5% is therefore ordered by the tie-break (`cox_risk_pct`), not by the
   rules.
6. **Fuzzy R02 (the thesis rule) is subsumed by R09** and never changes
   the score; it fires for explanation only. R15, R16 and R17 are also
   explanation-only.
7. **Fuzzy rule weights were left at 1.0.** 55 validation events cannot
   support a weight search.
8. **Fuzzy redesign would need a fresh validation period.** Test has been
   seen.
9. **`blindspot = 0` does not mean agreement.** `cox_risk_pct` and
   `epss_pct_now` are measured against different reference populations.
   Candidate fix for future work: put EPSS's raw score on Cox's reference
   distribution.
10. **There is a train vs test percentile shift.** Test `cox_risk_pct`
    medians are 0.32–0.38 against 0.5 on train. It is smaller than first
    reported, which was partly the encoding bug. *Tested consequence:* the
    shift (together with Cox being in-sample on validation) is large enough
    to break calibration transfer from validation to test, not only to
    move percentiles (`docs/robustness.md` §3).
11. **Residual enrichment bias.** Even after the own-CNA source rule,
    CVSS presence still differs between positives and negatives (2.8pp
    train / 6.2pp test). Validation C-index runs optimistic relative to
    test. *Tested:* restricting test to rows with a CNA CVSS score leaves
    Cox's advantage over EPSS intact (ΔC-index +0.094, ΔR@10% +0.178, both
    excluding zero), so CVSS presence is not what drives it. The validation
    optimism caveat stands. `disclosure@vulncheck.com`, a threat-intel
    vendor acting as CNA, is 46 CVEs in train but **2,564 CVEs (26 row-level
    events) on test**. *Tested:* excluding them leaves Cox's advantage intact
    (`docs/robustness.md` §1).
12. **Resolved: both stale analyses were re-run with the corrected
    encoding** (`docs/robustness.md` §2). The XGBoost-AFT ablation agrees
    with Cox on C-index. At recall@10% the full model is significantly
    worse than the trajectory-free one, which still gives no support for
    H1.
13. **RSF is not run-to-run reproducible** under `n_jobs=-1`: test C-index
    spread is 0.0106 across 3 seeds (corrected encoding).
14. **Version-transition rows.** The default export drops rows whose
    window spans an EPSS model release. *Tested:* adding back the 6,755 test
    rows (16 events) leaves every conclusion unchanged
    (`docs/robustness.md` §1).
15. **The original test encoding was wrong for 84,684 test rows.** Every
    number above uses the corrected encoding (`encode_for_model`). The
    original path is kept only to reproduce the old numbers.
16. **Small event counts.** There are 268 test events and 55 validation
    events. Recall CIs are wide (about ±0.1), and differences of a few
    points between models are mostly within noise.
