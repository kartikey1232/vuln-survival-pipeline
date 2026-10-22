# Robustness pass

Sensitivity analyses and recomputations. **No design choice, hyperparameter
or frozen model changes here.** Every number uses the corrected test
encoding (`encode_for_model`), train-median imputation, seed 20260922 and
200 whole-CVE resamples, through `scripts/evaluate/common.py`. This is a new
record; nothing earlier is overwritten.

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

This test addresses the residual CVSS-presence gap (2.8pp train / 6.2pp
test). It keeps 138,956 rows (47,203 CVEs) with 225 events (93 CVEs) and
removes 39,800 rows and 43 events.

- Within this subset `cvss_cna_missing` is constant, so Cox cannot use CVSS
  presence to rank at all.
- **Cox's advantage holds at full size**: ΔC-index +0.094, ΔR@10% +0.178.
  Both models score higher here than at baseline.
- **CVSS presence is not what drives Cox's advantage over EPSS.** What
  this subset does *not* test is whether the presence gap inflates
  validation metrics relative to test. That caveat is about validation and
  stays as stated.

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
