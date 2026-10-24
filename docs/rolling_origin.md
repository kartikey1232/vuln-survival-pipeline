# Rolling-origin evaluation (consistency check)

**The frozen 2025-01-01 Cox model remains the headline**
(`docs/final_results.md`). The other folds check whether its advantage over
EPSS-alone is consistent across time. They are not competing results, and
no number here replaces a headline number.

`python -m scripts.evaluate.rolling_origin` → `scratch/rolling_origin.json`.

## Design

For each cutoff k ∈ {2024-01-01, 2024-07-01, 2025-01-01, 2025-07-01}:

- **Train:** CVEs published before k, rows whose `as_of_date` is before k
  (the build's condition 3 at k), labels censored at k
  (`data_splits._relabel`, the same function the fit/val split uses).
- **Test:** CVEs published in [k, k + 6 months), labels observed to the
  data cutoff 2026-09-20. The four test windows are disjoint. Every window
  ends by 2026-01-01, so every test CVE is inside the build's 180-day
  minimum follow-up (`STUDY_END` = 2026-03-24; asserted per fold).
- **Model:** Cox refit under the frozen model's exact recipe
  (`final_comparison._fit_cox`). That is penalizer 0.1,
  `MODEL_FEATURE_COLUMNS`, one-hot on train with constant columns dropped,
  test encoded with `encode_for_model`, and train-median imputation. **This
  is a refit, not re-tuning:** no hyperparameter, feature or design choice
  changes between folds.
- **Evaluation:** Cox and EPSS-alone (`epss_pct_now`) on the fold's test
  rows, through `scripts/evaluate/common.py` (`evaluate_model`,
  `paired_bootstrap_compare`), with 200 whole-CVE resamples and seed
  20260922.
- **Version-transition rows** are excluded, as in the default export.

### Where the rows come from

`training.training_dataset` has no rows whose `as_of_date` crosses
2025-01-01 for CVEs published before it, because condition 3 drops them at
build time. Using it directly would truncate the 2024-07-01 fold's test
window: late-December 2024 CVEs would lose their day-14/30 rows.

- **One in-memory rebuild of the full landmark grid** supplies the rows
  instead. `build()` gained an optional `train_test_cutoff` parameter,
  default unchanged. Called with `STUDY_START`, no row is dropped by
  condition 3 and every label is observed to the data cutoff. Features are
  computed as of each row's own `as_of_date` and do not depend on the
  cutoff.
- **The rebuild adds 5,206 rows (12 events).** All of them fall in the
  2024-07-01 fold's test window: 658 day-7, 1,125 day-14 and 3,423 day-30
  rows.
- **The rebuild is checked before any fold runs.** It must reproduce
  `training_dataset` exactly on all 447,700 rows: every model feature, the
  label (train rows relabeled at 2025-01-01) and `epss_score_at_asof_raw`.
  Otherwise the script refuses to run.
  - **The first run failed this check**, on `cwe_kev_rate_expanding`.
  - **The cause was storage precision.** `training_dataset` stores
    `cwe_kev_rate_expanding` and `cna_kev_rate_expanding` as
    `NUMERIC(8,6)`. The frozen model was fit on those stored values, while
    the in-memory build is unrounded (differences ≤ 5×10⁻⁷).
  - Rounding the rebuild to 6 decimals gives exact equality on every row.
    The script now does this.

### Sanity check (passed)

The 2025-01-01 refit **reproduces the frozen model**. Its scores on the full
headline test set (178,756 rows, 268 events) match the frozen model's to a
maximum relative difference of 2.2×10⁻¹⁶. Its C-index is 0.850085, identical
to the frozen model's recorded corrected-encoding value. On the 2025-01-01
fold's own rows, the refit and the frozen model give identical C-index and
recall with identical CIs. That fold's training set is the headline training
set (268,944 rows, 441 events).

## Results

| Cutoff k | Test window | Train rows / events | Test rows / CVEs / events (event CVEs) |
|---|---|---|---|
| 2024-01-01 | 2024-01-01 – 2024-06-30 | 151,686 / 252 | 59,490 / 20,081 / 97 (36) |
| 2024-07-01 | 2024-07-01 – 2024-12-31 | 210,440 / 324 | 58,880 / 19,631 / 125 (46) |
| **2025-01-01** (headline model) | 2025-01-01 – 2025-06-30 | 268,944 / 441 | 64,497 / 22,865 / 126 (50) |
| 2025-07-01 | 2025-07-01 – 2025-12-31 | 332,401 / 600 | 73,702 / 24,575 / 103 (42) |

| Cutoff | Model | C-index | Recall@1% | Recall@5% | Recall@10% |
|---|---|---|---|---|---|
| 2024-01-01 | Cox | 0.857 (0.771–0.922) | 0.258 (0.125–0.363) | 0.577 (0.412–0.713) | 0.660 (0.506–0.792) |
| | EPSS-alone | 0.706 (0.604–0.796) | 0.196 (0.089–0.299) | 0.381 (0.239–0.516) | 0.464 (0.309–0.581) |
| 2024-07-01 | Cox | 0.804 (0.746–0.851) | 0.144 (0.063–0.234) | 0.312 (0.204–0.426) | 0.464 (0.346–0.589) |
| | EPSS-alone | 0.621 (0.546–0.690) | 0.144 (0.061–0.239) | 0.184 (0.091–0.296) | 0.304 (0.174–0.429) |
| **2025-01-01** | Cox | 0.863 (0.804–0.918) | 0.325 (0.227–0.464) | 0.571 (0.439–0.704) | 0.659 (0.548–0.790) |
| | EPSS-alone | 0.764 (0.696–0.827) | 0.222 (0.132–0.331) | 0.405 (0.277–0.527) | 0.492 (0.380–0.606) |
| 2025-07-01 | Cox | 0.858 (0.810–0.905) | 0.117 (0.026–0.195) | 0.466 (0.333–0.602) | 0.641 (0.516–0.787) |
| | EPSS-alone | 0.750 (0.647–0.840) | 0.146 (0.063–0.262) | 0.330 (0.175–0.469) | 0.495 (0.351–0.653) |

Paired Cox − EPSS-alone (**bold** = interval excludes zero):

| Cutoff | ΔC-index | ΔRecall@1% | ΔRecall@5% | ΔRecall@10% |
|---|---|---|---|---|
| 2024-01-01 | **+0.151 (+0.092, +0.227)** | +0.062 (+0.000, +0.128) | **+0.196 (+0.084, +0.345)** | **+0.196 (+0.081, +0.337)** |
| 2024-07-01 | **+0.183 (+0.117, +0.260)** | +0.000 (−0.026, +0.021) | **+0.128 (+0.037, +0.222)** | **+0.160 (+0.071, +0.265)** |
| **2025-01-01** | **+0.099 (+0.055, +0.154)** | **+0.103 (+0.010, +0.203)** | **+0.167 (+0.077, +0.294)** | **+0.167 (+0.068, +0.289)** |
| 2025-07-01 | **+0.107 (+0.050, +0.177)** | −0.029 (−0.138, +0.059) | +0.136 (+0.000, +0.261) | **+0.146 (+0.021, +0.299)** |

### Reading

- **C-index: Cox beats EPSS-alone in every fold**, with intervals excluding
  zero (+0.099 to +0.183). Cox's own C-index stays at 0.80–0.86 throughout.
- **Recall@10%: the same holds in every fold** (+0.146 to +0.196).
- **Recall@5%** excludes zero in three folds. In 2025-07-01 the lower bound
  sits at zero (+0.000), so it does not strictly exclude it.
- **Recall@1% is not consistent.** It is significant only in the
  2025-01-01 fold, and its point estimate is negative in 2025-07-01. This
  matches the headline, where ΔRecall@1% is not significant either. Each
  fold has only 36–50 listed CVEs, so the top 1% (590–740 rows) holds very
  few events.
- **The 2024-07-01 fold is the weakest for both models**: Cox 0.804, EPSS
  0.621. Cox's *advantage* is largest there (+0.183). That window is the
  validation period. *[Corrected 2026-10-23: this originally continued
  "where the residual CVSS-presence gap was largest (`docs/STATUS.md`).
  Nothing here separates that from other differences between periods."
  The premise is false. The pre-2025 gap is −2.76pp (positives *more* often
  missing), smaller than and opposite to test's +6.23pp, and the validation
  period's own gap has not been computed. See `docs/STATUS.md`,
  "Correction: residual CNA-CVSS presence gap".]* Nothing here explains
  the fold's result.
- **Test windows are six months long and hold 97–126 events each**, so
  intervals are wider than the headline's (268 events over ~20 months).
  Fold-to-fold differences are mostly within noise. The point is the sign
  and significance of the Cox − EPSS gap, which is stable.

**Conclusion.** The headline result, Cox ranking above EPSS-alone on
C-index and recall@10%, holds in each of four disjoint six-month windows
under the same frozen recipe. It is not an artifact of the single
2025-01-01 split.
