# Results with corrected test-time encoding

This is the corrected record of every test evaluation. It does not
overwrite the original numbers. The original tables in
`docs/model_comparison.md` and `docs/fuzzy_layer.md` are kept as they
were, marked as computed with the encoding bug, and linked here.

**Nothing was refit, re-tuned or re-featured.** The same frozen models
(`models/`), the same frozen fuzzy design (`models/fuzzy_config.json`),
the same 178,756 test rows, the same seed (20260922) and the same 200
whole-CVE resamples are used, all through `scripts/evaluate/common.py`.
Only the test frame's one-hot encoding changed.

Scripts:

- `python -m scripts.evaluate.corrected_encoding` (models, EPSS,
  post-freeze metrics). It computes both encodings on the same resamples,
  and refuses to run unless the original encoding reproduces each frozen
  model's recorded C-index exactly.
- `python -m scripts.fuzzy.risk_percentile` then
  `python -m scripts.fuzzy.evaluate_fuzzy` (fuzzy layer). Pass
  `--encoding original` to either to reproduce the original numbers.

Raw output: `scratch/results_corrected_encoding.json` and
`scratch/fuzzy_evaluation.json`.

## The bug

`scripts/evaluate/features.py::one_hot(df, cols, align_to=train_cols)`
calls `pd.get_dummies(..., drop_first=True)` on `df` itself, and only then
aligns to the training columns. `drop_first` drops `df`'s own
alphabetically first level. When that level isn't the training frame's
first level, it is a real training column, and every row in it gets
encoded as the training **reference** category.

On test:

| Feature | Training reference | Test's first level | Test rows mis-encoded |
|---|---|---|---|
| `confidentiality_impact` | COMPLETE | HIGH | 56,385 |
| `availability_impact` | COMPLETE | HIGH | 49,146 |
| `epss_model_version_at_asof` | unversioned | v2023.03.01 | 22,967 |
| `cvss_version` | 2.0 | 3.0 | 3,947 |

In all, 84,684 test rows had at least one feature mis-encoded. Their
scores changed for Cox (84,684 rows), RSF (79,414) and XGBoost-AFT
(34,766); the tree models don't split on every affected column.

**What it affected:** every test number from the frozen models, and the
fuzzy layer's test `cox_risk_pct` (84,677 test rows changed).

**What it did not affect:**

- Model fitting: a training frame's own first level *is* the reference.
- The training-period percentile reference: all 268,944 training rows give
  identical scores under both encodings, and the reference was verified,
  not rewritten.
- The fuzzy layer's validation design: its validation `cox_risk_pct`
  came from encoding the full training frame.
- The API, which already used the corrected encoder.

**Fix:** `encode_for_model` (same module) builds dummies with
`drop_first=False` and reindexes to the frozen model's columns. So
categories are dropped relative to the **training** frame's category set,
a training level not present in the scored frame keeps its column, and an
unseen level encodes as all zeros. `encode_against(df, cols, encoding=...)`
switches between `"original"` and `"corrected"`. The old path is kept so
that every original number still reproduces. Regression tests are in
`tests/test_evaluate/test_encoding.py`.

### Why re-running is a correctness fix, not tuning

The models, hyperparameters, features, fuzzy rules and cut-offs are all
unchanged, and none was chosen or altered after seeing the corrected
numbers. Only the arithmetic that turns an unchanged test row into the
model's input changed: it now gives each row the encoding the model was
trained to read. A test row with `cvss_version = 3.0` was previously
handed to the model as `2.0`. The corrected number is the frozen model's
actual performance; the original was a performance on partly mislabelled
inputs.

## Scope: validation was also mis-encoded (limitation, not re-tuned)

The RSF and XGBoost-AFT tuning scripts encoded validation the same way
(`rsf.py`, `xgboost_aft.py`: `one_hot(val_df, align_to=fit_cols)`). On
validation, **`epss_model_version_at_asof` was mis-encoded on all 53,674
rows**. Every validation row carried v2023.03.01, the validation frame's
only level, and was encoded as the `unversioned` reference, a category with
only 2,167 fit rows. No other validation column differed: the other
first-level differences (COMPLETE, 2.0) are validation levels that fit
never saw, which encode as zeros either way. This was checked by comparing
the full validation inputs under both encoders.

| Feature | Fit first | Val first | Train first | Test first |
|---|---|---|---|---|
| `epss_model_version_at_asof` | unversioned | v2023.03.01 | unversioned | v2023.03.01 |
| `confidentiality_impact` | HIGH | COMPLETE | COMPLETE | HIGH |
| `availability_impact` | HIGH | COMPLETE | COMPLETE | HIGH |
| `cvss_version` | 3.0 | 2.0 | 2.0 | 3.0 |
| other 6 categoricals | identical | identical | identical | identical |

- **RSF and XGBoost-AFT** hyperparameters were selected on these
  mis-encoded validation inputs, so the chosen configurations may be
  suboptimal. They were **not re-tuned**: test results are known, and
  re-tuning now would be selection leakage. Nor were the tuning grids
  re-scored on corrected validation. A result that couldn't be acted on
  without leakage isn't worth producing.
- **Cox**, the best-performing and headline model, has **no fit/validation
  tuning step and is unaffected**. `penalizer=0.1` was a fixed value set in
  the first preliminary baseline (`5233885`, an "untuned CoxPHFitter
  (penalizer=0.1)"), four commits before the fit/validation split existed
  (`600b8ac`). No script ever compared penalizer values on validation.
  (`docs/model_comparison.md` previously said it was "chosen on C-index";
  that sentence has been corrected.)
- **The fuzzy layer's design is unaffected**: its validation
  `cox_risk_pct` came from encoding the full training frame.

The code paths have been switched to `encode_for_model` for any future
run, but they were not re-run here: `cox.py`, `rsf.py`, `xgboost_aft.py`,
`final_comparison.py` and `freeze_final_models.py` all refit.

## Corrected results

Same frozen models and resamples under both encodings: original → corrected.

### Main table (95% CI)

| Model | C-index | Recall@1% | Recall@5% | Recall@10% |
|---|---|---|---|---|
| EPSS-alone | 0.750 (0.687–0.804), unchanged | 0.190 | 0.369 | 0.459 |
| **Cox** | 0.849 → **0.850** (0.810–0.887) | 0.224 → **0.231** (0.149–0.298) | 0.485 → **0.496** (0.398–0.591) | 0.623 → **0.631** (0.529–0.718) |
| RSF | 0.812 → **0.812** (0.757–0.854) | 0.284 → **0.287** (0.214–0.366) | 0.489 → **0.504** (0.414–0.578) | 0.575 → **0.582** (0.482–0.667) |
| XGBoost-AFT | 0.785 → **0.785** (0.734–0.825) | 0.250 → **0.231** (0.165–0.315) | 0.425 → **0.425** (0.330–0.504) | 0.511 → **0.504** (0.413–0.592) |

The RSF "original" values here are the frozen model's. They match
`rsf_final_metadata.json` exactly, and differ slightly from the
`final_comparison.py` refit numbers in model_comparison.md's table,
because RSF is not run-to-run reproducible.

### Paired difference vs EPSS-alone (`epss_pct_now`), corrected

| Model | ΔC-index | ΔRecall@1% | ΔRecall@5% | ΔRecall@10% |
|---|---|---|---|---|
| Cox | **+0.100 (0.069, 0.139)** | +0.041 (−0.022, 0.095) | **+0.127 (0.055, 0.184)** | **+0.172 (0.095, 0.236)** |
| RSF | **+0.062 (0.003, 0.124)** | **+0.097 (0.036, 0.157)** | **+0.134 (0.049, 0.231)** | **+0.123 (0.028, 0.234)** |
| XGBoost-AFT | +0.035 (−0.029, 0.105) | +0.041 (−0.043, 0.129) | +0.056 (−0.040, 0.150) | +0.045 (−0.066, 0.161) |

**Bold** means the CI excludes zero. Significance is unchanged from the
original for every cell. **XGBoost-AFT vs EPSS remains non-significant**
on C-index and at every budget. Against raw EPSS it is +0.037
(−0.023, 0.106), also non-significant.

### Per-landmark C-index (point estimates), corrected

| Landmark | EPSS-alone | Cox | RSF | XGBoost-AFT |
|---|---|---|---|---|
| 7 | 0.761 | 0.857 (was 0.857) | 0.813 (0.812) | 0.761 (0.765) |
| 14 | 0.766 | 0.858 (0.857) | 0.815 (0.816) | 0.786 (0.792) |
| 30 | 0.714 | 0.831 (0.830) | 0.805 (0.806) | 0.838 (0.845) |

### Blind-spot catch rate at 10%, corrected

| Model | Catch rate (95% CI) | Original |
|---|---|---|
| Cox | 0.338 (0.210–0.458) | 0.310 |
| RSF | 0.379 (0.253–0.506) | 0.352 |
| XGBoost-AFT | 0.428 (0.297–0.545) | 0.421 |

Paired against Cox: RSF +0.041 (−0.037, 0.134) and XGBoost-AFT +0.090
(−0.032, 0.206). Neither excludes zero.

### Time-dependent AUC (pooled; censoring from train), corrected

| Model | 30d | 90d | 180d | Original (30/90/180) |
|---|---|---|---|---|
| Cox | 0.851 | 0.850 | 0.853 | 0.847 / 0.846 / 0.850 |
| RSF | 0.824 | 0.815 | 0.822 | 0.825 / 0.817 / 0.820 |
| XGBoost-AFT | 0.758 | 0.778 | 0.787 | 0.752 / 0.777 / 0.788 |
| EPSS raw | 0.736 | 0.736 | 0.734 | unchanged |

Paired vs EPSS raw: Cox and RSF exclude zero at every horizon; XGBoost-AFT
does not (30d +0.023, 90d +0.042, 180d +0.053). This is the same pattern
as the original.

Per landmark (30/90/180), corrected:

| | Cox | RSF | XGBoost-AFT | EPSS raw |
|---|---|---|---|---|
| Landmark 7 | 0.876 / 0.869 / 0.861 | 0.824 / 0.818 / 0.822 | 0.752 / 0.745 / 0.767 | 0.787 / 0.766 / 0.749 |
| Landmark 14 | 0.868 / 0.857 / 0.856 | 0.836 / 0.823 / 0.821 | 0.762 / 0.783 / 0.791 | 0.770 / 0.748 / 0.748 |
| Landmark 30 | 0.794 / 0.813 / 0.837 | 0.805 / 0.798 / 0.819 | 0.825 / 0.826 / 0.837 | 0.615 / 0.673 / 0.695 |

At landmark 30, XGBoost-AFT still has the highest AUC at 30 and 90 days,
as originally.

### Cox Brier score and calibration, corrected

| Metric | Original | Corrected |
|---|---|---|
| Integrated Brier (30–180d) | 0.0010362 | 0.0010362 |
| IPA (integrated) | 0.00035 | 0.00038 |
| IPA at 30 / 90 / 180d | 0.00015 / 0.00031 / 0.00049 | 0.00017 / 0.00035 / 0.00054 |

The 90-day calibration is essentially unchanged.

- Predicted P(KEV ≤ 90d) spans 0.078–0.191% (was 0.078–0.184%).
- The top decile is predicted at 0.112% and observed at 0.632%, still
  about 6× too low. It holds 113 of 177 events (was 111).
- Calibration-in-the-large ratio: 0.93 (was 0.92).

Figure: `docs/figures/calibration_90d_corrected_encoding.png`. The
original figure is left as is.

### Fuzzy layer vs references, corrected

The frozen design is unchanged; only test `cox_risk_pct` is corrected.

| Ranking | C-index | Recall@1% | Recall@5% | Recall@10% | Blind-spot @10% |
|---|---|---|---|---|---|
| Fuzzy | 0.842 (0.802–0.876) | 0.213 | 0.448 | 0.534 | 0.207 |
| Cox | 0.850 (0.810–0.887) | 0.231 | 0.496 | 0.631 | 0.338 |
| EPSS | 0.750 | 0.190 | 0.369 | 0.459 | 0 |
| Linear blend | 0.836 (0.787–0.870) | 0.201 | 0.470 | 0.582 | 0.317 |

Paired, fuzzy minus reference:

| vs | ΔC-index | ΔR@1% | ΔR@5% | ΔR@10% | ΔBlind-spot |
|---|---|---|---|---|---|
| Cox | −0.009 (−0.016, +0.000) | −0.019 (−0.051, +0.012) | −0.049 (−0.103, +0.014) | **−0.097 (−0.154, −0.031)** | **−0.131 (−0.229, −0.024)** |
| EPSS | **+0.092 (+0.056, +0.130)** | +0.022 (−0.028, +0.078) | **+0.078 (+0.032, +0.129)** | **+0.075 (+0.022, +0.145)** | +0.207 |
| Linear blend | +0.006 (−0.010, +0.026) | +0.011 (−0.034, +0.061) | −0.022 (−0.098, +0.056) | −0.049 (−0.135, +0.029) | −0.110 (−0.231, +0.000) |

Originally: vs Cox, recall@10% was −0.071 and blind-spot −0.110 (CI
upper +0.0004).

Ties: the top plateau (79.52) now holds 11,886 test rows (6.6%; was
10,750). The top 1% and 5% still contain a single priority value. The
thesis rule R02 fires on 13.4% of test rows (was 7.9%).

**The train-vs-test percentile shift was partly an artifact of the
bug.** Under correct encoding, the test medians of `cox_risk_pct` are
0.38 / 0.34 / 0.32 at landmarks 7/14/30 (originally reported as
0.33 / 0.26 / 0.25 in `18d1548`), and 7.6% of test rows reach ≥ 0.9
(originally 5.5%). Those rows hold 155 of 268 events. The shift is real
but smaller; test is still below the training median of 0.5. Validation
remains the right reference for the cut-offs.

### Not re-run

These require refitting models, so they stay as originally computed, with
the bug, in `docs/model_comparison.md`:

- the XGBoost-AFT and Cox trajectory ablations;
- RSF run-to-run variance.

## Conclusions re-checked

1. **Cox still leads all models.** It is best on C-index (0.850 vs 0.812
   and 0.785), recall@10% and time-dependent AUC at every horizon. RSF
   remains slightly ahead at recall@1% and @5%, and XGBoost-AFT on the
   blind-spot rate and on landmark-30 AUC. That pattern held under the
   original encoding too, and none of those paired differences against Cox
   excludes zero.
2. **The fuzzy layer still fails to beat the linear blend.** No paired
   difference excludes zero.
3. **It still loses to Cox, by more than originally reported.** At
   recall@10% the gap is −9.7pp (CI excludes zero). The blind-spot
   difference (−0.131) now also excludes zero. The decision stands: rank
   by Cox, explain by fuzzy rules.

Neither conclusion flipped.

## Limitations from this correction

- RSF and XGBoost-AFT hyperparameters were selected on validation inputs
  where `epss_model_version_at_asof` was mis-encoded on all 53,674 rows
  (every row carried v2023.03.01 but was encoded as the `unversioned`
  reference). The chosen configurations may therefore be suboptimal. They
  were not re-tuned, because test results are known and re-tuning would
  constitute selection leakage.
- Cox, the best-performing and headline model, has no fit/validation
  tuning step (`penalizer=0.1` was a fixed value, never compared on
  validation), so it is unaffected.
- The fuzzy layer's design is unaffected: its validation `cox_risk_pct`
  came from encoding the full training frame, which was correct.
- The trajectory ablations and the RSF variance study were not re-run,
  because they require refits.
