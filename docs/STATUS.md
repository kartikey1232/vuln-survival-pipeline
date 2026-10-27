# Project status (handoff doc)

Beyond EPSS — predicting time-to-CISA-KEV-inclusion for CVEs using survival
analysis. This document exists so a new session (or a compacted-context
continuation of this one) can pick up work without re-deriving everything
below from scratch. Update it whenever a design decision changes.

## Hypotheses (exact wording)

**H1** (as recorded in the progress report): *"adding EPSS trajectory
features improves discrimination over a model using only the current
EPSS value."*

**Status: rejected — no evidence that trajectory features help.**

- Cox ablation, corrected encoding: (a) full Cox minus (b) Cox without the
  6 trajectory features gives ΔC-index −0.0055, paired 95% CI [−0.0147,
  +0.0049]. The interval spans zero.
- So the trajectory features show **no measurable benefit** (a null
  result), and that is the whole claim.
- Companion finding: full Cox beats Cox-without-any-EPSS at recall@10%
  (+0.075, CI excludes zero). So EPSS's current level carries real signal,
  and its trajectory adds nothing measurable on top.
- Numbers: `docs/final_results.md`.

The rejection does NOT rest on the original-encoding result (an interval
excluding zero in the other direction). That result was an artifact of the
test-encoding bug and is not cited as evidence.

## Pipeline state, end to end

1. **Ingestion** (`scripts/download/`): NVD (full backfill 2021-11-01 →
   2026-09-20, `download_nvd.py`), EPSS (same range, two-phase
   fetch/load design in `download_epss.py` — see its docstring for two
   real concurrency bugs found and fixed there), KEV, ExploitDB, CWE.
2. **Cleaning** (`scripts/clean/`): raw → `canonical.*`. `clean_nvd.py`
   also extracts the real per-weakness CWE `source` (was hardcoded
   `"nvd"` until this session — fixed).
3. **Feature/label build** (`scripts/features/build_landmark_dataset.py`):
   the landmark design (see below) — writes to `features.static_features`,
   `features.temporal_features`, `training.survival_labels`,
   `training.training_dataset` (flat export,
   `dataset_version=landmark_v20260922`), plus a parquet copy.
4. **Evaluation** (`scripts/evaluate/`): shared bootstrap/metrics module
   (`common.py`), fit/val/test splitting (`data_splits.py`), feature prep
   (`features.py`).
5. **Models** (`scripts/models/`): `cox.py`, `rsf.py`, `xgboost_aft.py` —
   each tunes (RSF/XGBoost only) on fit/val, refits on full train,
   evaluates on test.
6. **Docs**: `docs/model_comparison.md` (final numbers),
   `docs/enrichment_leakage.md`, `docs/eda_summary.md`,
   `docs/evaluation_plan.md` (future metric design, not yet implemented),
   `docs/figures/*.png`.

Run any script as `python -m scripts.<path.without.py>` (e.g.
`python -m scripts.features.build_landmark_dataset`). Real Postgres only,
no mocks, no SQLite — see `tests/conftest.py`.

## Key design decisions, with reasons

### Landmark prediction (not single-checkpoint day-30)
Original design: predict at day 30 whether a CVE would later be
KEV-listed. Abandoned after finding **62% of KEV listings happen within
30 days of publication** — a single day-30 checkpoint discards most of
the signal by construction (most events have already happened by the
time day-30 features are computed). Replaced with landmarks at day
**7, 14, 30** (`config.checkpoints.days`): at each landmark, ask "will
this still-unlisted CVE be KEV-listed after this point." A CVE
contributes up to 3 rows (one per landmark it's still eligible for).

### Row existence rules (why a row exists at all)
For CVE × landmark L, `as_of_date = published_date + L`. A row exists
only if ALL of:
1. Not already KEV-listed on/before `as_of_date` (`date_added` null or
   `> as_of_date`).
2. At least one EPSS observation exists on/before `as_of_date`.
3. (TRAIN rows only) `as_of_date` itself precedes the train/test cutoff.
Every row also gets `spans_version_transition` (see below) — flagged,
not dropped; the DEFAULT export filters it out but the flag survives in
`features.temporal_features`/`training.training_dataset` for a future
sensitivity analysis.

### Train/test cutoff: 2025-01-01
TRAIN = published < 2025-01-01, labels censored at 2025-01-01 (a KEV
listing after the cutoff was unknowable at "training time," so it's
censored, not an event). TEST = published >= 2025-01-01, observed
through the real data cutoff 2026-09-20.

### Fit/validation split (for hyperparameter tuning only)
`scripts/evaluate/data_splits.py`: FIT = train CVEs published before
2024-07-01, RELABELED with a 2024-07-01 cutoff (reusing the stored
2025-01-01-cutoff labels here would leak validation-period KEV listings
into fit). VAL = train CVEs published 2024-07-01..2024-12-31, stored
labels reused as-is (their cutoff already equals 2025-01-01 = val's own
cutoff, so no relabeling needed). TEST is untouched by this split. All
hyperparameter choices happen on VAL only; TEST is touched only for the
final, already-chosen-config evaluation.

### Publication-time-only features (the enrichment-leakage fix)
**Finding**: 100% of KEV positives had NVD `vulnStatus=Analyzed` vs.
19-50% of negatives — NVD's own analyst enrichment (CVSS, CWE, CPE/vendor
data) is added preferentially for CVEs NVD prioritizes, which correlates
with eventual KEV status. Using NVD-added fields as features leaks the
label via "has this CVE been reviewed yet," not via any date field (so
the temporal leakage tests still pass — this is a *selection*-leakage
class, not a temporal one).

**Fix, in two rounds**:
1. First pass: CVSS/CWE features restricted to `source != nvd@nist.gov`
   ("CNA-sourced"). `vendor_kev_rate_expanding`/`vendor_count`/
   `product_count` REMOVED entirely from the model-feature allowlist —
   CPE/vendor data is NVD's own enrichment with no CNA-sourced
   alternative, and was the single largest leaky contributor.
2. **Second pass (current rule)**: the `!= nvd@nist.gov` filter still
   admitted CISA's own ADP (Vulnrichment) contributions — confirmed via
   raw payload inspection that source
   `134c704f-9b21-4f2e-91b3-4a467353bcc0` carries
   `ssvcData.role="CISA Coordinator"`. CISA runs KEV, so CISA enriching a
   CVE with its own CVSS/CWE is a direct circularity. **Current rule**:
   accept a CVSS metric or CWE mapping ONLY if its `source` equals the
   CVE's own `sourceIdentifier` (payload-level field — the CNA that
   actually owns/reported the CVE). Implemented in
   `build_landmark_dataset.py::_load_base_cve_table`. This removed ~18%
   of previously-accepted CVSS metrics and ~20% of CWE mappings.
   Enrichment-bias gap (positive vs negative presence) dropped from
   20.9pp → 2.8pp (train) and 6.0pp → stayed ~6.2pp (test) for CVSS
   *[Corrected 2026-10-23: post-fix train is −2.76pp, opposite sign to
   test's +6.23pp; see "Correction: residual CNA-CVSS presence gap"]*;
   `primary_cwe_id` missingness 19.0pp → 5.4pp (train), 9.1pp → 4.5pp
   (test, now under the 5pp flag threshold) *[Corrected 2026-10-23: pre-fix
   figures verified; post-fix CWE train is −5.36pp, opposite sign. CVSS was
   reduced on train but not on test, CWE on both. See "Correction:
   residual CNA-CVSS presence gap"]*.
   `cwe_kev_rate_expanding`/`vendor_kev_rate_expanding` were similarly
   filtered; `cna_kev_rate_expanding` (new) is an expanding-window
   target encoding on the CVE's own `sourceIdentifier`, replacing the
   removed vendor encoding.

**Residual, not fully resolved**: even after the fix, CVSS-presence
still correlates with the label (2.8pp train / 6.2pp test gap). Because
this residual is BIGGER in the older (fit/val) era than in test,
validation-set C-index runs optimistic relative to test — always trust
test numbers. *[Corrected 2026-10-23: the train residual is smaller than
test's, not bigger, and in the opposite direction, so this reasoning does
not hold. See "Correction: residual CNA-CVSS presence gap".]*

### Model-feature allowlist
`scripts/features/build_landmark_dataset.py::MODEL_FEATURE_COLUMNS` is
the single source of truth for what any model may use:
`epss_pct_now, epss_pct_7d_ago, epss_pct_7d_ago_missing,
epss_pct_delta_7d, epss_pct_first, epss_pct_max_to_date,
days_to_first_epss, epss_model_version_at_asof, landmark_day,
cvss_base_score, attack_vector, attack_complexity, privileges_required,
user_interaction, confidentiality_impact, integrity_impact,
availability_impact, cvss_version, cvss_cna_missing,
cwe_kev_rate_expanding, cna_kev_rate_expanding,
exploit_published_by_asof, days_to_first_exploit`.
Non-feature exported columns (never used as model input):
`cve_id, as_of_date, split, event_time, event_observed,
epss_score_at_asof_raw, spans_version_transition`.
`tests/test_leakage/test_landmark_features.py::test_export_column_allowlist_exact`
enforces this exactly, including a banned-columns list (legacy day-30
columns + the removed enrichment-leaking columns) that must never
reappear.

### Bootstrap evaluation
`scripts/evaluate/common.py`. CVE-level (not row-level) resampling with
replacement, 200 resamples for final numbers. Two performance fixes this
session:
- The real bottleneck was never `concordance_index` — it was rebuilding
  a cve_id→row-indices lookup from scratch on EVERY resample (measured
  52.8s for ONE resample on the 178k-row test set). Building it once per
  `evaluate_model*` call fixed it (~0.02s/resample after).
- `fast_concordance_index`: a vectorized Harrell's C, validated to match
  `lifelines.utils.concordance_index` exactly (1e-9) including tie
  handling (reverse-engineered empirically from lifelines' behavior on
  controlled small cases, not assumed — see the function's docstring and
  `tests/test_evaluate/test_fast_concordance.py`).
- `paired_bootstrap_compare`: computes model and baseline metrics on the
  SAME resample (not independent draws) for a properly-paired CI on the
  difference.

## Final model-comparison numbers (test set, post both-round leakage fix)

See `docs/model_comparison.md` for full tables. Headline:

| Model | Test C-index | vs EPSS-alone (paired CI excludes 0?) |
|---|---|---|
| EPSS-alone | 0.750 | — |
| **Cox** (penalizer=0.1) | **0.849** | yes, +0.100 |
| RSF (leaf=50, log2, 200 trees) | 0.812 | yes, +0.063 |
| XGBoost-AFT (extreme, scale=1.2, depth=6) | 0.785 | no |

Cox is currently the strongest model — this only became true after the
second-round (CISA ADP) fix; before it, XGBoost/RSF scored higher because
their tree splits could exploit the enrichment artifact more than Cox's
linear form could. **Open item, per the most recent instruction**: don't
assert *why* Cox wins without direct evidence — the more defensible
explanation offered is "few training events (~440) favor a penalized
linear model over flexible learners," not "Cox can't exploit artifacts,"
unless a specific ablation supports the latter.

Trajectory ablation (XGBoost-AFT, current tuning; original encoding, never
re-run with the corrected encoding): under the original encoding the
(a) − (b) recall@10% interval excluded zero. Its status under the
corrected encoding is unknown. The config was also tuned on mis-encoded
validation inputs, so this is not cited as evidence about trajectory
features. H1's evidence is the corrected Cox ablation (see Hypotheses).
*[Resolved 2026-10-22: re-run with the corrected encoding; see the
robustness addendum below.]*

## Known limitations / open items at handoff

- Cox's stability across the CVSS/CWE fix (0.849 before AND after) has
  NOT yet been independently verified to have used post-fix data — this
  is the next task in progress.
- Cox trajectory ablation not yet run (XGBoost's was; see above).
  *[Resolved: run in 0456e46 and re-run with the corrected encoding in
  f260542; see Hypotheses.]*
- Blind-spot catch rate side-by-side table for all 3 models not yet
  written up in one place (numbers exist in
  `scratch/final_comparison_results.json`).
- No models frozen/saved to `models/` yet with metadata (commit hash,
  cutoff, features, hyperparameters, test metrics) — planned, not done.
- `docs/model_comparison.md`'s explanation of why Cox wins needs the
  wording fix noted above.
- **RSF is not run-to-run reproducible** despite `random_state=0` (both
  its tuning-time config selection AND its test C-index vary run to run
  under `n_jobs=-1` — spread 0.0062 across 3 seeds at a fixed config).
  Treat any single RSF number as approximate. *[Corrected-encoding
  re-run 2026-10-22: spread 0.0106, std 0.0046; see the robustness
  addendum.]*
- `cwe_relationship.relationship_type` CHECK constraint was widened
  (CanPrecede/CanAlsoBe/Requires/StartsWith) but the relationship GRAPH
  itself is not used by any feature — data completeness only.
- `disclosure@vulncheck.com` (a threat-intel vendor acting as CNA) is
  flagged in `docs/model_comparison.md`'s limitations as a CNA whose
  CVSS/CWE contributions might correlate with "already known interesting"
  even though it isn't CISA — small n (46 CVEs), not resolved further.
  *[Tested 2026-10-22: 46 CVEs is train only; on test it is 2,564 CVEs /
  26 events, and excluding them leaves Cox > EPSS intact. See the
  robustness addendum.]*
- No feature-engineering/model work happens on `scripts/labels/`,
  `scripts/export/` — those are still stub packages
  from the original pipeline design; the landmark build script bypassed
  them entirely with its own self-contained logic. (`scripts/epss_reconstruct/`,
  a third stub, was deleted on 2026-10-24 along with the `vsp reconstruct epss`
  command that imported a module it never contained.)
- `docs/evaluation_plan.md` (recall-at-budget as primary metric,
  C-index/time-dependent-AUC as secondary, whole-CVE bootstrap CIs) was
  written as a forward-looking plan before the landmark rebuild; the
  actual evaluation now uses the plan's design (recall@budget primary,
  paired bootstrap CIs) — the plan doc itself hasn't been marked
  "implemented."

## Addendum: Cox stability verification (post-handoff)

Confirmed Cox WAS refit on the post-CISA-fix rebuilt data (not stale):
test C-index 0.8491 (before, source!=nvd@nist.gov filter) vs 0.8492
(after, source=own-CNA filter) — nearly identical but numerically
distinct, `cox_results_fast.json` timestamped 3.5 min after the rebuild's
DB write completed, row count and `cvss_cna_missing` rate (33.66%) match
the current table exactly. Cox's stability is real, not a stale-file
artifact — consistent with Cox being linear and unable to exploit
"CVSS present vs absent" as a strong categorical split the way RSF/
XGBoost's tree structures can.

## Addendum: post-freeze secondary metrics (2026-09-24)

`scripts/evaluate/post_freeze_metrics.py` computes time-dependent AUC
(30/90/180d), plus Brier score, IPA and 90-day calibration for Cox. It
runs on the FROZEN models; nothing is refit. The new metric functions live
in `scripts/evaluate/common.py` and use the same seed and CVE resamples as
C-index and recall. Full results are in `docs/model_comparison.md`'s
"Post-freeze secondary metrics" section.

- Time-dependent AUC agrees with the C-index ranking (Cox ≈0.85 at every
  horizon, significantly above EPSS raw ≈0.735).
- XGBoost-AFT's paired C-index gain over EPSS does NOT exclude zero
  (+0.035, CI −0.027..+0.099). The outstanding item is resolved.
- **New open item: frozen Cox probabilities are badly under-dispersed.**
  - Predicted P(KEV ≤90d) spans only 0.078–0.184% across all test rows,
    and IPA vs the base rate is ≈0.0003.
  - The top decile is under-predicted about 6×, and the bottom deciles
    are over-predicted.
  - Calibration-in-the-large is fine (ratio 0.92).
  - The fuzzy layer must not consume these raw probabilities without
    recalibration (on fit/val only) or a switch to rank-based inputs. That
    decision is still open.

## Addendum: Cox risk percentiles for the fuzzy layer (2026-10-21)

Open item resolved: the fuzzy layer uses rank-based inputs, not
recalibrated probabilities. `scripts/fuzzy/risk_percentile.py` maps frozen
Cox's score to `cox_risk_pct`, its percentile against the TRAINING-period
score distribution of the row's own landmark. It uses the same "same or
lower" definition as EPSS's percentile. Rows are never ranked within test.
The reference is stored in `models/cox_risk_reference.npz`. Per-row
`cox_risk_pct` + `epss_pct_now` for train and test go to
`data/training/cox_risk_pct.parquet` (regenerable).

- Train percentiles are uniform by construction: deciles land at
  0.1/0.5/0.9 for every landmark.
- **Test percentiles sit well below train.** The median `cox_risk_pct` is
  0.33/0.26/0.25 at landmarks 7/14/30, and only 5.5% of test rows reach
  ≥0.9 (10% by construction on train). Those rows hold 137 of 268 test
  events (row-level). `epss_pct_now` drops the same way (test median 0.109
  vs train 0.181). The shift therefore follows the inputs, not the
  mapping. Fuzzy membership breakpoints must be chosen with this in mind
  (on fit/val, not test).

## Addendum: fuzzy ranking layer (2026-10-21)

`scripts/fuzzy/` builds a Mamdani fuzzy layer (scikit-fuzzy) over
`cox_risk_pct`, `epss_pct_now`, CNA CVSS (with its own missing path) and
`blindspot`. It was designed on validation only, frozen in
`models/fuzzy_config.json` (commit `7177bf8`), and then evaluated once on
test. Full write-up: `docs/fuzzy_layer.md`.

- **Ranking result: null against a validation-fitted linear blend of the
  same inputs.** No paired CI excludes zero.
- **Worse than Cox alone at recall@10%** (-7.1pp, CI excludes zero).
  Blind-spot catch rate 0.20 vs 0.31.
- **Better than EPSS alone.**
- The layer's value is interpretability: every rule's firing strength is
  stored per row in `data/training/fuzzy_priority.parquet`.
- Mamdani centroid output wasn't monotone in `cox_risk` with the literal
  brief rules. The rule base was restructured until it passed a dense grid
  check, which `design.py` enforces. As a result the thesis rule R02 is
  explanation-only.
- The top priority plateau holds about 6% of test rows. Ordering at
  budgets of 5% or less is therefore the `cox_risk_pct` tie-break.
- Test has been seen. Any fuzzy redesign needs a fresh validation period.

**Decision (final): the system RANKS by Cox and EXPLAINS by fuzzy rules.**
The fuzzy layer is frozen as shipped and is not to be redesigned against
these test results. The watchlist orders by the frozen Cox partial hazard;
the fuzzy priority and fired rules are attached as the explanation. See
`docs/fuzzy_layer.md` "Conclusion" for the four limitations (Cox in-sample
on validation, the ~6% top-end tie, R02 subsumed by R09, weights left at
1.0).

Candidate changes for any future work, which needs a fresh validation
period:
1. Put EPSS's raw score on the same reference distribution as Cox, so
   `blindspot = 0` means agreement.
2. Break the top-end tie (VeryHigh saturating at the validation 95th
   percentile flattens the top ~6% of test rows).

## Addendum: test-time one-hot encoding bug — corrected (2026-10-21)

`one_hot(df, ..., align_to=train_cols)` dropped `df`'s OWN first category
before aligning. On test this encoded 84,684 rows' category as the
training reference (`confidentiality_impact`/`availability_impact` HIGH,
`epss_model_version_at_asof` v2023.03.01, `cvss_version` 3.0).

All test evaluations were re-run with `encode_for_model`, nothing refit,
same seed and resamples, and published as a new record:
**`docs/results_corrected_encoding.md`**.

- The original tables in `model_comparison.md` and `fuzzy_layer.md` are
  kept and marked.
- The metadata JSONs have `test_metrics_corrected_encoding` added
  alongside the recorded `test_metrics`.
- `encode_against(encoding="original")` still reproduces every original
  number. Regression tests: `tests/test_evaluate/test_encoding.py`.

Corrected headline:

- **Cox still leads**: C-index 0.850 (was 0.849), R@10% 0.631, AUC ≈ 0.85
  at 30/90/180d.
- RSF: 0.812. XGBoost-AFT: 0.785. **XGBoost-AFT vs EPSS is still
  non-significant.**
- **Fuzzy still doesn't beat the linear blend**, and loses to Cox by more:
  recall@10% −9.7pp; blind-spot −0.131, CI now excludes zero.
- The train/test `cox_risk_pct` shift was partly the bug: corrected test
  medians are 0.32–0.38, not 0.25–0.33.
- **Cox trajectory ablation re-run** (refits reduced-feature Cox models
  only; same feature sets, penalizer and seed):
  - Trajectory features show **no measurable benefit** (a null result):
    (a) − (b) ΔC-index −0.0055, CI [−0.0147, +0.0049], which spans zero.
    Under the original encoding the interval excluded zero; that result
    is not cited.
  - The point estimates split by metric. C-index is 0.8501 full vs 0.8556
    trimmed. Recall@10% is 0.631 full vs 0.616 trimmed, so full Cox leads.
    Neither difference is significant, and the trimmed model is not
    superior.
  - Companion finding: full Cox beats Cox-without-any-EPSS at recall@10%
    (+0.075, CI excludes zero). EPSS's current level carries real signal;
    its trajectory adds nothing measurable on top.
- The XGBoost-AFT ablation and RSF variance were not re-run. *[Resolved:
  re-run 2026-10-22, see the robustness addendum.]*

**Limitations:**

- **RSF and XGBoost-AFT hyperparameters were selected on mis-encoded
  validation inputs.** `epss_model_version_at_asof` was mis-encoded on all
  53,674 validation rows: every row carried v2023.03.01 but was encoded as
  the `unversioned` reference. The chosen configurations may be
  suboptimal. They were not re-tuned, because test results are known and
  re-tuning would be selection leakage.
- **Cox has no fit/validation tuning step and is unaffected.**
  `penalizer=0.1` was a fixed value from the untuned preliminary baseline
  (`5233885`), set before the fit/val split existed. A sentence in
  model_comparison.md claiming it was "chosen on C-index" was corrected.
- **The fuzzy design is unaffected**: its validation `cox_risk_pct` came
  from encoding the full training frame, which was correct.

## Addendum: API (2026-10-21)

`api/` is a read-only FastAPI service (`uv run uvicorn api.main:app`),
documented in `api/README.md`. It loads the frozen Cox model, the
percentile reference, the fuzzy config and
`models/cox_serving_preprocessing.json` (train imputation medians, from
`scripts/models/export_serving_preprocessing.py`). It reads Postgres and
never fits.

`/watchlist` ranks by Cox, not fuzzy. Its pool reproduces the
correctly-encoded Cox test C-index exactly (0.850085). Tests are in
`tests/test_api/`, against the real test DB.

## Addendum: robustness pass (2026-10-22)

Sensitivity analyses and recomputations only. No design choice,
hyperparameter or frozen model changed. Full record: **`docs/robustness.md`**;
headline numbers are in `docs/final_results.md` ("Robustness").
Scripts: `scripts/evaluate/{sensitivity,stale_reruns,calibration}.py`.

**Limitations that are now tested, not merely stated:**

- **Version-transition rows** (flagged, dropped from the default export).
  Re-adding the 6,755 test rows (16 events) leaves Cox > EPSS intact. The
  rows are rebuilt from the same build's feature/label tables, and the
  rebuild is checked to reproduce `training_dataset` exactly on the
  unflagged rows.
- **VulnCheck as CNA.** The "46 CVEs" in earlier docs is the training
  population. On test it is 2,564 CVEs / 26 row-level events (~10% of test
  events). Excluding them leaves Cox > EPSS intact.
- **Residual CVSS-presence gap** (2.8pp train / 6.2pp test; *[corrected
  2026-10-23: train −2.76pp, opposite sign to test's +6.23pp]*). Restricting
  test to CNA-CVSS-present rows leaves Cox > EPSS intact (ΔC-index +0.094,
  ΔR@10% +0.178). So CVSS presence does not drive the test result. The
  separate caveat that validation runs optimistic relative to test is
  untested and stands. *[Corrected 2026-10-23: not established, because its
  premise is false. See "Correction: residual CNA-CVSS presence gap".]*
- **Cox under-dispersion / "rank, don't read the probability".**
  Validation-fitted isotonic and Platt maps (IPCW for validation's
  2025-01-01 censoring) were each evaluated once on test.
  - Isotonic (the validation CV rule's pick): IPA −0.42, about 3.2×
    over-prediction.
  - Platt: effectively the identity.
  - **Not shipped (decision by the user).** Choosing between them on test
    would be selection leakage. The API and dashboard keep the raw
    probability with the existing note.
  - Recorded cause: validation → test shift, mixed with Cox being
    in-sample on validation; the data cannot separate the two. The shift
    breaks calibration transfer, not only percentiles.
  - Also found: isotonic ties 121,454 distinct scores into 345 values,
    which would cost 0.014 C-index if ranked by. "Monotone ⇒ ranking
    unchanged" holds only for strictly monotone maps.
- **The two stale original-encoding analyses**, re-run with the corrected
  encoding:
  - RSF seed spread: 0.0106, std 0.0046.
  - XGBoost-AFT trajectory ablation: the C-index is null like Cox's. At
    recall@10% the full model is significantly *worse* than the
    trajectory-free one (−0.060), matching the original-encoding number.
  - H1 stays rejected.

**Still stated, not tested:** validation optimism from the residual
enrichment gap (*[corrected 2026-10-23: not established, premise false]*),
the in-sample-validation issue for Cox (limitation 1), and
the train-tuned RSF/XGBoost configs (limitation 2).

**Dashboard screenshots:** `docs/figures/dashboard_{cve_lookup,watchlist,backtest}.png`
(CVE-2025-24472 for the lookup view).

**New shared-evaluation helpers** (`scripts/evaluate/common.py`):
`evaluate_brier_at_horizon`, and `km_calibration_table(bin_score=...)`.

## Addendum: rolling origin, lead time, budget equivalence (2026-10-22)

No model, hyperparameter or design choice changed.

- **`docs/rolling_origin.md`: a consistency check, not a competing
  result.** Cox is refit under the frozen recipe at cutoffs 2024-01-01,
  2024-07-01, 2025-01-01 and 2025-07-01, each tested on the next 6 months.
  - Cox > EPSS on C-index and recall@10% in every fold.
  - The 2025-01-01 refit reproduces the frozen model exactly.
  - Rows come from an in-memory rebuild of the full grid:
    `build(train_test_cutoff=STUDY_START)`, a new optional parameter with
    the default unchanged.
  - The rebuild is checked against `training_dataset` before use. The two
    target encodings are stored as `NUMERIC(8,6)`, so the rebuild rounds
    them to match.
- **`docs/lead_time.md`: post-hoc and descriptive.** At a 10%
  per-landmark budget, Cox and EPSS almost always flag shared CVEs at the
  same landmark. Cox's lead comes from 19 blind spots it flags, a median
  of 48 days before listing.
- **Budget equivalence** (`final_results.md`): EPSS needs ~2.2× / 2.3× the
  budget to match Cox's recall at 5% / 10%, both CIs excluding 1×. At 1% it
  is 1.7×, with a CI that includes 1×.

## Decision: Cox's advantage is stated as coverage, not earliness (2026-10-22)

**Decision.** The project's claim about Cox vs EPSS-alone is now
**coverage**, not earliness. Cox flags listed CVEs that EPSS never flags.
On CVEs both flag, it does not flag them sooner. Report and deck wording
must not say Cox "warns earlier".

**What it replaces.** The working framing, per the project owner, was that
Cox "warns earlier" than EPSS. That framing was never written into this
repository: a grep of `docs/`, `api/`, `dashboard/` and `scripts/` finds no
such claim. It is recorded here so the report and deck follow this decision.

**Evidence** (`docs/lead_time.md`; numbers in `docs/final_results.md`,
"Lead time"). This is a post-hoc descriptive analysis on the frozen models,
at a 10% per-landmark budget, over the 108 later-listed test CVEs.

- Both models flag 54. In 51 of those they flag at the **same landmark**.
  Cox is earlier for 1 and later for 2.
- Cox flags 19 that EPSS never does, all EPSS blind spots. EPSS flags 2
  that Cox never does. 33 are flagged by neither.
- **Median Cox lead over EPSS is 0 days** (CI 0 to 0), over both the
  either-caught and the both-caught set.
- **Given a model flags a CVE, the lead before listing is the same for
  both:** median 48 days for Cox and 48 for EPSS.
- Cox recovers 19 of 52 blind spots (36.5%, CI 23.8–48.9%), a median 48
  days before listing.

**Reasoning.**

1. **"Earlier" describes timing on the same CVEs, and on those there is no
   timing difference.** 51 of 54 shared catches land on the same landmark,
   and both models' lead given a catch is a median 48 days.
2. **The only positive lead statistic comes from coverage.** The mean
   +16.9 days (CI +4.8 to +32.3) exists only because the convention
   gives a never-caught CVE a lead of 0. The 19 Cox-only catches produce
   the whole mean. Reporting it as "warns 17 days earlier" would present a
   coverage difference as a timing difference.
3. **The design cannot measure fine-grained earliness.** With landmarks at
   days 7, 14 and 30, the only possible timing differences are 0, 7, 16 or
   23 days. Most catches by both models happen at day 7, the first
   landmark, so neither model can be earlier on those CVEs.
4. **The coverage claim is the one the confirmatory metrics already
   support.**
   - The blind-spot catch rate, 0.338 at the pooled 10% budget, was
     defined before test.
   - Recall@10% is +0.172 over EPSS, CI excluding zero.
   - The rolling-origin folds show the recall@10% gap in all four windows.
   The lead-time analysis is consistent with these. It adds the
   description "a median 48 days before listing" for the recovered blind
   spots.

**How to apply.**

- **Say:** "Cox flags KEV-bound CVEs that EPSS misses (19 of 52 EPSS blind
  spots, a median 48 days before listing)", and "EPSS needs ~2.2–2.3× the
  triage budget to match Cox's recall at 5–10%".
- **Don't say:** that Cox warns earlier, or quote the +16.9-day mean as
  lead time.
- **Any future earliness claim needs its own design, specified before test:**
  daily or weekly landmarks, a real-time (rolling) budget, and a timing
  metric conditioned on both models catching the CVE.
- Lead time stays labelled post-hoc and descriptive everywhere it is cited.


## Correction: residual CNA-CVSS presence gap (2026-10-23)

**Decision.** The residual CNA-CVSS presence gap is now reported with the
split, the aggregation level and the direction stated, and with the
recomputed figures. "Validation C-index runs optimistic relative to test"
is no longer supported by this gap. It is recorded as a correction, the
way the encoding defect was: the original claim is kept and marked, not
overwritten.

**Original claim** (`docs/model_comparison.md`, and this file's
leakage-fix section): "positives are less likely to be missing a CVSS score
than negatives, by 2.8pp on train and 6.2pp on test … Because the gap is
larger in the earlier (fit/val) era than in the test era, validation-set
model selection somewhat over-credits this residual signal".

**Recomputed** from `landmark_v20260922`, at landmark-row level, with
`scripts/eda/enrichment_gap.py`. The gap is negatives' `cvss_cna_missing`
rate minus positives', under the own-CNA source rule:

| Split | Rows (positive) | Missing, negatives | Missing, positives | Gap | In words |
|---|---|---|---|---|---|
| Train (pre-2025, fit+val) | 268,944 (441) | 41.24% | 43.99% | **−2.76pp** | positives *more* often missing |
| Test | 178,756 (268) | 22.27% | 16.04% | **+6.23pp** | positives *less* often missing |

At CVE level (one row per CVE, positive if ever listed) the figures are
−0.82pp train and +8.70pp test. The recorded figures match the row-level
computation, so row level is the level the original numbers were
computed at.

**What was wrong:**

1. **Direction on train.** On train, positives are *more* likely to be
   missing a CNA-CVSS score, not less. The test direction was right.
2. **"Larger in the earlier era."** |−2.76| < 6.23. Even the original
   unsigned 2.8 vs 6.2 contradicted this.
3. **No aggregation level.** Row-level and CVE-level gaps differ (test
   +6.23 vs +8.70pp), so the level has to be stated.

**Reasoning.**

- The validation-optimism caveat rested on the train gap being the larger
  one, in the same direction as test. It is neither, so that argument
  falls. This does not show that validation is *pessimistic* either. The
  validation period's own gap has not been computed, and "train" here also
  includes the fit period. Validation optimism is now **unestablished**,
  not refuted. Test numbers remain the ones to report.
- `docs/robustness.md` §1c already showed that restricting test to rows
  with a CNA CVSS score leaves Cox > EPSS intact (ΔC +0.094, ΔR@10%
  +0.178). That result does not depend on the train figure and stands.
- **Pre-fix figures, verified 2026-10-23** (read-only, landmark-row
  level, `python -m scripts.eda.enrichment_gap --rules`, after the NVD
  refresh's `clean_nvd`). The script asserts that its own-CNA rule
  reproduces the stored `cvss_cna_missing` exactly. "Pre-fix" means the
  first-pass `source != nvd@nist.gov` rule (commit `3b4d6ec`). Gap =
  negatives' missing rate minus positives':

  | Feature | Split | Pre-fix (`!= nvd`) | Post-fix (own CNA) | Recorded as |
  |---|---|---|---|---|
  | CNA-CVSS | Train | **+20.93pp**: positives *less* often missing (0.0% vs 20.9%) | **−2.76pp**: positives *more* often missing | 20.9 → 2.8 |
  | CNA-CVSS | Test | **+5.96pp**: positives *less* often missing (0.0% vs 6.0%) | **+6.23pp**: positives *less* often missing | 6.0 → ~6.2 |
  | `primary_cwe_id` | Train | **+18.98pp**: positives *less* often missing (7.5% vs 26.5%) | **−5.36pp**: positives *more* often missing (50.1% vs 44.8%) | 19.0 → 5.4 |
  | `primary_cwe_id` | Test | **+9.07pp**: positives *less* often missing (1.9% vs 10.9%) | **+4.50pp**: positives *less* often missing (20.9% vs 25.4%) | 9.1 → 4.5 |

  All four pre-fix magnitudes match the record, and all four are
  positive. **The CWE train post-fix figure had the same sign error as
  CVSS train**: it is −5.36pp, not +5.4pp.

  Under the first-pass rule, *no* positive lacked a CVSS score on either
  split. That is consistent with CISA's ADP scoring KEV-listed CVEs (the
  circularity the own-CNA rule removed).
- **The mitigation's effect differs by split and by feature:**
  - **CNA-CVSS, train: reduced in magnitude** (20.93 → 2.76pp) **and
    reversed in direction.** It overshot rather than closing the gap.
  - **CNA-CVSS, test: not reduced** (5.96 → 6.23pp, +0.27pp, same
    direction).
  - **`primary_cwe_id`, train: reduced in magnitude** (18.98 → 5.36pp)
    **and reversed in direction.**
  - **`primary_cwe_id`, test: reduced** (9.07 → 4.50pp, same direction).

  So "reduced on train, not on test" is right for CVSS but **wrong for
  CWE**, which was reduced on both. On train, for both features, the rule
  traded a large gap favouring positives for a smaller one in the
  opposite direction.
- **For reference only, the unfiltered (any-source) rule:** CVSS +1.69pp
  train, +2.22pp test; CWE +2.49pp train, +6.40pp test. These are smaller
  because almost every CVE has *some* score once NVD's own values count.
  This was never a feature rule after the leakage finding.
- The `vulnStatus` split does not depend on the CVSS source rule, so it
  is the same before and after the fix. Analyzed: 100% of positives on
  both splits, against 19.2% of negatives on train and 50.0% on test
  (vulnStatus as of the 2026-09-20 fetch).

**Corrected in place, with the original wording kept as superseded:**
`docs/model_comparison.md` (leakage-fix bullet), `docs/final_results.md`
(Limitations item 11), `docs/robustness.md` §1c (twice),
`docs/rolling_origin.md` (2024-07-01 fold note), and this file (leakage-fix
section twice, robustness addendum twice).

**Consequence for the validation-optimism claim.** Every statement that
validation over-credits residual enrichment signal relative to test rested
on the train gap being larger than test's and in the same direction. Both
are false, so each such statement is now marked **not established**. The
files are `docs/model_comparison.md`, `docs/final_results.md` (item 11),
`docs/robustness.md` §1c, `docs/rolling_origin.md`, and this file (lines
in the leakage-fix section and the robustness addendum). Two kinds of
validation-vs-test difference do not depend on this premise and are
unchanged:

- **Cox is in-sample on validation** (final_results limitation 1,
  `docs/fuzzy_layer.md`). Validation metrics fitted on Cox, such as the
  blend weights, stay optimistic for that reason.
- **XGBoost-AFT's validation-to-test drop** (selected-config validation
  C-index 0.913 in `scratch/xgboost_aft_tuning.csv`, test 0.785) is
  attributed to overfitting of a flexible model selected on validation.
  That attribution has not been separately tested, and the mis-encoded
  validation inputs (limitation 2) may contribute. It never depended on
  the enrichment gap.

**What the model can read** (verified 2026-10-23 against
`MODEL_FEATURE_COLUMNS`, `_load_base_cve_table`, `build()` and
`scripts/evaluate/features.py`):

- **`vulnStatus` is not readable, directly or by derivation.**
  `_load_base_cve_table` reads only `cve_id, published_date, cvss_missing`
  from `canonical.cve`. No feature-build, evaluation, model or fuzzy code
  reads `vuln_status`; outside cleaning and tests it appears only in the
  API's CVE display (`api/db.py`, `api/schemas.py`), never in a score.
  Row existence (`generate_candidate_grid`) does not filter on it.
  `test_export_column_allowlist_exact` bans `vulnStatus`/`vuln_status` by
  name, but a name ban cannot catch a derived column. The code trace above
  is what rules derivation out.
- **Features that do encode enrichment presence:**
  - `cvss_cna_missing`: an explicit CNA-CVSS presence flag.
  - The CVSS component columns (`cvss_version`, `attack_vector`, …,
    `availability_impact`) take the category `"missing"` when there is no
    CNA CVSS (`features.py::prepare_raw`), and `cvss_base_score` is
    median-imputed. They encode the same presence redundantly.
  - `cwe_kev_rate_expanding` has **no explicit CWE-presence flag**. A row
    with no own-CNA CWE gets the global expanding rate (the `no_cat` branch
    of `encode`), so CWE absence is implicitly encoded as that value.
- **Not enrichment presence:** `cna_kev_rate_expanding` is keyed on
  `sourceIdentifier`, which every CVE has.
- **Indirect channel, time-correct:** the EPSS features. EPSS's own model
  takes NVD-derived inputs, so EPSS as of a landmark reflects NVD
  enrichment as it stood on that date. It is as-of data, not a later
  fetch, but it is a route by which NVD's prioritisation can reach the
  model.
- **Timing caveat:** CNA CVSS/CWE come from each CVE's latest staged
  payload (the 2026-09-20 fetch) and are static across landmarks. A metric
  a CNA added after publication is therefore visible at every landmark.
  `cvss_cna_missing` is "CNA-sourced as of fetch", not strictly
  "present at publication".

## Finding: the residual test CNA-CVSS gap, conditioned on CNA (2026-10-23)

**Question.** Is the test gap (+6.23pp, positives less often missing a
CNA-CVSS score) hindsight bias, or is it CNA composition? The alternative:
large CNAs that reliably supply CVSS scores also account for a
disproportionate share of exploited CVEs. That would produce a presence
gap without any hindsight. This is for interpretation and report wording
only. **No feature or model was changed, and none is to be changed on
this basis.**

**Method.** `python -m scripts.eda.enrichment_gap --by-cna`, read-only, on
the stored test rows. CNA is the CVE's `sourceIdentifier`. Gaps are at
landmark-row level (negatives' missing rate minus positives', so + means
positives are less often missing). "Conditioned on CNA" is the
Mantel-Haenszel risk difference across CNAs. Intervals are 2.5–97.5
percentiles over 200 whole-CVE resamples (seed 20260922). This is a
descriptive check, not a model evaluation, so it does not go through
`common.py`.

**CNA composition (CVE level).** The 108 positive CVEs come from 35 of 381
CNAs. Compared with negatives, positives are over-represented at
`cve@mitre.org` (23.1% of positives vs 9.7% of negatives),
`disclosure@vulncheck.com` (10.2% vs 4.2%), Microsoft (5.6% vs 2.4%), Cisco
(5.6% vs 0.6%) and Fortinet (2.8% vs 0.4%). Patchstack, VulDB and
Wordfence (volume ranks 1, 2 and 6) hold 32.5% of negatives and no
positives. The ten largest CNAs by volume hold 55.6% of positive CVEs
against 70.8% of negative CVEs. At most CNAs, CNA-CVSS presence is close
to all-or-nothing: Microsoft, Cisco, Fortinet and GitHub ≈ 0% missing,
Apple 100%. The main exceptions are MITRE (85.9% missing) and
`416baaa9-…` (71.9%).

| Estimate (test) | Gap | 95% interval |
|---|---|---|
| Crude, all rows | +6.23pp | [−2.24, +13.14] |
| Crude, top-5 / top-10 / top-20 CNAs by volume | +2.34 / −0.67 / +3.04pp | all span zero |
| **Conditioned on CNA, all rows** | **+12.52pp** | [+6.74, +20.47] |
| Crude, excluding `cve@mitre.org` | +7.14pp | [+0.25, +12.63] |
| **Conditioned on CNA, excluding `cve@mitre.org`** | **+1.43pp** | [+0.22, +4.08] |
| Within `cve@mitre.org` only (25 positive CVEs) | +46.20pp | [+24.5, +64.9] |

**Result: the gap neither simply shrinks nor simply persists. It
separates into two parts.**

1. **Outside MITRE, CNA composition explains most of the gap.**
   Conditioning on CNA takes it from +7.14 to +1.43pp. That is roughly
   80% of the gap, and it is the vendor-composition mechanism proposed.
   The remainder is small but its interval excludes zero.
2. **Within MITRE-assigned CVEs there is a large gap that composition
   cannot explain.** 16 of 25 positive MITRE CVEs have a CNA-CVSS score,
   against about 14% of negative MITRE CVEs (row level: 40% vs 86%
   missing). MITRE contributes 11.4 of the 12.5pp conditioned gap. That is
   why conditioning on CNA *raises* the overall figure. Positives are
   over-represented at MITRE, where missingness is high, and that pulled
   the crude gap down, so the crude gap understated the within-CNA
   difference.
3. **The crude test gap is not distinguishable from zero.** Its interval
   is [−2.24, +13.14]. The +6.23pp point estimate should not be reported
   as if it were a precisely measured bias.

**Reasoning.**

- The proposed reading ("if it largely disappears once CNA is conditioned
  on, it is ex-ante signal and the own-CNA rule did its job on test")
  holds **for CVEs not assigned by MITRE**. There, the gap is mostly which
  CNA reported the CVE. That is publication-time information, and it is
  already a feature (`cna_kev_rate_expanding`).
- **It does not hold for MITRE-assigned CVEs**, and those carry most of the
  conditioned gap. This stays recorded as **unexplained residual bias,
  localised to `cve@mitre.org`**. Both readings are open:
  - *Hindsight:* a CVSS score added to the MITRE record after the CVE
    became notable. This project uses each CVE's latest payload, not its
    payload at the landmark (the timing caveat above).
  - *Ex-ante:* reports detailed enough to carry a score at assignment are
    also the ones that get exploited.
  The two are distinguishable only by *when* each score first appeared,
  which the stored latest payloads cannot show. Testing that would need
  CVE record history, for example the CVE Program's record versions.
- n is small: 25 positive CVEs within MITRE, 83 outside it. Both intervals
  are wide.
- **Consequence for report wording:** describe the residual test gap as
  "mostly CNA composition outside MITRE-assigned CVEs, with an unexplained
  within-CNA gap among MITRE-assigned CVEs". Do not call it "hindsight
  leakage", and do not call it "resolved". `docs/robustness.md` §1c (Cox >
  EPSS on CNA-CVSS-present rows) is unaffected: there, CVSS presence is
  constant, so neither component can drive that result.

## Finding: when MITRE-assigned CVEs' CNA CVSS scores appeared (2026-10-23)

**Question.** The conditioned test gap is concentrated in `cve@mitre.org`
(previous entry). Were those CNA CVSS scores there at publication
(ex-ante), or added later, for example after the KEV listing (hindsight)?
The stored features use each CVE's *latest* NVD payload, so they can't
answer this. This is for interpretation and report wording only. **No
feature, model or stored value was changed.**

**Method.** Each CVE's record history in the CVE Program's `cvelistV5`
repository, read through the GitHub API (`gh api`; commit list for the
record's file, then the file at each commit), without cloning. For each
version the script records whether the **CNA container** carries a CVSS
metric (`cvssV2_0/3_0/3_1/4_0`), and separately whether an ADP container
does. The sample is all 25 MITRE-assigned test positives, plus 25 MITRE
test negatives that carry a CNA CVSS in NVD, drawn at random (seed
20260922) from 814. Every record was retrieved: no rate limiting, no
missing histories. All 50 first versions are `PUBLISHED` with assigner
`mitre`. Commit time is when a change reached the public list, and the
timing classes are relative to the NVD publication date. Scripts and raw
responses were kept outside the repository (a session scratchpad); the
tables below are the record.

**Result: the scores were present at publication. This is ex-ante signal,
not hindsight.**

- **Positives with a CNA CVSS (16):** 15 had it on the publication day,
  11 of them in the first published version and 4 in a same-day revision.
  **15 of 16 appeared before the KEV listing.** The exception is
  CVE-2025-27920: its CNA CVSS first appeared on 2025-05-19, its day-14
  date, which is also the day it was KEV-listed. KEV's `dateAdded` has no
  time, so the order within that day cannot be determined. Its only stored
  row is day 7, where it is marked as having a score it did not yet have.
  That is one row of hindsight. Treating that row as missing would move
  the within-MITRE gap from about 46.2 to about 44.7pp. **Known defect,
  deliberately not corrected** (decision 2026-10-23). Correcting one row
  found by inspection, when thousands were never examined, would leave a
  non-uniformly corrected dataset, which is harder to reason about than a
  uniformly imperfect one. Any correction would be systematic and recorded
  as its own re-evaluation (see "as-of audit" below), not a patch.
- **Positives without a CNA CVSS (9):** none ever had one in the CNA
  container. All 9 received a **CISA-ADP** CVSS within days of
  publication. The own-CNA rule correctly excludes those. Under the
  first-pass `!= nvd@nist.gov` rule, they would have counted as scored.
- **Negatives with a CNA CVSS (25):** 24 had it at publication. One
  (CVE-2025-59033) gained it on day 39, so its stored day-7/14/30 rows show
  a score that came later. That is hindsight in the other direction, and
  it *shrinks* the gap.
- **No systematic post-KEV appearance.** 0 of 16 appeared after KEV
  listing, and 1 is the same day. There is no evidence of a third
  hindsight mechanism in MITRE-assigned records.

**Reasoning.**

- The within-MITRE gap is a publication-time difference. MITRE-assigned
  CVEs whose records carry a CNA CVSS at publication are KEV-listed more
  often than those without one. That is information available at
  publication, so the own-CNA rule did its job on test for these records.
  Combined with the previous entry (outside MITRE, the gap is mostly CNA
  composition), **the residual test CNA-CVSS gap is best described as
  ex-ante signal, not leakage.** The two hindsight cases found (one
  positive row, three negative rows) are individual timing errors from
  using the latest payload. They run in opposite directions and don't
  explain the gap.
- **The timing caveat in "What the model can read" still stands in
  general.** The stored features are "as of fetch". This check covered
  MITRE-assigned CVEs only, and it found late additions in 2 of 41 scored
  CVEs (1 of 16 positives, 1 of 25 negatives).
- **Report wording:** "the residual presence gap reflects which CVEs carry
  a score at publication (CNA composition, and within MITRE-assigned
  CVEs, whether the record was published with a score). A history check
  of MITRE-assigned records found no systematic post-listing additions."
  Don't call it leakage. The sample is small (25 + 25), so don't claim a
  rate more precise than that.


**Positives (all 25)**

| CVE | Published | CNA CVSS in NVD now | First CNA CVSS in record | When | KEV listed | vs KEV | CISA-ADP CVSS first |
|---|---|---|---|---|---|---|---|
| CVE-2023-52163 | 2025-02-03 | no | - | never | 2025-12-22 | - | 2025-02-05 |
| CVE-2024-48248 | 2025-03-04 | yes | 2025-03-04 | at publication (same-day revision) | 2025-03-19 | before KEV | - |
| CVE-2024-50603 | 2025-01-08 | yes | 2025-01-08 | at publication | 2025-01-16 | before KEV | - |
| CVE-2024-57726 | 2025-01-15 | no | - | never | 2026-04-24 | - | 2025-01-31 |
| CVE-2024-57727 | 2025-01-15 | no | - | never | 2025-02-13 | - | 2025-01-31 |
| CVE-2024-57728 | 2025-01-15 | no | - | never | 2026-04-24 | - | 2025-01-31 |
| CVE-2024-57968 | 2025-02-03 | yes | 2025-02-03 | at publication (same-day revision) | 2025-03-10 | before KEV | - |
| CVE-2024-58136 | 2025-04-10 | yes | 2025-04-10 | at publication | 2025-05-02 | before KEV | - |
| CVE-2025-25181 | 2025-02-03 | yes | 2025-02-03 | at publication (same-day revision) | 2025-03-10 | before KEV | 2025-02-04 |
| CVE-2025-27920 | 2025-05-05 | yes | 2025-05-19 | by day 30 | 2025-05-19 | same day as KEV | 2025-05-05 |
| CVE-2025-29635 | 2025-03-25 | no | - | never | 2026-04-24 | - | 2025-03-25 |
| CVE-2025-32463 | 2025-06-30 | yes | 2025-06-30 | at publication | 2025-09-29 | before KEV | - |
| CVE-2025-32975 | 2025-06-24 | no | - | never | 2026-04-20 | - | 2025-06-24 |
| CVE-2025-47813 | 2025-07-10 | yes | 2025-07-10 | at publication | 2026-03-16 | before KEV | - |
| CVE-2025-47827 | 2025-06-05 | no | - | never | 2025-10-14 | - | 2025-06-10 |
| CVE-2025-48700 | 2025-06-23 | no | - | never | 2026-04-20 | - | 2025-06-24 |
| CVE-2025-48703 | 2025-09-19 | yes | 2025-09-19 | at publication | 2025-11-04 | before KEV | - |
| CVE-2025-48927 | 2025-05-28 | yes | 2025-05-28 | at publication | 2025-07-01 | before KEV | - |
| CVE-2025-48928 | 2025-05-28 | yes | 2025-05-28 | at publication (same-day revision) | 2025-07-01 | before KEV | - |
| CVE-2025-49113 | 2025-06-02 | yes | 2025-06-02 | at publication | 2026-02-20 | before KEV | - |
| CVE-2025-54313 | 2025-07-19 | yes | 2025-07-19 | at publication | 2026-01-22 | before KEV | - |
| CVE-2025-59689 | 2025-09-19 | yes | 2025-09-19 | at publication | 2025-09-29 | before KEV | - |
| CVE-2025-66376 | 2026-01-05 | yes | 2026-01-05 | at publication | 2026-03-18 | before KEV | - |
| CVE-2025-68461 | 2025-12-18 | yes | 2025-12-18 | at publication | 2026-02-20 | before KEV | - |
| CVE-2025-68645 | 2025-12-22 | no | - | never | 2026-01-22 | - | 2025-12-22 |

**Negatives with a CNA CVSS (25 of 814, seed 20260922)**

| CVE | Published | First CNA CVSS in record | When |
|---|---|---|---|
| CVE-2025-53393 | 2025-06-28 | 2025-06-28 | at publication |
| CVE-2024-57261 | 2025-02-19 | 2025-02-19 | at publication |
| CVE-2025-52132 | 2025-08-03 | 2025-08-03 | at publication |
| CVE-2025-26168 | 2025-05-07 | 2025-05-07 | at publication |
| CVE-2025-68936 | 2025-12-25 | 2025-12-25 | at publication |
| CVE-2025-46416 | 2025-06-27 | 2025-06-27 | at publication |
| CVE-2025-59033 | 2025-09-08 | 2025-10-17 | later (day 39) |
| CVE-2025-59820 | 2025-11-26 | 2025-11-26 | at publication |
| CVE-2025-59714 | 2025-09-19 | 2025-09-19 | at publication |
| CVE-2025-62646 | 2025-10-17 | 2025-10-17 | at publication (same-day revision) |
| CVE-2025-27813 | 2025-04-10 | 2025-04-10 | at publication (same-day revision) |
| CVE-2024-56429 | 2025-05-21 | 2025-05-21 | at publication |
| CVE-2025-63531 | 2025-12-01 | 2025-12-01 | at publication |
| CVE-2025-48701 | 2025-05-23 | 2025-05-23 | at publication |
| CVE-2024-58133 | 2025-04-06 | 2025-04-06 | at publication (same-day revision) |
| CVE-2024-39327 | 2025-02-18 | 2025-02-18 | at publication |
| CVE-2025-32413 | 2025-04-08 | 2025-04-08 | at publication |
| CVE-2025-30234 | 2025-03-19 | 2025-03-19 | at publication (same-day revision) |
| CVE-2025-49090 | 2025-10-02 | 2025-10-02 | at publication |
| CVE-2025-62643 | 2025-10-17 | 2025-10-17 | at publication |
| CVE-2024-58128 | 2025-03-28 | 2025-03-28 | at publication (same-day revision) |
| CVE-2025-47824 | 2025-06-27 | 2025-06-27 | at publication |
| CVE-2023-50786 | 2025-07-05 | 2025-07-05 | at publication |
| CVE-2023-53160 | 2025-07-28 | 2025-07-28 | at publication |
| CVE-2025-27364 | 2025-02-24 | 2025-02-24 | at publication (same-day revision) |

## Fix: KEV refresh check is now split-aware (2026-10-23)

`refresh.py::step_kev` flagged new listings as "affecting stored labels"
using one date filter (≤ 2026-09-20) for every CVE. Train rows observe
their label only until 2025-01-01 (`compute_labels`), so a 2026 listing
of a train CVE cannot change a stored train label. The check listed 8
CVEs. Two were train CVEs (CVE-2022-0995, CVE-2023-49105), so only **6
test CVEs / 18 rows** actually change.

- New pure function `label_affecting_listings(new, stored)`. It applies
  each CVE's own split cutoff (`TRAIN_TEST_CUTOFF` for train,
  `DATA_CUTOFF` for test) and returns the affecting and non-affecting
  listings, each with split, label cutoff and stored row count. The
  completion record now also carries `stored_rows_with_changed_labels`
  and `new_entries_with_rows_not_affecting_labels`. Tests are in
  `tests/test_download/test_refresh.py`.
- **The stored completion record was corrected in place.**
  `data/raw/kev/refresh/refresh_kev.json` now lists the 6 CVEs (18 rows),
  moves the 2 train CVEs to the non-affecting list, and keeps the
  original 8-entry list under `correction.original_…` with the reason and
  time. Its `staging.file_manifest` row was re-upserted with the new
  sha256 and size. Its `fetched_at` (the original completion time),
  status, snapshot_date (2026-10-21) and row_count are unchanged.
- No stored label was changed. Relabelling the 18 rows is a separate
  decision.
- **Consequence for the test suite.**
  `test_default_build_reproduces_stored_test_rows_exactly` now fails with
  "event_time: 18 of 178756 rows differ". It was confirmed that these are
  exactly the 18 rows of the 6 CVEs, censored in storage and an event in a
  fresh build. The guard is doing its job: `build()` now reads the
  2026-10-21 KEV catalog. It will keep failing until the stored labels are
  either updated or the guard is pinned to the catalog the stored table
  was built from. That is part of the same decision.
  *Update 2026-10-24:* the test was restructured instead of pinned (see
  "Corrected-labels re-evaluation" below), and the stored labels are
  unchanged.

## Defect: fuzzy priority is not monotone in EPSS (2026-10-23)

**Decision.** This is recorded as a defect of the shipped fuzzy design.
It is **not fixed** now. The fix belongs to the fuzzy redesign, run as a
registered experiment under `docs/holdout_protocol.md`. Details and
tables: `docs/fuzzy_layer.md`, "Monotonicity defect".

- **What was claimed vs checked.** The design was described as monotone.
  Its check (`worst_cox_monotonicity_step`, enforced by `design.py`)
  varied only `cox_risk`.
- **What a per-input sweep shows** (`scripts/eda/fuzzy_monotonicity.py`,
  frozen config). Priority is monotone in `cox_risk`, CVSS and blindspot
  (free mode), and **non-monotone in EPSS** on 30 of 35 shipped-mode grid
  lines. There are three mechanisms:
  1. R13 ("epss High → Medium"): drops of up to 9.9 points as EPSS
     enters High.
  2. The R04 → R11 (and R12 → R10) crossover between EPSS High and
     VeryHigh: up to 3.1 points. This is the adjacent-level max(fading,
     rising) defect that was fixed for `cox_risk` but never for EPSS.
  3. R03 fading as EPSS rises, because blindspot = cox − epss: up to 7.3
     points with Critical CVSS at mid `cox_risk`.
- **Why it matters.** The fuzzy layer is the explanation shown in the
  dashboard and API, not the ranking (the ranking is Cox). The defect
  is already built into the reported fuzzy-layer metrics, which were
  computed with this design, and Cox's numbers are unaffected. It does mean
  a CVE's shown priority can fall when its EPSS rises, which an explanation layer
  shouldn't do. The redesign's acceptance check must sweep every input.

## Finding: as-of error rate of `cvss_cna_missing` (2026-10-23)

**Question.** `cvss_cna_missing` is computed from each CVE's latest NVD
payload, not as of the landmark. How often is the stored value wrong for
the landmark date, and is it wrong more often for positives? A higher
rate among positives would mean scores arrive late for CVEs that turn out
to be exploited. That would be a timing-based leak that the source-based
rule doesn't catch. This is for interpretation only. **Nothing was
changed**, and CVE-2025-27920 stays uncorrected (see the MITRE entry).

**Method.**
- **Sample:** all 108 distinct test positives, plus 200 test negatives
  with a stored CNA CVSS (random, seed 20260922, from 47,110). That is
  854 landmark rows.
- **Record history:** cvelistV5 history for each CVE via the GitHub API,
  as in the MITRE entry. All 308 histories were retrieved, with no errors
  or rate limiting.
- **As-of truth:** for each stored landmark row, whether the record's CNA
  container carried a CVSS in the latest version committed on or before
  the row's `as_of_date` (UTC date). Using strictly-before instead gives
  identical results.
- **Error:** the stored value disagrees with the as-of truth.
- **Scope:** for negatives, only rows stored as *present* were sampled, so
  only that error type can be measured for them. The comparable figure is
  the rate among stored-present rows in both groups. All 43 positive rows
  stored as missing were correct.

**Rates (stored-present rows):**

| | Positives | Negatives | Difference |
|---|---|---|---|
| All CNAs: rows | **7 / 225 = 3.1%** [0.0, 7.2] | **60 / 586 = 10.2%** [6.1, 14.4] | −7.1pp [−12.5, −1.0] |
| All CNAs: CVEs with any wrong row | 3 / 93 | 20 / 200 | Fisher p = 0.06 |
| Excluding kernel.org and Patchstack: rows | 4 / 222 = 1.8% | **0 / 480 = 0%** | |
| Excluding kernel.org and Patchstack: CVEs | 2 / 92 | 0 / 163 | Fisher p = 0.13 |

Intervals are 2.5–97.5 percentiles over 2,000 whole-CVE resamples (seed
20260922).

**Result.**

1. **Overall, the error rate is *higher among negatives*, not positives.**
   That is the opposite of the leak direction.
2. **Nearly all errors come from two CNA-wide bulk backfills, unrelated to
   exploitation:**
   - **kernel.org** (`416baaa9-…`) added CVSS to its existing records on
     2026-07-30 / 2026-08-04. All 24 sampled kernel rows are wrong, and so
     is one kernel positive (CVE-2025-38352).
   - **Patchstack** did the same around 2026-04-23 to 04-29. 36 of 82
     sampled rows are wrong.

   Both happened after the frozen test's landmarks, so a score that didn't
   exist at the landmark appears in the stored features. Patchstack has no
   positives. These errors make negatives look *more* often scored, so as
   of the landmark the true gap is somewhat *larger* than the stored one.
3. **Outside those two CNAs, the only errors are two positives (four
   rows):**
   - **CVE-2025-27920** (MITRE): score first appeared on its KEV listing
     day (already known).
   - **CVE-2025-67038** (ICS-CERT): score first appeared on 2026-09-04,
     **73 days after its KEV listing** (2026-06-23).

   Both scores appeared on or after the listing. The sampled negatives
   outside those CNAs had no errors (0 of 163 CVEs). The difference is not
   statistically distinguishable (2/92 vs 0/163 CVEs, p = 0.13).

**Reasoning.**
- **There is no evidence that scores systematically arrive late for CVEs
  that become exploited.** The dominant as-of error is CNA batch
  backfilling. It is uniform within a CNA, it hits negatives more (because
  of which CNAs backfilled), and it biases the measured gap *down*, not up.
  That is a data-quality limitation, not leakage.
- **A post-listing score addition does exist as a mechanism**, with two
  observed instances: CVE-2025-27920 on the same day, CVE-2025-67038 after.
  It is recorded as a **possible third hindsight mechanism, too rare in
  this sample to measure** (2 of 92 non-backfill positives with a stored
  score). It is not established as a systematic leak. A larger audit, or
  as-of features built from record history, would be needed to bound it.
- **A systematic correction is not warranted on this evidence.** The
  errors are concentrated, explainable and mostly in the conservative
  direction. If one is ever made, it would rebuild `cvss_cna_missing` (and
  the CVSS columns) as of each landmark from record history for *all*
  rows, as its own recorded re-evaluation. It would not patch the rows
  found here.
- **Report wording:** "`cvss_cna_missing` reflects the score as of the
  2026-09-20 fetch. A record-history audit (308 CVEs, 854 rows) found it
  wrong for the landmark date on 3.1% of positive and 10.2% of negative
  rows. The errors were mainly two CNAs' bulk backfills, and two positives
  received a score on or after KEV listing."

<details><summary>Test positives (all 108)</summary>

| CVE | CNA | Stored CNA CVSS | Day 7 | Day 14 | Day 30 | First CNA CVSS in record | KEV listed |
|---|---|---|---|---|---|---|---|
| CVE-2025-27920 | cve@mitre.org | present | ✗ **≠ stored** | – | – | 2025-05-19 | 2025-05-19 |
| CVE-2025-38352 | kernel.org (416baaa9…) | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-07-30 | 2025-09-04 |
| CVE-2025-67038 | ics-cert@hq.dhs.gov | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-09-04 | 2026-06-23 |
| CVE-2023-43000 | product-security@apple.com | missing | ✗ | ✗ | ✗ | never | 2026-03-05 |
| CVE-2023-52163 | cve@mitre.org | missing | ✗ | ✗ | ✗ | never | 2025-12-22 |
| CVE-2024-13159 | 3c1d8aa1-5a33-4ea4-8992-aadd6440af75 | present | ✓ | ✓ | ✓ | 2025-01-14 | 2025-03-10 |
| CVE-2024-13160 | 3c1d8aa1-5a33-4ea4-8992-aadd6440af75 | present | ✓ | ✓ | ✓ | 2025-01-14 | 2025-03-10 |
| CVE-2024-13161 | 3c1d8aa1-5a33-4ea4-8992-aadd6440af75 | present | ✓ | ✓ | ✓ | 2025-01-14 | 2025-03-10 |
| CVE-2024-48248 | cve@mitre.org | present | ✓ | – | – | 2025-03-04 | 2025-03-19 |
| CVE-2024-50603 | cve@mitre.org | present | ✓ | – | – | 2025-01-08 | 2025-01-16 |
| CVE-2024-53704 | PSIRT@sonicwall.com | missing | ✗ | ✗ | ✗ | never | 2025-02-18 |
| CVE-2024-57726 | cve@mitre.org | missing | ✗ | ✗ | ✗ | never | 2026-04-24 |
| CVE-2024-57727 | cve@mitre.org | missing | ✗ | ✗ | – | never | 2025-02-13 |
| CVE-2024-57728 | cve@mitre.org | missing | ✗ | ✗ | ✗ | never | 2026-04-24 |
| CVE-2024-57968 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2025-02-03 | 2025-03-10 |
| CVE-2024-58136 | cve@mitre.org | present | ✓ | ✓ | – | 2025-04-10 | 2025-05-02 |
| CVE-2025-0111 | psirt@paloaltonetworks.com | present | ✓ | – | – | 2025-02-12 | 2025-02-20 |
| CVE-2025-0411 | zdi-disclosures@trendmicro.com | present | ✓ | – | – | 2025-01-25 | 2025-02-06 |
| CVE-2025-10035 | df4dee71-de3a-4139-9588-11b62fe6c0ff | present | ✓ | – | – | 2025-09-18 | 2025-09-29 |
| CVE-2025-11371 | 5dacb0b8-2277-4717-899c-254586fe4912 | missing | ✗ | ✗ | – | never | 2025-11-04 |
| CVE-2025-11953 | reefs@jfrog.com | present | ✓ | ✓ | ✓ | 2025-11-03 | 2026-02-05 |
| CVE-2025-1316 | ics-cert@hq.dhs.gov | present | ✓ | – | – | 2025-03-04 | 2025-03-19 |
| CVE-2025-14847 | cna@mongodb.com | present | ✓ | – | – | 2025-12-19 | 2025-12-29 |
| CVE-2025-15556 | disclosure@vulncheck.com | present | ✓ | – | – | 2026-02-03 | 2026-02-12 |
| CVE-2025-20281 | psirt@cisco.com | present | ✓ | ✓ | ✓ | 2025-06-25 | 2025-07-28 |
| CVE-2025-20337 | psirt@cisco.com | present | ✓ | – | – | 2025-07-16 | 2025-07-28 |
| CVE-2025-21042 | mobile.security@samsung.com | present | ✓ | ✓ | ✓ | 2025-09-12 | 2025-11-10 |
| CVE-2025-21043 | mobile.security@samsung.com | present | ✓ | ✓ | – | 2025-09-12 | 2025-10-02 |
| CVE-2025-23209 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-01-18 | 2025-02-20 |
| CVE-2025-24016 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-02-10 | 2025-06-10 |
| CVE-2025-24472 | psirt@fortinet.com | present | ✓ | ✓ | ✓ | 2025-02-11 | 2025-03-18 |
| CVE-2025-24893 | security-advisories@github.com | present | ✓ | ✓ | – | 2025-02-20 | 2025-10-30 |
| CVE-2025-25181 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2025-02-03 | 2025-03-10 |
| CVE-2025-26399 | psirt@solarwinds.com | present | ✓ | ✓ | ✓ | 2025-09-23 | 2026-03-09 |
| CVE-2025-2746 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2025-03-24 | 2025-10-20 |
| CVE-2025-2747 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2025-03-24 | 2025-10-20 |
| CVE-2025-2749 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2025-03-24 | 2026-04-20 |
| CVE-2025-2775 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2025-05-07 | 2025-07-22 |
| CVE-2025-2776 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2025-05-07 | 2025-07-22 |
| CVE-2025-29635 | cve@mitre.org | missing | ✗ | ✗ | ✗ | never | 2026-04-24 |
| CVE-2025-31125 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-03-31 | 2026-01-22 |
| CVE-2025-31277 | product-security@apple.com | missing | ✗ | ✗ | ✗ | never | 2026-03-20 |
| CVE-2025-32432 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-04-25 | 2026-03-20 |
| CVE-2025-32433 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-04-16 | 2025-06-09 |
| CVE-2025-32463 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2025-06-30 | 2025-09-29 |
| CVE-2025-3248 | disclosure@vulncheck.com | present | ✓ | ✓ | – | 2025-04-07 | 2025-05-05 |
| CVE-2025-32975 | cve@mitre.org | missing | ✗ | ✗ | ✗ | never | 2026-04-20 |
| CVE-2025-33073 | secure@microsoft.com | present | ✓ | ✓ | ✓ | 2025-06-10 | 2025-10-20 |
| CVE-2025-34026 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2025-05-21 | 2026-01-22 |
| CVE-2025-34028 | disclosure@vulncheck.com | present | ✓ | – | – | 2025-04-22 | 2025-05-02 |
| CVE-2025-34291 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2025-12-05 | 2026-05-21 |
| CVE-2025-35939 | 9119a7d8-5eab-497f-8521-727c672e3725 | present | ✓ | ✓ | – | 2025-05-07 | 2025-06-02 |
| CVE-2025-37164 | security-alert@hpe.com | present | ✓ | ✓ | – | 2025-12-16 | 2026-01-07 |
| CVE-2025-3935 | 7d616e1a-3288-43b1-a0dd-0a65d3e70a49 | present | ✓ | ✓ | ✓ | 2025-04-25 | 2025-06-02 |
| CVE-2025-4008 | research@onekey.com | present | ✓ | ✓ | ✓ | 2025-05-21 | 2025-10-02 |
| CVE-2025-40536 | psirt@solarwinds.com | present | ✓ | ✓ | – | 2026-01-28 | 2026-02-12 |
| CVE-2025-41244 | security@vmware.com | present | ✓ | ✓ | ✓ | 2025-09-29 | 2025-10-30 |
| CVE-2025-42599 | vultures@jpcert.or.jp | present | ✓ | – | – | 2025-04-18 | 2025-04-28 |
| CVE-2025-43510 | product-security@apple.com | missing | ✗ | ✗ | ✗ | never | 2026-03-20 |
| CVE-2025-43520 | product-security@apple.com | missing | ✗ | ✗ | ✗ | never | 2026-03-20 |
| CVE-2025-4632 | PSIRT@samsung.com | present | ✓ | – | – | 2025-05-13 | 2025-05-22 |
| CVE-2025-47813 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2025-07-10 | 2026-03-16 |
| CVE-2025-47827 | cve@mitre.org | missing | ✗ | ✗ | ✗ | never | 2025-10-14 |
| CVE-2025-48384 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-07-08 | 2025-08-25 |
| CVE-2025-48700 | cve@mitre.org | missing | ✗ | ✗ | ✗ | never | 2026-04-20 |
| CVE-2025-48703 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2025-09-19 | 2025-11-04 |
| CVE-2025-48927 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2025-05-28 | 2025-07-01 |
| CVE-2025-48928 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2025-05-28 | 2025-07-01 |
| CVE-2025-49113 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2025-06-02 | 2026-02-20 |
| CVE-2025-49704 | secure@microsoft.com | present | ✓ | – | – | 2025-07-08 | 2025-07-22 |
| CVE-2025-49706 | secure@microsoft.com | present | ✓ | – | – | 2025-07-08 | 2025-07-22 |
| CVE-2025-5086 | 3DS.Information-Security@3ds.com | present | ✓ | ✓ | ✓ | 2025-06-02 | 2025-09-11 |
| CVE-2025-52691 | 5f57b9bf-260d-4433-bf07-b6a79e9bb7d4 | present | ✓ | ✓ | – | 2025-12-29 | 2026-01-26 |
| CVE-2025-53521 | f5sirt@f5.com | present | ✓ | ✓ | ✓ | 2025-10-15 | 2026-03-27 |
| CVE-2025-54068 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-07-17 | 2026-03-20 |
| CVE-2025-54236 | psirt@adobe.com | present | ✓ | ✓ | ✓ | 2025-09-09 | 2025-10-24 |
| CVE-2025-54253 | psirt@adobe.com | present | ✓ | ✓ | ✓ | 2025-08-05 | 2025-10-15 |
| CVE-2025-54313 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2025-07-19 | 2026-01-22 |
| CVE-2025-54948 | security@trendmicro.com | present | ✓ | – | – | 2025-08-05 | 2025-08-18 |
| CVE-2025-5777 | secure@citrix.com | present | ✓ | ✓ | – | 2025-06-17 | 2025-07-10 |
| CVE-2025-58360 | security-advisories@github.com | present | ✓ | ✓ | – | 2025-11-25 | 2025-12-11 |
| CVE-2025-59287 | secure@microsoft.com | present | ✓ | – | – | 2025-10-14 | 2025-10-24 |
| CVE-2025-59689 | cve@mitre.org | present | ✓ | – | – | 2025-09-19 | 2025-09-29 |
| CVE-2025-60710 | secure@microsoft.com | present | ✓ | ✓ | ✓ | 2025-11-11 | 2026-04-13 |
| CVE-2025-61757 | secalert_us@oracle.com | present | ✓ | ✓ | ✓ | 2025-10-21 | 2025-11-21 |
| CVE-2025-61884 | secalert_us@oracle.com | present | ✓ | – | – | 2025-10-12 | 2025-10-20 |
| CVE-2025-6204 | 3DS.Information-Security@3ds.com | present | ✓ | ✓ | ✓ | 2025-08-04 | 2025-10-28 |
| CVE-2025-6205 | 3DS.Information-Security@3ds.com | present | ✓ | ✓ | ✓ | 2025-08-04 | 2025-10-28 |
| CVE-2025-6218 | zdi-disclosures@trendmicro.com | present | ✓ | ✓ | ✓ | 2025-06-21 | 2025-12-09 |
| CVE-2025-64328 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-11-07 | 2026-02-03 |
| CVE-2025-66376 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2026-01-05 | 2026-03-18 |
| CVE-2025-68461 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2025-12-18 | 2026-02-20 |
| CVE-2025-68613 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-12-19 | 2026-03-11 |
| CVE-2025-68645 | cve@mitre.org | missing | ✗ | ✗ | ✗ | never | 2026-01-22 |
| CVE-2025-68686 | psirt@fortinet.com | present | ✓ | ✓ | ✓ | 2026-02-10 | 2026-07-27 |
| CVE-2025-8110 | 9947ef80-c5d5-474a-bbab-97341a59000e | present | ✓ | ✓ | ✓ | 2025-12-10 | 2026-01-12 |
| CVE-2025-9242 | 5d1c2695-1a31-4499-88ae-e847036fd7e3 | present | ✓ | ✓ | ✓ | 2025-09-17 | 2025-11-12 |
| CVE-2026-0770 | zdi-disclosures@trendmicro.com | present | ✓ | ✓ | ✓ | 2026-01-23 | 2026-07-21 |
| CVE-2026-1340 | 3c1d8aa1-5a33-4ea4-8992-aadd6440af75 | present | ✓ | ✓ | ✓ | 2026-01-29 | 2026-04-08 |
| CVE-2026-1603 | 3c1d8aa1-5a33-4ea4-8992-aadd6440af75 | present | ✓ | ✓ | – | 2026-02-10 | 2026-03-09 |
| CVE-2026-20122 | psirt@cisco.com | present | ✓ | ✓ | ✓ | 2026-02-25 | 2026-04-20 |
| CVE-2026-20128 | psirt@cisco.com | present | ✓ | ✓ | ✓ | 2026-02-25 | 2026-04-20 |
| CVE-2026-20131 | psirt@cisco.com | present | ✓ | ✓ | – | 2026-03-04 | 2026-03-19 |
| CVE-2026-20133 | psirt@cisco.com | present | ✓ | ✓ | ✓ | 2026-02-25 | 2026-04-20 |
| CVE-2026-20963 | secure@microsoft.com | present | ✓ | ✓ | ✓ | 2026-01-13 | 2026-03-18 |
| CVE-2026-21643 | psirt@fortinet.com | present | ✓ | ✓ | ✓ | 2026-02-06 | 2026-04-13 |
| CVE-2026-24423 | disclosure@vulncheck.com | present | ✓ | – | – | 2026-01-23 | 2026-02-05 |
| CVE-2026-25108 | vultures@jpcert.or.jp | present | ✓ | – | – | 2026-02-13 | 2026-02-24 |

</details>

<details><summary>Test negatives with a stored CNA CVSS (200 of 47,110, seed 20260922)</summary>

| CVE | CNA | Stored CNA CVSS | Day 7 | Day 14 | Day 30 | First CNA CVSS in record | KEV listed |
|---|---|---|---|---|---|---|---|
| CVE-2022-50286 | kernel.org (416baaa9…) | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-08-04 | – |
| CVE-2023-53580 | kernel.org (416baaa9…) | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-08-04 | – |
| CVE-2024-58094 | kernel.org (416baaa9…) | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-08-04 | – |
| CVE-2025-37757 | kernel.org (416baaa9…) | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-07-30 | – |
| CVE-2025-39689 | kernel.org (416baaa9…) | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-07-30 | – |
| CVE-2025-40112 | kernel.org (416baaa9…) | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-07-30 | – |
| CVE-2025-49050 | audit@patchstack.com | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-04-23 | – |
| CVE-2025-62006 | audit@patchstack.com | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-04-23 | – |
| CVE-2025-68031 | audit@patchstack.com | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-04-28 | – |
| CVE-2025-68913 | audit@patchstack.com | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-04-28 | – |
| CVE-2025-71082 | kernel.org (416baaa9…) | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-07-30 | – |
| CVE-2025-71126 | kernel.org (416baaa9…) | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-07-30 | – |
| CVE-2026-22360 | audit@patchstack.com | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-04-28 | – |
| CVE-2026-22451 | audit@patchstack.com | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-04-28 | – |
| CVE-2026-22454 | audit@patchstack.com | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-04-28 | – |
| CVE-2026-24371 | audit@patchstack.com | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-04-23 | – |
| CVE-2026-24538 | audit@patchstack.com | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-04-23 | – |
| CVE-2026-24553 | audit@patchstack.com | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-04-28 | – |
| CVE-2026-25386 | audit@patchstack.com | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-04-28 | – |
| CVE-2026-32375 | audit@patchstack.com | present | ✗ **≠ stored** | ✗ **≠ stored** | ✗ **≠ stored** | 2026-04-29 | – |
| CVE-2009-20009 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2025-08-30 | – |
| CVE-2012-10064 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2026-01-16 | – |
| CVE-2014-125125 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2025-07-31 | – |
| CVE-2014-125128 | 596c5446-0ce5-4ba2-aa66-48b3b757a647 | present | ✓ | ✓ | ✓ | 2025-09-08 | – |
| CVE-2019-25426 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2026-02-19 | – |
| CVE-2019-25622 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2026-03-23 | – |
| CVE-2021-3978 | cna@cloudflare.com | present | ✓ | ✓ | ✓ | 2025-01-29 | – |
| CVE-2023-53935 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2025-12-18 | – |
| CVE-2023-7322 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2025-10-30 | – |
| CVE-2024-11821 | security@huntr.dev | present | ✓ | ✓ | ✓ | 2025-03-20 | – |
| CVE-2024-13612 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2025-02-01 | – |
| CVE-2024-49364 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-07-01 | – |
| CVE-2024-51666 | audit@patchstack.com | present | ✓ | ✓ | ✓ | 2025-05-15 | – |
| CVE-2024-55542 | security@acronis.com | present | ✓ | ✓ | ✓ | 2025-01-02 | – |
| CVE-2025-0177 | security@wordfence.com | present | ✓ | – | – | 2025-03-08 | – |
| CVE-2025-0879 | iletisim@usom.gov.tr | present | ✓ | ✓ | ✓ | 2025-09-17 | – |
| CVE-2025-10073 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-09-07 | – |
| CVE-2025-10088 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-09-08 | – |
| CVE-2025-10146 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2025-09-19 | – |
| CVE-2025-10246 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-09-11 | – |
| CVE-2025-10896 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2025-11-04 | – |
| CVE-2025-11080 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-09-27 | – |
| CVE-2025-11584 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-10-10 | – |
| CVE-2025-1227 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-02-12 | – |
| CVE-2025-12455 | security@opentext.com | present | ✓ | ✓ | ✓ | 2026-03-13 | – |
| CVE-2025-12602 | a0340c66-c385-4f8b-991b-3d05f6fd5220 | present | ✓ | ✓ | ✓ | 2025-11-01 | – |
| CVE-2025-1265 | ics-cert@hq.dhs.gov | present | ✓ | ✓ | – | 2025-02-20 | – |
| CVE-2025-12986 | product-security@silabs.com | present | ✓ | ✓ | ✓ | 2025-12-04 | – |
| CVE-2025-13090 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2025-12-02 | – |
| CVE-2025-13220 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2025-12-21 | – |
| CVE-2025-13258 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-11-17 | – |
| CVE-2025-13286 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-11-17 | – |
| CVE-2025-13468 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-11-20 | – |
| CVE-2025-13813 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-12-01 | – |
| CVE-2025-13851 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2026-02-19 | – |
| CVE-2025-14711 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-12-15 | – |
| CVE-2025-14742 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2026-02-25 | – |
| CVE-2025-15504 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2026-01-10 | – |
| CVE-2025-1664 | security@wordfence.com | present | ✓ | – | – | 2025-03-08 | – |
| CVE-2025-1875 | cve-coordination@incibe.es | present | ✓ | – | – | 2025-03-03 | – |
| CVE-2025-21086 | secure@intel.com | present | ✓ | ✓ | ✓ | 2025-08-12 | – |
| CVE-2025-21532 | secalert_us@oracle.com | present | ✓ | ✓ | ✓ | 2025-01-21 | – |
| CVE-2025-21534 | secalert_us@oracle.com | present | ✓ | ✓ | ✓ | 2025-01-21 | – |
| CVE-2025-2179 | psirt@paloaltonetworks.com | present | ✓ | ✓ | ✓ | 2025-07-29 | – |
| CVE-2025-22645 | audit@patchstack.com | present | ✓ | ✓ | – | 2025-02-18 | – |
| CVE-2025-23473 | audit@patchstack.com | present | ✓ | – | – | 2025-03-03 | – |
| CVE-2025-23747 | audit@patchstack.com | present | ✓ | ✓ | ✓ | 2025-02-03 | – |
| CVE-2025-24068 | secure@microsoft.com | present | ✓ | ✓ | ✓ | 2025-06-10 | – |
| CVE-2025-24461 | cve@jetbrains.com | present | ✓ | ✓ | ✓ | 2025-01-21 | – |
| CVE-2025-24981 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-02-06 | – |
| CVE-2025-25132 | audit@patchstack.com | present | ✓ | – | – | 2025-03-03 | – |
| CVE-2025-26487 | a6d3dc9e-0591-4a13-bce7-0f5b31ff6158 | present | ✓ | ✓ | ✓ | 2025-12-08 | – |
| CVE-2025-26513 | security-alert@netapp.com | present | ✓ | ✓ | ✓ | 2025-08-07 | – |
| CVE-2025-2700 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-03-24 | – |
| CVE-2025-27134 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-04-30 | – |
| CVE-2025-27155 | security-advisories@github.com | present | ✓ | – | – | 2025-03-04 | – |
| CVE-2025-27415 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-03-19 | – |
| CVE-2025-27775 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-03-19 | – |
| CVE-2025-2871 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2025-04-12 | – |
| CVE-2025-30262 | security@qnapsecurity.com.tw | present | ✓ | ✓ | ✓ | 2025-08-29 | – |
| CVE-2025-30263 | security@qnapsecurity.com.tw | present | ✓ | ✓ | ✓ | 2025-08-29 | – |
| CVE-2025-30532 | audit@patchstack.com | present | ✓ | ✓ | ✓ | 2025-03-24 | – |
| CVE-2025-30670 | security@zoom.us | present | ✓ | ✓ | ✓ | 2025-04-08 | – |
| CVE-2025-30750 | secalert_us@oracle.com | present | ✓ | ✓ | ✓ | 2025-07-15 | – |
| CVE-2025-30881 | audit@patchstack.com | present | ✓ | ✓ | ✓ | 2025-03-27 | – |
| CVE-2025-3134 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-04-03 | – |
| CVE-2025-32072 | c4f26cc8-17ff-4c99-b5e2-38fc1793eacc | present | ✓ | ✓ | ✓ | 2025-04-11 | – |
| CVE-2025-32912 | secalert@redhat.com | present | ✓ | ✓ | ✓ | 2025-04-14 | – |
| CVE-2025-32926 | audit@patchstack.com | present | ✓ | ✓ | ✓ | 2025-05-19 | – |
| CVE-2025-33114 | psirt@us.ibm.com | present | ✓ | ✓ | ✓ | 2025-07-29 | – |
| CVE-2025-3344 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-04-07 | – |
| CVE-2025-34058 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2025-07-01 | – |
| CVE-2025-34059 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2025-07-01 | – |
| CVE-2025-34457 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2025-12-22 | – |
| CVE-2025-3462 | 54bf65a7-a193-42d2-b1ba-8e150d3c35e1 | present | ✓ | ✓ | ✓ | 2025-05-09 | – |
| CVE-2025-35032 | 9119a7d8-5eab-497f-8521-727c672e3725 | present | ✓ | ✓ | ✓ | 2025-09-29 | – |
| CVE-2025-35451 | 9119a7d8-5eab-497f-8521-727c672e3725 | present | ✓ | ✓ | ✓ | 2025-09-05 | – |
| CVE-2025-3771 | trellixpsirt@trellix.com | present | ✓ | ✓ | ✓ | 2025-06-26 | – |
| CVE-2025-39485 | audit@patchstack.com | present | ✓ | ✓ | ✓ | 2025-05-23 | – |
| CVE-2025-4010 | research@onekey.com | present | ✓ | ✓ | ✓ | 2025-06-02 | – |
| CVE-2025-40626 | cve-coordination@incibe.es | present | ✓ | ✓ | ✓ | 2025-05-12 | – |
| CVE-2025-40763 | productcert@siemens.com | present | ✓ | ✓ | ✓ | 2025-11-11 | – |
| CVE-2025-40797 | productcert@siemens.com | present | ✓ | ✓ | ✓ | 2025-09-09 | – |
| CVE-2025-40941 | productcert@siemens.com | present | ✓ | ✓ | ✓ | 2025-12-09 | – |
| CVE-2025-41100 | cve-coordination@incibe.es | present | ✓ | ✓ | ✓ | 2025-07-21 | – |
| CVE-2025-41694 | info@cert.vde.com | present | ✓ | ✓ | ✓ | 2025-12-09 | – |
| CVE-2025-4254 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-05-04 | – |
| CVE-2025-42880 | cna@sap.com | present | ✓ | ✓ | ✓ | 2025-12-09 | – |
| CVE-2025-43006 | cna@sap.com | present | ✓ | ✓ | ✓ | 2025-05-13 | – |
| CVE-2025-43790 | security@liferay.com | present | ✓ | ✓ | ✓ | 2025-09-11 | – |
| CVE-2025-4615 | psirt@paloaltonetworks.com | present | ✓ | ✓ | ✓ | 2025-10-09 | – |
| CVE-2025-46352 | ics-cert@hq.dhs.gov | present | ✓ | ✓ | ✓ | 2025-05-29 | – |
| CVE-2025-46748 | security@selinc.com | present | ✓ | ✓ | ✓ | 2025-05-12 | – |
| CVE-2025-46774 | psirt@fortinet.com | present | ✓ | ✓ | ✓ | 2025-10-14 | – |
| CVE-2025-46981 | psirt@adobe.com | present | ✓ | ✓ | ✓ | 2025-06-10 | – |
| CVE-2025-46986 | psirt@adobe.com | present | ✓ | ✓ | ✓ | 2025-06-10 | – |
| CVE-2025-47735 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2025-05-09 | – |
| CVE-2025-48253 | audit@patchstack.com | present | ✓ | ✓ | ✓ | 2025-05-19 | – |
| CVE-2025-4960 | 41c37e40-543d-43a2-b660-2fee83ea851a | present | ✓ | ✓ | ✓ | 2026-02-19 | – |
| CVE-2025-52469 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2026-03-02 | – |
| CVE-2025-52602 | psirt@hcl.com | present | ✓ | ✓ | ✓ | 2025-11-05 | – |
| CVE-2025-52633 | psirt@hcl.com | present | ✓ | ✓ | ✓ | 2026-02-03 | – |
| CVE-2025-52832 | audit@patchstack.com | present | ✓ | ✓ | ✓ | 2025-07-04 | – |
| CVE-2025-52861 | security@qnapsecurity.com.tw | present | ✓ | ✓ | ✓ | 2025-08-29 | – |
| CVE-2025-52925 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2025-07-02 | – |
| CVE-2025-53224 | audit@patchstack.com | present | ✓ | ✓ | ✓ | 2025-08-28 | – |
| CVE-2025-53559 | audit@patchstack.com | present | ✓ | ✓ | ✓ | 2025-08-20 | – |
| CVE-2025-53927 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-07-17 | – |
| CVE-2025-5586 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2025-06-06 | – |
| CVE-2025-5734 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-06-06 | – |
| CVE-2025-57943 | audit@patchstack.com | present | ✓ | ✓ | ✓ | 2025-09-22 | – |
| CVE-2025-58285 | psirt@huawei.com | present | ✓ | ✓ | ✓ | 2025-10-11 | – |
| CVE-2025-58291 | psirt@huawei.com | present | ✓ | ✓ | ✓ | 2025-10-11 | – |
| CVE-2025-58781 | vultures@jpcert.or.jp | present | ✓ | ✓ | ✓ | 2025-09-12 | – |
| CVE-2025-58875 | audit@patchstack.com | present | ✓ | ✓ | ✓ | 2025-09-05 | – |
| CVE-2025-59344 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-09-19 | – |
| CVE-2025-59368 | 54bf65a7-a193-42d2-b1ba-8e150d3c35e1 | present | ✓ | ✓ | ✓ | 2025-11-25 | – |
| CVE-2025-59451 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2025-10-06 | – |
| CVE-2025-59838 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-09-25 | – |
| CVE-2025-6054 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2025-07-23 | – |
| CVE-2025-62214 | secure@microsoft.com | present | ✓ | ✓ | ✓ | 2025-11-11 | – |
| CVE-2025-6233 | responsibledisclosure@mattermost.com | present | ✓ | ✓ | ✓ | 2025-07-18 | – |
| CVE-2025-62467 | secure@microsoft.com | present | ✓ | ✓ | ✓ | 2025-12-09 | – |
| CVE-2025-62474 | secure@microsoft.com | present | ✓ | ✓ | ✓ | 2025-12-09 | – |
| CVE-2025-6462 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2025-06-29 | – |
| CVE-2025-65120 | vultures@jpcert.or.jp | present | ✓ | ✓ | ✓ | 2025-12-12 | – |
| CVE-2025-65465 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2026-03-02 | – |
| CVE-2025-66419 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-12-11 | – |
| CVE-2025-66567 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2025-12-09 | – |
| CVE-2025-6748 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-06-27 | – |
| CVE-2025-67645 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2026-01-27 | – |
| CVE-2025-68701 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2026-01-13 | – |
| CVE-2025-68879 | audit@patchstack.com | present | ✓ | ✓ | ✓ | 2025-12-29 | – |
| CVE-2025-7063 | cvd@cert.pl | present | ✓ | ✓ | ✓ | 2025-09-30 | – |
| CVE-2025-7306 | zdi-disclosures@trendmicro.com | present | ✓ | ✓ | ✓ | 2025-07-21 | – |
| CVE-2025-8742 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-08-08 | – |
| CVE-2025-8754 | cybersecurity@ch.abb.com | present | ✓ | ✓ | ✓ | 2025-08-13 | – |
| CVE-2025-8912 | twcert@cert.org.tw | present | ✓ | ✓ | ✓ | 2025-08-13 | – |
| CVE-2025-9004 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-08-15 | – |
| CVE-2025-9490 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2025-09-26 | – |
| CVE-2025-9723 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2025-08-31 | – |
| CVE-2025-9945 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2025-10-03 | – |
| CVE-2025-9979 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2025-09-10 | – |
| CVE-2026-0578 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2026-01-04 | – |
| CVE-2026-1004 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2026-01-16 | – |
| CVE-2026-1074 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2026-03-07 | – |
| CVE-2026-1486 | secalert@redhat.com | present | ✓ | ✓ | ✓ | 2026-02-09 | – |
| CVE-2026-1616 | 74b3a70d-cca6-4d34-9789-e83b222ae3be | present | ✓ | ✓ | ✓ | 2026-01-29 | – |
| CVE-2026-20064 | psirt@cisco.com | present | ✓ | ✓ | ✓ | 2026-03-04 | – |
| CVE-2026-21297 | psirt@adobe.com | present | ✓ | ✓ | ✓ | 2026-03-11 | – |
| CVE-2026-22213 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2026-01-12 | – |
| CVE-2026-22324 | audit@patchstack.com | present | ✓ | ✓ | ✓ | 2026-03-20 | – |
| CVE-2026-22549 | f5sirt@f5.com | present | ✓ | ✓ | ✓ | 2026-02-04 | – |
| CVE-2026-24290 | secure@microsoft.com | present | ✓ | ✓ | ✓ | 2026-03-10 | – |
| CVE-2026-2471 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2026-02-28 | – |
| CVE-2026-24820 | cve_disclosure@tech.gov.sg | present | ✓ | ✓ | ✓ | 2026-01-27 | – |
| CVE-2026-25168 | secure@microsoft.com | present | ✓ | ✓ | ✓ | 2026-03-10 | – |
| CVE-2026-25611 | cna@mongodb.com | present | ✓ | ✓ | ✓ | 2026-02-10 | – |
| CVE-2026-25920 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2026-02-09 | – |
| CVE-2026-26186 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2026-02-26 | – |
| CVE-2026-26195 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2026-03-05 | – |
| CVE-2026-2623 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2026-02-17 | – |
| CVE-2026-26335 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2026-02-13 | – |
| CVE-2026-27148 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2026-02-25 | – |
| CVE-2026-27739 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2026-02-25 | – |
| CVE-2026-28207 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2026-02-26 | – |
| CVE-2026-28469 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2026-03-05 | – |
| CVE-2026-28470 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2026-03-05 | – |
| CVE-2026-3051 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2026-02-24 | – |
| CVE-2026-31882 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2026-03-13 | – |
| CVE-2026-32024 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2026-03-19 | – |
| CVE-2026-32038 | disclosure@vulncheck.com | present | ✓ | ✓ | ✓ | 2026-03-19 | – |
| CVE-2026-32310 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2026-03-20 | – |
| CVE-2026-3240 | ff5b8ace-8b95-4078-9743-eac1ca5451de | present | ✓ | ✓ | ✓ | 2026-03-04 | – |
| CVE-2026-32632 | security-advisories@github.com | present | ✓ | ✓ | ✓ | 2026-03-18 | – |
| CVE-2026-32647 | f5sirt@f5.com | present | ✓ | ✓ | ✓ | 2026-03-24 | – |
| CVE-2026-33549 | cve@mitre.org | present | ✓ | ✓ | ✓ | 2026-03-22 | – |
| CVE-2026-3442 | secalert@redhat.com | present | ✓ | ✓ | ✓ | 2026-03-15 | – |
| CVE-2026-4136 | security@wordfence.com | present | ✓ | ✓ | ✓ | 2026-03-20 | – |
| CVE-2026-4543 | cna@vuldb.com | present | ✓ | ✓ | ✓ | 2026-03-22 | – |

</details>

## Fix: EPSS refresh immutability check (2026-10-23)

The EPSS step's `historical_cve_rows_added == 0` check passes whatever
happened to history. `download_epss` keeps a snapshot only within 90 days
of publication, so a CVE published before 2026-03-25 can't get a row dated
on or after 2026-09-21. **That check confirms the window was applied. It
does not test immutability**, and it must not be quoted as if it did. It
is now labelled as a window check in the code, in the module docstring and
in the stored record (`historical_cve_rows_added_note`).

**Real check (new).** `step_epss` now compares every
`canonical.epss_timeline` row dated on or before 2026-06-22 (the last date
any pre-cohort CVE can have) three ways: before its clean, after its clean,
and against the pre-refresh backup
(`data/backups/vuln_survival_pre_refresh_20261022.dump`). Each comparison
uses the row count plus two order-independent checksums, one over
(cve_id, snapshot_date, epss_score, percentile) and one over the full row.

**Result for this refresh** (run after the step had completed, since the
check was added afterwards): **exact match**. Live and backup both have
15,229,696 rows, the 4-column checksum is `2704061a…5a5ac4` and the
full-row checksum is `89193d17…d28719`. An independent pipeline
(`pg_restore`/`psql` COPY streams) gives the same values. The result is
stored as `history_immutability` in `refresh_epss.json`, and the manifest
row was re-upserted with the new file checksum. The backup is 463,612,521
bytes (442 MiB).

## Corrected-labels re-evaluation (2026-10-24)

**Decision.** The 18 test rows (6 CVEs) whose stored labels predate their
KEV listing are corrected **in memory only**, and every reported
test-period metric is recomputed with the frozen models and frozen
features. The result is published as a new record,
**`docs/results_corrected_labels.md`**, beside `docs/final_results.md`
rather than replacing it. `training.training_dataset` was not written to:
its content hash equals the pre-refresh backup's (`docs/backups.md`).

**Regression test, restructured** (not relabelled, not pinned):
`tests/test_features/test_build_reproduces_training_dataset.py`.

- *Features:* every exported non-label column must match bit for bit on
  all 178,756 test rows, with no exceptions.
- *Labels:* the set of rows whose `event_time`/`event_observed` differ must
  equal the record in `tests/fixtures/kev_label_diffs_20261021.json`. That
  record holds each CVE, its listing date, its rows' stored and corrected
  labels, and both catalogs (2026.08.06 and 2026.10.21, with their
  sha256s). The test fails in both directions:
  - a differing row that is not in the record;
  - a recorded row that no longer differs.

  Mutation-checked: dropping or adding a record row, "correcting" one
  stored label, a 1-ulp feature change and a one-row label change each
  fail.
- *Catalog diff:* 2026.10.21 removes no entry and changes no date relative
  to 2026.08.06. All 93 additions are dated 2026-08-07 or later.

**Method** (`scripts/evaluate/corrected_labels.py`;
`scripts/evaluate/label_corrections.py` does the relabel):

- *Two passes on identical code.* One uses the stored labels, the other
  the corrected labels.
- *The stored pass is a check, and it passed.* It reproduces the 9
  recorded result files **exactly**: 1,163 numbers, 0 mismatches. That
  makes every difference the effect of the 18 rows alone. It also shows
  that the rolling-origin rebuild (current catalog) differs from the
  stored data only on those rows.
- *Training labels are identical in both passes.* Ablation and fold refits
  see the same training labels, because every listing (2026-08-17 to
  2026-09-18) falls after every training cutoff.
- *Not re-run:* the RSF seed-variance study, because RSF refits are not
  reproducible.

**Result.** Test events go from 268 to **286** (108 → 114 listed CVEs).
The new events are 159–371 days after their landmark, so the 90-day
calibration base (177) is unchanged.

| Quantity | Recorded | Corrected |
|---|---|---|
| Cox C-index | 0.850 | 0.850 |
| EPSS-alone C-index | 0.750 | 0.734 |
| Cox − EPSS ΔC-index | +0.100 | +0.116 |
| Cox − EPSS ΔRecall@10% | +0.172 | +0.168 |
| Effort ratio @10% | 2.35× | 2.37× |

The ΔC-index and ΔRecall@10% intervals both still exclude zero, and the
effort-ratio interval still excludes 1×. No headline conclusion
changes. **Five intervals cross their null:**

1. Blind-spot catch, XGBoost-AFT − Cox: +0.090 (−0.032, +0.206) →
   **+0.124 (+0.016, +0.246)**, now significant.
2. Cox ablation (a) − (c), ΔRecall@10%: **+0.075 (+0.008, +0.139)** →
   +0.042 (−0.029, +0.118), **no longer significant**.
   `final_results.md`'s "EPSS's current level carries real signal" rests
   on this interval.
3. XGBoost-AFT ablation (a) − (b), ΔC-index: −0.032 (−0.077, +0.005) →
   **−0.041 (−0.083, −0.005)**. The full model is now significantly
   worse.
4. XGBoost-AFT ablation (a) − (c), ΔC-index: −0.031 (−0.073, +0.003) →
   **−0.041 (−0.080, −0.006)**.
5. Fuzzy − Cox, blind-spot catch: **−0.131 (−0.229, −0.024)** → −0.093
   (−0.186, +0.014), **no longer significant**.

H1 stays rejected in both models: no trajectory benefit, and for
XGBoost-AFT, significant harm. Full tables are in
`docs/results_corrected_labels.md`. The report rebuild decides which
record the report cites. `final_results.md` is unchanged until then.

**Backup record.** `docs/backups.md` records the pre-refresh dump's path,
size, sha256 (authoritative) and a re-verification run on 2026-10-24. The
first verification, run 2026-10-22, was never recorded.

## Holdout cohort built; four open items closed (2026-10-24)

**The 2026 holdout cohort** is in `training.holdout_2026`
(`holdout_2026_v20261024`), built by
`scripts/features/build_holdout_cohort.py`. Full record:
`docs/holdout_protocol.md`. **No model has been evaluated on it.**

- **Population:** CVEs published 2026-03-25..2026-09-21.
- **Labels:** censored at 2026-10-21. The 180-day rule is applied at
  evaluation, from the stored `followup_days`.
- **Size** (default rows): 153,005 rows, 53,130 CVEs, 100 events (50
  CVEs), censoring 99.93%.
- **Overlap guarantee:** zero CVE overlap with `training_dataset`, enforced
  by constraint triggers on both tables (migration `b7d41c2e9f30`, mirrored
  in `schema.sql`, `models.py` and the test DB).
- **Tests:** `tests/test_leakage/test_holdout_cohort.py` runs the
  allowlist and the leakage rules against the stored rows. Its prod-row
  checks were mutation-checked.

**Finding (recorded before any evaluation):** the cohort's CNA-CVSS gap is
**+17.17pp** (+10.03 to +22.08), against test's +6.23pp. It is larger, and
in the opposite direction to the protocol's expectation. The protocol now
has a gate requiring an as-of check and a CNA-stratified gap before any
cohort evaluation. Also recorded there:

- under the 180-day rule the cohort has 9 events;
- 72.7% of its rows are scored under EPSS v2026.06.15, which the frozen
  models never saw.

**Open items closed:**

1. **2026-06-15 EPSS transition.**
   - `VERSION_TRANSITIONS` was missing the 2026-06-15 release, although
     `VERSION_BOUNDARIES` had it. It is now derived from
     `VERSION_BOUNDARIES`, so the two lists cannot drift apart.
   - No study row spans it: max as_of is 2026-04-23. The default build is
     unchanged, as the regression test confirms.
   - 12,827 cohort rows span it and are flagged.
2. **`scripts/epss_reconstruct/` deleted.**
   - It was an empty package.
   - The `vsp reconstruct epss` command imported a module that never
     existed, so it was removed with the package.
   - `clean_epss.py`'s docstring now says the build forward-fills at query
     time.
3. **Feature-affecting ordering no longer depends on surrogate ids.**
   - **`primary_vendor`** was the CPE entry with the lowest
     `cpe_product_id`. It is now the alphabetically first (vendor,
     product), via `pick_primary_vendor`. That changes the pick for 7,328
     CVEs. It is not a model feature and not in the export, and the stored
     tables are not rewritten.
   - **The own-CNA CVSS pick** (`pick_own_cna_cvss`) broke version ties by
     the order SQL returned rows. It now breaks them on the metric's
     values. No CVE has such a tie today, so nothing changes.
   - **The own-CNA `DISTINCT ON` query** is one constant with a content
     tie-break.
   - **EPSS** is sorted on (snapshot_date, cve_id).
   - **`tests/test_features/test_ordering.py`:**
     - It fails if any feature-path module names a BIGSERIAL column, with
       the set read from `schema.sql`. It flags the previous build module
       at its two `cpe_product_id` lines.
     - It also checks that both picks are invariant to row permutation.
       The old CVSS pick fails that check.
4. **Latent hazard, recorded and not fixed.**
   - **What is staged:** `canonical.epss_timeline` holds **7,212 snapshots
     dated 2026-06-15..2026-06-22 for 1,545 study CVEs**, i.e. CVEs with
     landmark rows. That is 7,230 / 1,548 counting every CVE published in
     the study window. These are v2026.06.15 scores from the last days of
     each CVE's 90-day window.
   - **Why no feature reads them now:** every EPSS feature is as of the
     landmark, and the latest study as_of is 2026-04-23.
     `epss_pct_first`, the cummax and `days_to_first_epss` take the
     earliest or the running value up to as_of.
   - **The hazard:** any future feature that reads a CVE's EPSS series
     beyond its landmark, such as a "last", "max over window" or
     "trajectory to day 90" feature, would silently mix two EPSS models
     for these CVEs, and only for the most recently published ones.
   - **Guard to add with any such feature:** filter to snapshot_date <=
     as_of, or to one model version.

## `vsp results`: presentation output from the committed record (2026-10-27)

**What it is.** `vsp results` prints the corrected-labels record as terminal
tables for a live presentation (`scripts/results/`).

- **Output:** a header line with the test-set definition, then the sections
  headline, models, budget, rolling, blindspot, negatives, fuzzy and
  sensitivity, then a footer naming the record and its commit. Each section
  can be selected with `--section`.
- **What it reads:** `results/corrected_labels/corrected.json` and nothing
  else. It uses no database, network, config, `.env`, pandas or numpy, and
  runs in about 0.06 s.
- **No hardcoded numbers:** `tests/test_results/` fails on any numeric
  literal in the formatting code other than a budget threshold.
- **`vsp results --check`:**
  - re-reads the record and verifies every printed cell against it through a
    mapping written independently of the formatter;
  - verifies that each ✓ appears exactly when the interval excludes zero
    strictly, and that each verdict follows from its interval;
  - runs in CI (`.github/workflows/ci.yml`) before the suite.

**Decision: the record is committed and stamped with its commit.**

- **Before:** `docs/results_corrected_labels.md` was generated from `scratch/`,
  which is gitignored, so its source was not in the repository.
- **Now:** `scripts/evaluate/corrected_labels.py` writes
  `results/corrected_labels/{stored,corrected,comparison}.json`, which are
  committed.
- **Provenance block:** each pass records its commit, interval settings, the
  publication window and the observation cutoff. A pass refuses to run with
  uncommitted changes to tracked files.
- **Regeneration:** both passes were re-run at `1faacd2` in a clean worktree.
  - Every number is bit-identical to the 2026-10-24 record, and the figures
    are byte-identical.
  - The stored pass again reproduced all 1,163 recorded values exactly.
  - The only doc change is a line naming the record and its commit.

**CI.**

- **Setup:** CI runs against a Postgres service with no production database,
  so the tests that verify stored production data skip.
- **Fix needed for that:**
  `tests/test_evaluate/test_fast_concordance.py::real_test_data` read the
  production database without a skip. It now skips like the other
  production-data tests.
- **Simulated locally before pushing:** a clean copy with no `.env` and no
  `data/` gave 142 passed and 11 skipped.
