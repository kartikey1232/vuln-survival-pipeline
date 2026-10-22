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
   20.9pp → 2.8pp (train) and 6.0pp → stayed ~6.2pp (test) for CVSS;
   `primary_cwe_id` missingness 19.0pp → 5.4pp (train), 9.1pp → 4.5pp
   (test, now under the 5pp flag threshold).
   `cwe_kev_rate_expanding`/`vendor_kev_rate_expanding` were similarly
   filtered; `cna_kev_rate_expanding` (new) is an expanding-window
   target encoding on the CVE's own `sourceIdentifier`, replacing the
   removed vendor encoding.

**Residual, not fully resolved**: even after the fix, CVSS-presence
still correlates with the label (2.8pp train / 6.2pp test gap). Because
this residual is BIGGER in the older (fit/val) era than in test,
validation-set C-index runs optimistic relative to test — always trust
test numbers.

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
- No feature-engineering/model work happens on `scripts/epss_reconstruct/`,
  `scripts/labels/`, `scripts/export/` — those are still stub packages
  from the original pipeline design; the landmark build script bypassed
  them entirely with its own self-contained logic.
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
- **Residual CVSS-presence gap** (2.8pp train / 6.2pp test). Restricting
  test to CNA-CVSS-present rows leaves Cox > EPSS intact (ΔC-index +0.094,
  ΔR@10% +0.178). So CVSS presence does not drive the test result. The
  separate caveat that validation runs optimistic relative to test is
  untested and stands.
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
enrichment gap, the in-sample-validation issue for Cox (limitation 1), and
the train-tuned RSF/XGBoost configs (limitation 2).

**Dashboard screenshots:** `docs/figures/dashboard_{cve_lookup,watchlist,backtest}.png`
(CVE-2025-24472 for the lookup view).

**New shared-evaluation helpers** (`scripts/evaluate/common.py`):
`evaluate_brier_at_horizon`, and `km_calibration_table(bin_score=...)`.
