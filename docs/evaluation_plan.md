# Evaluation plan (recorded for later — not implemented yet)

This records the evaluation design agreed for the landmark-prediction models
built from `training.training_dataset` / `scripts/features/build_landmark_dataset.py`.
No model has been trained yet; this is scope-setting only.

## Primary metric: recall at fixed alert budgets

For each landmark (7, 14, 30) separately, rank that landmark's test rows by
the model's predicted risk score, descending. At each of the top 1%, 5%,
and 10% of rows (by count, per landmark — not pooled across landmarks),
compute recall: what fraction of that landmark's true test positives
(`event_observed = true`) fall inside that top slice.

Report the same recall-at-budget for a baseline ranking by
`epss_score_at_asof_raw` alone (the raw EPSS score stored specifically for
this comparison — never a model feature; see
`build_landmark_dataset.py`'s `MODEL_FEATURE_COLUMNS` /
`NON_FEATURE_COLUMNS` split) on the identical set of rows, so the
comparison is apples-to-apples: same rows, same budgets, model ranking vs.
EPSS-alone ranking.

This is the primary metric because it's the one that answers the actual
question this project exists to answer: at a fixed triage budget (an
analyst can only chase N% of alerts), does the model catch more of the
CVEs that go on to be KEV-listed than EPSS alone would have, including the
blind-spot cases EPSS misses (see the STEP 1(e) test-positive EPSS-score
distribution in the project history — a large majority of true positives
sit below a raw EPSS score of 0.1).

## Secondary metrics

- **C-index** (concordance), per landmark.
- **Time-dependent AUC**, per landmark, at a small set of follow-up
  horizons still to be chosen once training data is finalized.

These are reported as secondary/diagnostic — standard survival-model
discrimination metrics — but recall-at-alert-budget is what drives any
go/no-go or model-comparison decision, since it's the metric that
corresponds to how the model would actually be used.

## Confidence intervals: bootstrap resampling whole CVEs, not rows

A CVE can appear as up to 3 rows in the dataset (one per landmark it's
eligible for). Resampling rows directly would treat those as independent
observations, which they are not — they share the same CVE, the same KEV
outcome, and highly correlated features (CVSS, CWE, vendor are literally
identical across a CVE's landmark rows; EPSS trajectory features are
strongly autocorrelated). All confidence intervals (for both the primary
and secondary metrics) must be computed by:

1. Resampling **CVEs** (not rows) with replacement, at the appropriate
   population size (per-landmark for a per-landmark metric; pooled for a
   pooled metric).
2. Taking every row belonging to each resampled CVE (i.e., resampling is
   at the CVE-id level, and a CVE's rows move together).
3. Recomputing the metric on the resampled row set.
4. Repeating (2000+ resamples recommended) and taking the percentile
   interval.

Row-level bootstrap would understate the true variance and produce
falsely tight confidence intervals, given the row-level correlation
structure described above.

## Not yet decided / out of scope for this document

- Model family (Cox PH / Random Survival Forest / XGBoost-AFT / logistic) —
  no model has been chosen or trained.
- Exact horizons for time-dependent AUC.
- Whether/how to pool metrics across landmarks into a single headline
  number, versus reporting all three separately.
- Sensitivity-analysis protocol for the `spans_version_transition`-flagged
  rows that are excluded from the default training table (see
  `build_landmark_dataset.py`) — they're retained in
  `training.training_dataset` with the flag set, but how to fold them
  back in for a robustness check hasn't been designed.
