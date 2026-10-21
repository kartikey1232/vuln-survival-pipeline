# models/

Frozen final models from the model-comparison exercise (see
`docs/model_comparison.md`), each refit once on the full train set with
its already-chosen (tuned on fit/val, never on test) config, via
`scripts/models/freeze_final_models.py`.

- `cox_final.pkl` / `cox_final_metadata.json`
- `rsf_final.pkl` / `rsf_final_metadata.json`
- `xgboost_aft_final.json` / `xgboost_aft_final_columns.json` /
  `xgboost_aft_final_metadata.json`

Each metadata JSON records the git commit hash the model was produced
from, the data cutoff, the exact feature list
(`MODEL_FEATURE_COLUMNS`), hyperparameters, and test-set metrics.

**No further tuning of any model against test results after this
freeze** — this is the final, reported state. A future retrain (e.g. on
newer data) should be a new, explicitly-named freeze, not an overwrite
of these files.

RSF is not exactly reproducible run to run even with `random_state`
fixed (see `docs/model_comparison.md`'s RSF run-to-run variance
section and rule 8 in `CLAUDE.md`) — treat `rsf_final.pkl`'s test
C-index as approximate.

The database already has a schema-only placeholder for model output —
`training.prediction` — for a future serving/inference phase.

## Corrected-encoding metrics

Each `*_final_metadata.json` keeps its recorded `test_metrics` and has a
`test_metrics_corrected_encoding` block added beside it (2026-10-21):
the same frozen model, with the test frame encoded relative to the
training categories. See `docs/results_corrected_encoding.md`.
`cox_serving_preprocessing.json` holds the training imputation medians
the API uses.

## Fuzzy-layer input reference

- `cox_risk_reference.npz` / `cox_risk_reference_metadata.json` — frozen
  Cox's partial-hazard scores on the full train set, sorted, one array
  per landmark (7/14/30). `scripts/fuzzy/risk_percentile.py` maps any
  row's Cox score to `cox_risk_pct = #(reference <= score) / n` against
  its own landmark's array. Derived from `cox_final.pkl` without refitting;
  rebuild it if Cox is ever re-frozen.
