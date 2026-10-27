# CLAUDE.md

Guidance for AI assistants working in this repo. **Read `docs/STATUS.md`
first** — it has the current pipeline state, every major design decision
with its reasoning, and open items. This file is the shorter set of rules
to follow; STATUS.md is the longer narrative.

## Non-negotiable rules

1. **No NVD-analyst-added field may become a model feature**, directly or
   indirectly, without checking it against the enrichment-leakage finding
   in `docs/STATUS.md`. If you're unsure whether a candidate feature is
   "NVD's own enrichment" (added preferentially to reviewed/prioritized
   CVEs) vs. genuinely publication-time information, check whether it has
   a `source` field and verify that source resolves to the CVE's own
   `sourceIdentifier` (its actual CNA) — not `nvd@nist.gov`, and not a
   third-party ADP/coordinator (CISA's Vulnrichment UUID
   `134c704f-9b21-4f2e-91b3-4a467353bcc0` is a known example; there may be
   others — check via the raw payload's `ssvcData.role` or equivalent
   before trusting a new `source` value).
2. **Never add a column to `scripts/features/build_landmark_dataset.py`'s
   `MODEL_FEATURE_COLUMNS`** without updating
   `tests/test_leakage/test_landmark_features.py::test_export_column_allowlist_exact`
   in the same change. That test's `banned_columns` set exists specifically
   to catch a leaky/legacy column sneaking back in.
3. **Every model must be evaluated through `scripts/evaluate/common.py`**
   (`evaluate_model`, `evaluate_model_per_landmark`,
   `paired_bootstrap_compare`) — never write a one-off bootstrap loop. The
   whole point is that every model/baseline comparison in
   `docs/model_comparison.md` uses identical test rows, seed, and
   resampling. If you're about to write `for i in range(n_resamples):
   ... concordance_index(...)` by hand, stop and use the shared module.
4. **Hyperparameter tuning happens on fit/val only**
   (`scripts/evaluate/data_splits.py::load_splits`), never on test. Once a
   model's config is chosen, refit on the FULL original train set
   (`load_full_train_and_test`) — not on fit+val concatenated (they have
   different label-censoring cutoffs; concatenating them naively is
   wrong).
5. **This project has no mocks and no SQLite** — tests hit a real local
   Postgres test database (`tests/conftest.py`). Match that convention.
6. **Every schema change needs a hand-written Alembic migration**, not
   autogenerate. This repo's tables were created by executing
   `schema.sql` directly, so Postgres assigned different constraint/index
   names than SQLAlchemy's naming convention would — `alembic revision
   --autogenerate` proposes renaming/dropping most of the database over
   that alone. Write the migration by hand (see any file in
   `database/migrations/versions/` for the pattern) and mirror the change
   in both `database/schema.sql` and `database/models.py`. Also apply the
   equivalent DDL directly to the test database
   (`vuln_survival_test`) — it bootstraps from `schema.sql` via
   `conftest.py`, not from Alembic, so migrations never reach it
   automatically.
7. **Any bulk INSERT/UPSERT must be chunked** to stay under Postgres's
   65535 bound-parameter limit — `chunk_size = 65000 // n_columns`, not a
   fixed row count (a fixed chunk size safe for a narrow table can blow up
   silently on a wider one; this has happened twice in this project's
   history).
8. **RSF results are not exactly reproducible** even with `random_state`
   fixed (confirmed: both hyperparameter selection and test C-index vary
   run to run under `n_jobs=-1`). Don't report a single RSF number as
   precise; report it as approximate or re-run a few seeds if precision
   matters.
9. **Async/concurrent code using `database/engine.py`'s (synchronous)
   engine must wrap every DB call in `asyncio.to_thread(...)`** — see that
   file's module docstring for the concrete incident (an 8-way "concurrent"
   downloader that was actually fully serialized on every DB round-trip).

## Where things are

- `scripts/download/` — ingestion (NVD/EPSS/KEV/ExploitDB/CWE)
- `scripts/clean/` — raw → canonical
- `scripts/features/build_landmark_dataset.py` — the feature/label build
  (this is the pipeline's core; read it before touching features)
- `scripts/features/build_holdout_cohort.py` — the 2026 holdout cohort
  (`training.holdout_2026`; same build, own window/cutoff; read
  `docs/holdout_protocol.md` before evaluating anything on it)
- `scripts/evaluate/` — shared bootstrap/metrics (`common.py`), fit/val/
  test splitting (`data_splits.py`), feature prep (`features.py`)
- `scripts/models/{cox,rsf,xgboost_aft}.py` — the three candidate models
- `scripts/eda/` — one-off exploratory/diagnostic scripts, not pipeline
  stages (not wired into `vsp`)
- `api/` — read-only FastAPI service over the frozen artifacts (ranks by
  Cox, explains by fuzzy rules; see `api/README.md`)
- `scripts/fuzzy/` — Cox risk percentiles + the fuzzy explanation layer
- `docs/STATUS.md` — full narrative status, read this first
- `docs/final_results.md` — every corrected number for the report/deck in one
  place (start here for numbers)
- `docs/model_comparison.md` — original-encoding model numbers (marked)
- `docs/results_corrected_labels.md` — every test metric recomputed with the 18
  KEV-relabelled test rows, beside the recorded value (generated; do not edit)
- `results/corrected_labels/` — the committed record behind it
  (`corrected.json`, `stored.json`, `comparison.json`), each stamped with the
  commit it was generated at; regenerate with
  `scripts/evaluate/corrected_labels.py` from a clean tree only
- `scripts/results/` — `vsp results`: prints that record for presentation.
  No number may be hardcoded there (a test enforces it); every value comes
  from the record, and `vsp results --check` verifies the output
- `docs/backups.md` — database dumps: path, sha256, verification
- `docs/enrichment_leakage.md` — the leakage investigation writeup
- `database/schema.sql` + `database/models.py` — must always match each
  other (schema.sql is authoritative for a fresh `vsp db init`; models.py
  is authoritative for what Alembic migrations diff against)

## Commands

- `uv run pytest -q` — full test suite (~70s, of which ~60s is the fuzzy-layer
  grids in `tests/test_fuzzy/`; hits the real test DB)
- `uv run python -m scripts.<module.path>` — run any pipeline/model script
- `uv run vsp results [--section NAME] [--check]` — final results as tables
  (from the corrected-labels record); `--check` runs in CI with the suite
- `uv run alembic upgrade head` — apply migrations to the prod DB (then
  apply the equivalent DDL by hand to the test DB — see rule 6)
