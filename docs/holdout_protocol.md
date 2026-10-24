# 2026 holdout cohort protocol

The cohort is CVEs published 2026-03-25..2026-10-21: everything after the
frozen test period (published ≤ 2026-03-24), fetched by
`scripts/download/refresh.py`. Its NVD records are fetched in October 2026
and the frozen test's were fetched 2026-09-20, so the two populations were
captured at different enrichment maturities (age at NVD fetch: test
180–627 days, median 380 at landmark-row level; cohort at most ~210 days, measured once built).

## Expected direction of the maturity difference

The cohort's records are fetched at a **lower CVE age** than the frozen
test records were: at most ~210 days, against a test median of 380 days
(range 180–627). NVD enrichment (analysis, `vulnStatus=Analyzed`, NVD and
ADP scoring) builds up with age, so the cohort is expected to be **less
enrichment-mature** than test.

That makes the cohort a **harder** evaluation, not an easier one. Whatever
residual enrichment signal the publication-time rule leaves in the frozen
test (CNA-CVSS gap +6.23pp) has had less time to build up in the cohort.

Consequences:

- **A cohort result that degrades relative to test has a confounded
  explanation.** Lower enrichment maturity could produce the drop with no
  change in the model's real performance. That explanation must be
  excluded, starting with the enrichment-gap gate below, before the drop
  is attributed to the model.
- **A cohort result that holds is stronger evidence than the equivalent
  test result**, because it holds under less of the residual enrichment
  signal than test had.

Neither consequence licenses comparing absolute cohort metrics with test
figures. The comparability rule below still applies. This section says
which way the known bias points when cohort and test results are
discussed side by side in prose.

## Comparability rule

**The cohort supports within-cohort comparisons only**, meaning rankings
evaluated against each other on identical cohort rows (e.g. Cox vs
EPSS-alone through `scripts/evaluate/common.py::paired_bootstrap_compare`
on the same cohort rows).

**Absolute metrics computed on the cohort are not comparable to the frozen
test figures.** The two sets of records were captured at different
enrichment maturities. The publication-time (own-CNA source) rule reduces
that bias but does not eliminate it: a residual CNA-CVSS presence gap
remains (6.2pp on frozen test).

Any document or result file that reports a cohort metric must carry this
statement adjacent to the number:

> Cohort metric: valid only for comparison against other rankings on the
> same cohort rows. Not comparable to frozen test-period figures, since the
> cohort and test were captured at different NVD enrichment maturities and
> the publication-time rule reduces but does not eliminate that bias.

"Adjacent" means in the same table caption, paragraph or result-file
record as the number, not only in a document header or a footnote
elsewhere.

## Gate before any model is evaluated on the cohort

Once the cohort's landmark rows are built, and before any model is scored
on them, run:

    uv run python -m scripts.eda.enrichment_gap --cohort <dataset_version>

This is the same presence-gap test that produced the recorded figures. It
measures, at landmark-row level, the positive-vs-negative gap in CNA-CVSS
presence and in NVD `vulnStatus` distribution, and prints the frozen train
and test figures beside the cohort's. Record in this file the cohort's
figures next to the frozen test's (CNA-CVSS gap +6.23pp; `vulnStatus`
Analyzed share 100% of positives vs 50% of negatives).

If the cohort's gap differs materially from the test figure, that is a
finding about the cohort. It must be written up here before any model is
evaluated on the cohort, not afterwards.

### Recorded figures

| Population | CNA-CVSS gap (neg − pos missing) | vulnStatus Analyzed, pos / neg | Age at fetch, median |
|---|---|---|---|
| Frozen train | −2.76pp | 100% / 19.2% | 1,076 days |
| Frozen test | +6.23pp | 100% / 50.0% | 380 days |
| Cohort (`holdout_2026_v20261024`, default rows) | **+17.17pp** | 100% / 41.1% | 92 days |
| Cohort, all rows (incl. version-transition) | +18.08pp | 100% / 41.1% | 95 days |

Gap = negatives' `cvss_cna_missing` rate minus positives', at landmark-row
level. The frozen rows are the default export (no version-transition
rows), so the cohort's comparable figure is its default rows. Run
2026-10-24: `uv run python -m scripts.eda.enrichment_gap --cohort
holdout_2026_v20261024`, which now reads `training.holdout_2026`.

## The cohort as built (2026-10-24)

`training.holdout_2026`, `dataset_version = holdout_2026_v20261024`, built
by `scripts/features/build_holdout_cohort.py`.

- **Population:** CVEs published 2026-03-25 through 2026-09-21 (the cutoff
  minus 30 days, so every landmark falls by the cutoff).
- **Feature rules:** unchanged (`build_landmark_dataset.build()`).
- **Labels:** censored at **2026-10-21**, the as-of date of the refresh's
  NVD, KEV and EPSS steps.
- **Follow-up:** each row stores `followup_days` = 2026-10-21 − as_of_date.
  The 180-day minimum is **not** applied at build; it is applied at
  evaluation.
- **Overlap guarantee:** no CVE is shared with `training.training_dataset`.
  This is enforced by constraint triggers on both tables and tested in
  `tests/test_leakage/test_holdout_cohort.py`. The same file runs the
  feature allowlist and the leakage rules against the stored rows.

**No model has been evaluated on the cohort.** No metric computed from it
exists.

| | Default rows (no version-transition rows) | All rows |
|---|---|---|
| Rows | 153,005 | 165,832 |
| CVEs | 53,130 | 55,292 |
| KEV events (rows) / event CVEs | 100 / 50 | 115 / 53 |
| Censoring rate (rows) | 99.93% | 99.93% |
| Day 7: rows / events | 53,130 / 50 | 55,292 / 53 |
| Day 14: rows / events | 51,508 / 33 | 55,276 / 37 |
| Day 30: rows / events | 48,367 / 17 | 55,264 / 25 |
| Follow-up, days (min / q1 / median / q3 / max) | 0 / 37 / 70 / 133 / 203 | 0 / 41 / 78 / 130 / 203 |
| Rows with ≥ 180 days follow-up / events in them | 9,924 / 9 | 9,924 / 9 |
| EPSS model at as_of: v2026.06.15 / v2025.03.14 | 111,236 / 41,769 | 124,051 / 41,781 |
| Age at NVD fetch, days (min / q1 / median / q3 / max) | 32 / 59 / 92 / 149 / 211 | 32 / 62 / 95 / 148 / 211 |

The 12,827 version-transition rows (15 events) are rows whose window
contains the 2026-06-15 EPSS release, which is now in the transition list.

Two facts that any evaluation has to plan for. Neither is a result.

1. **Under the 180-day rule the cohort is very small.** Only CVEs
   published by 2026-04-24 have it: 9,924 rows and **9 events**. An
   evaluation at the study's own follow-up standard has almost no events.
   A shorter horizon has to be chosen, and justified, before evaluation.
2. **Most cohort rows are scored under an EPSS model the frozen models
   never saw.** 72.7% of default rows have
   `epss_model_version_at_asof = v2026.06.15`. Every training row predates
   that release, so for the frozen models this is an unseen category, and
   EPSS's own percentile scale changed at the release.

## Finding: the cohort's CNA-CVSS gap is larger than test's (2026-10-24)

**Recorded before any model was evaluated on the cohort, as this protocol
requires.**

| | Gap | 95% interval (2,000 whole-CVE resamples, seed 20260922) | Positive CVEs missing a CNA CVSS |
|---|---|---|---|
| Frozen test | +6.23pp | −1.79 to +13.36 | 15 of 108 |
| Cohort (default rows) | **+17.17pp** | **+10.03 to +22.08** | **3 of 50** |

- **Size.** The cohort's gap is about 2.8× test's. Its interval excludes
  test's point estimate. The two intervals overlap only between +10.0 and
  +13.4. The cohort has 50 positive CVEs, and only 3 of them lack a CNA
  score, so the cohort figure is imprecise. It is still a material
  difference, not noise around +6.23pp.
- **Direction.** It runs **against the expected direction** recorded
  above. Less enrichment maturity was expected to leave less residual
  signal; the cohort shows more. So the premise that "a cohort result that
  holds is stronger evidence than test" does not hold for this feature.
  The cohort is not a harder evaluation for `cvss_cna_missing`. If
  anything, that feature separates positives from negatives more strongly
  on the cohort than on test.
- **vulnStatus.** NVD analysis status shows the same enrichment pattern,
  less extreme for negatives than on test: 100% of positive rows are
  `Analyzed` against 41.1% of negative rows (test: 50.0%). `vulnStatus` is
  not a feature.
- **Causes, not yet tested.** Three are open:
  1. The CNA composition of the cohort's positives. The test gap was
     examined this way with `--by-cna`, which does not yet run on the
     cohort.
  2. CNA scores added after publication but before the October fetch, and
     preferentially for positives. This is the timing leak the
     2026-10-23 as-of check measured on test (`docs/STATUS.md`, "as-of
     error rate of `cvss_cna_missing`"). There the errors fell mostly on
     negatives.
  3. Chance, given 50 positive CVEs.

**Gate (added).** Before any model is evaluated on the cohort:

1. Run the as-of check of CNA-CVSS presence on the cohort's positives and
   a negative sample: cvelistV5 history, the 2026-10-23 method.
2. Run the CNA-stratified gap on the cohort.
3. Record both here.

If the gap is a timing artefact, `cvss_cna_missing` must be recomputed as
of each landmark for the cohort before any comparison that uses it. The
comparability rule above stands either way.
