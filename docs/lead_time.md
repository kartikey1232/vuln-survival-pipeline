# Lead time: how far ahead of KEV listing each ranking flags a CVE

> **Post-hoc descriptive analysis, not a pre-registered metric.** It was
> defined after test results were known, so it describes the frozen models'
> behaviour. It is not evidence for or against any hypothesis, and nothing
> was selected on it.

`python -m scripts.evaluate.lead_time` → `scratch/lead_time.json`,
`scratch/lead_time_per_cve.csv`.

The analysis uses the frozen Cox model and EPSS-alone (`epss_pct_now`) on
the default test set (corrected encoding; the script refuses to run unless
Cox reproduces its recorded C-index 0.850085). Nothing is fit.

## Definitions

- **Population:** the 108 test CVEs later KEV-listed. A CVE has a landmark
  row (day 7/14/30) only while it is still unlisted: 73 have all three, 14
  have two and 21 have only day 7.
- **Catch:** a model catches a CVE at a landmark if that row is in the
  model's top 10% of *that landmark's* test rows. This is the same top-k
  rule as `recall_at_budget`, applied per landmark.
- **Lead time:** days from the earliest catching landmark's `as_of_date`
  to the KEV listing. A model that never catches the CVE gets **0** (no
  warning before the listing). Cox's lead over EPSS is
  `lead_cox − lead_epss`, defined for every CVE at least one model caught.
- **Blind-spot subgroup:** listed CVEs that EPSS never placed in its top 10%
  at any of their landmarks.
- **CIs:** a CVE-level bootstrap over the listed CVEs, through
  `common._bootstrap_rows` (seed 20260922, 200 resamples). The top-10%
  thresholds are held fixed.
- **Caveats:**
  - The top-10% thresholds use the whole test period's rows at each
    landmark: a retrospective budget, not one a defender would have had in
    real time.
  - Landmarks are 7, 14 and 30 days, so when both models catch a CVE the
    difference in when they catch it can only be 0, 7, 16 or 23 days.

## Results

Who catches what (108 listed CVEs):

| | EPSS catches | EPSS never catches | Total |
|---|---|---|---|
| **Cox catches** | 54 | **19** | 73 |
| **Cox never catches** | 2 | 33 | 35 |
| Total | 56 | 52 (blind spots) | 108 |

First catching landmark: Cox catches 66 at day 7 and 7 at day 14. EPSS
catches 51 at day 7, 4 at day 14 and 1 at day 30.

**Cox's lead over EPSS**, for the 75 CVEs at least one model caught:

| Statistic | Days | 95% CI |
|---|---|---|
| Median | 0 | (0, 0) |
| IQR | 0 to 2 | 75th percentile CI (0, 27) |
| Mean | +16.9 | (+4.8, +32.3) |

- **When both models catch a CVE, they almost always catch it at the same
  landmark.** That holds for 51 of the 54 both-caught CVEs. Cox is earlier
  for 1 (by 23 days) and later for 2 (by 7 days each). The both-caught
  median difference is 0 with IQR 0 to 0.
- **Cox's lead therefore comes almost entirely from *which* CVEs it
  catches, not from catching shared ones sooner.** 19 CVEs are caught by
  Cox and never by EPSS (CI 12–26); 2 are caught by EPSS only (CI 0–5).
  Most CVEs either model catches have a difference of 0, so the median is
  0. The mean (+16.9 days, CI excluding zero) is carried by the 19 Cox-only
  catches.

**Blind-spot subgroup** (52 listed CVEs EPSS never flags):

| | Value | 95% CI |
|---|---|---|
| Caught by Cox | 19 of 52 (36.5%) | 23.8%–48.9% |
| Cox lead before listing, median | 48 days | (24, 139) |
| Cox lead before listing, IQR | 20 to 147.5 days | |

- Across the 52 blind spots, Cox gives a median of **48 days' warning**
  for the 19 it catches. For these CVEs EPSS gives no warning at its 10%
  budget. Example: CVE-2025-24472 (the dashboard lookup case) is flagged at
  day 7, 28 days before its listing.
- 33 of the 52 blind spots are missed by both models.

For reference, the lead time of each model given it catches the CVE is
nearly identical: Cox median 48 days (IQR 13–127, n=73), EPSS median 48
days (IQR 11–126, n=56). Both mostly catch at day 7. The difference
between the models is in coverage, not timing.

## Summary

At a 10% per-landmark budget, Cox does not warn *earlier* than EPSS on the
CVEs both flag. It warns on **19 more listed CVEs**, all EPSS blind spots,
a median of **48 days** before they are listed. Treat this as a description
of the frozen models on this test period, not as a validated metric.
