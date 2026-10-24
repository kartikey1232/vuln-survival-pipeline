# Fuzzy ranking layer

> **Computed with the test-time encoding bug.** Every test number in
> this document was computed with an encoding that mis-encoded 84,684 test
> rows (a category given as the training reference category). The tables
> are kept as originally recorded. **Corrected numbers, from the same frozen
> models with nothing refit: [`docs/results_corrected_encoding.md`](results_corrected_encoding.md).**
> The design (cut-offs, rules, blend) was
> unaffected. No conclusion changed: fuzzy still doesn't beat the linear
> blend, and it loses to Cox by more (recall@10% −9.7pp; blind-spot −0.131,
> now significant).

A Mamdani fuzzy layer that turns four inputs into a 0-100 patching
priority, with the firing strength of every rule stored per row as the
explanation. Code: `scripts/fuzzy/` (`fuzzy_layer.py` inference,
`design.py` validation-only design, `evaluate_fuzzy.py` one-time test
evaluation). Frozen design: `models/fuzzy_config.json`.

**All design was fixed on validation before test was evaluated.** Every
cut-off, the rule base, the rule weights, the tie-break and the
linear-blend reference were chosen with validation rows only: the train
split published 2024-07-01..2024-12-31, the same 53,674 rows / 55 events
as `data_splits.load_splits().val`. They were committed in `7177bf8`.
`evaluate_fuzzy.py` then ran once on test, and nothing was changed after
it ran. No model was retrained: Cox is the frozen `models/cox_final.pkl`.

## Caveat: validation is in-sample for Cox

The frozen Cox model was refit on the full train set (per CLAUDE.md rule
4), and that set contains the validation rows. So `cox_risk_pct` is
in-sample on validation: Cox's validation C-index is 0.859, against 0.849
on test. The cut-offs don't use labels (they are input quantiles), so they
aren't affected. Anything fitted to validation labels leans on an
optimistic Cox, though: the linear blend's weights, and the validation
metrics used to sanity-check the rule base. Only the test numbers below are
out-of-sample.

## Inputs

| Input | Source | Range |
|---|---|---|
| `cox_risk` | `cox_risk_pct`: frozen Cox partial hazard as a percentile of the training-period distribution of its own landmark (`scripts/fuzzy/risk_percentile.py`) | 0-1 |
| `epss` | `epss_pct_now` | 0-1 |
| `cvss` | CNA-supplied CVSS base score (own-CNA source rule, see `docs/enrichment_leakage.md`), **unimputed** | 0-10 |
| `cvss_missing` | `cvss_cna_missing` (33.66% of rows), a crisp input | {0, 1} |
| `blindspot` | `cox_risk - epss` | -1..+1 |

**`blindspot = 0` does not mean agreement.** The two percentiles have
different reference populations. Cox's is training landmark rows; EPSS's
is every CVE that EPSS scores on that day, in which young CVEs rank low.
The median validation blindspot is +0.24, so its three sets are anchored
on validation quantiles like the other inputs, not on zero.

## Membership functions (validation quantiles)

`cox_risk` and `epss` each get four sets anchored at the validation 30th,
60th, 85th and 95th percentiles. Adjacent sets cross at 0.5 and the
memberships sum to 1 everywhere. The gaps between set peaks shrink towards
the top (30, then 25, then 10 quantile points), where the budget is spent.

| Set | Shape | `cox_risk` | `epss` |
|---|---|---|---|
| Low | trapmf, saturates at the bottom | [0, 0, 0.2616, 0.4783] | [0, 0, 0.1020, 0.1634] |
| Medium | trimf | [0.2616, 0.4783, 0.7936] | [0.1020, 0.1634, 0.2766] |
| High | trimf | [0.4783, 0.7936, 0.8990] | [0.1634, 0.2766, 0.4174] |
| VeryHigh | trapmf, saturates at the top | [0.7936, 0.8990, 1, 1] | [0.2766, 0.4174, 1, 1] |
| *AtLeastMedium* | cumulative = Medium + High + VeryHigh | [0.2616, 0.4783, 1, 1] | (unused) |
| *AtLeastHigh* | cumulative = High + VeryHigh | [0.4783, 0.7936, 1, 1] | (unused) |

Validation quantiles behind them:

| Quantile | 30th | 60th | 85th | 95th |
|---|---|---|---|---|
| `cox_risk_pct` | 0.2616 | 0.4783 | 0.7936 | 0.8990 |
| `epss_pct_now` | 0.1020 | 0.1634 | 0.2766 | 0.4174 |

For comparison, the 95th percentile on test is 0.912 for `cox_risk_pct`
and 0.459 for `epss_pct_now`, while the test medians sit well below the
validation ones (0.280 vs 0.405 for `cox_risk_pct`, 0.109 vs 0.135 for
`epss_pct_now`). Validation was used as the reference because training
percentiles are uniform by construction and test can't be used for design.

`blindspot` (validation 10th / 50th / 90th percentiles: -0.0501 / 0.2401 / 0.5883):

| Set | Shape | Points |
|---|---|---|
| EPSSHigher | trapmf | [-1, -1, -0.0501, 0.2401] |
| Agrees | trimf | [-0.0501, 0.2401, 0.5883] |
| ModelHigher | trapmf | [0.2401, 0.5883, 1, 1] |

`cvss` uses the standard NVD severity bands, not quantiles, so the terms
mean what an analyst expects. Each ramp is 0.1 wide and ends at the band
boundary, so every real (one-decimal) score belongs fully to exactly its
NVD band: 3.9 is Low, 4.0 Medium, 6.9 Medium, 7.0 High, 8.9 High, 9.0
Critical.

| Set | Points |
|---|---|
| Low | [0, 0, 3.9, 4.0] |
| Medium | [3.9, 4.0, 6.9, 7.0] |
| High | [6.9, 7.0, 8.9, 9.0] |
| Critical | [8.9, 9.0, 10, 10] |

Output `priority` (0-100): VeryLow trapmf [0, 0, 10, 30], Low trimf
[10, 30, 50], Medium trimf [30, 50, 70], High trimf [50, 70, 90], Critical
trapmf [70, 90, 100, 100].

Inference: Mamdani, min for AND, max aggregation, clipping, centroid
defuzzification, all via `skfuzzy.control`. Firing strengths are recorded
from skfuzzy's own `compute_rule`, not recomputed.

## Rule base

All weights are 1.0. Validation has 55 events, and one event is worth
1.8pp of recall, so a search over weights would fit noise. None was run.

| ID | Rule | Effect on score |
|---|---|---|
| R01 | IF cox_risk is VeryHigh THEN Critical | |
| R02 | IF cox_risk is High AND epss is Low THEN High — **thesis rule** | explanation only (bounded by R09) |
| R03 | IF blindspot is ModelHigher AND cvss is Critical THEN Critical | |
| R04 | IF cox_risk is High *or above* AND epss is High THEN Critical | |
| R05 | IF cox_risk is Medium *or above* AND cvss is Critical THEN High | |
| R06 | IF cox_risk is Low AND epss is Low AND cvss is not Critical THEN VeryLow | |
| R07 | IF cox_risk is Low THEN Low | backbone |
| R08 | IF cox_risk is Medium THEN Medium | backbone |
| R09 | IF cox_risk is Medium *or above* THEN High | backbone |
| R10 | IF epss is VeryHigh THEN High | |
| R11 | IF cox_risk is High *or above* AND epss is VeryHigh THEN Critical | |
| R12 | IF cox_risk is Medium *or above* AND epss is High THEN High | |
| R13 | IF epss is High THEN Medium | |
| R14 | IF cox_risk is High *or above* AND cvss is Critical THEN Critical | |
| R15 | IF blindspot is Agrees AND cox_risk is Medium AND epss is Medium THEN Medium | explanation only (bounded by R08) |
| R16 | IF cvss is Missing AND cox_risk is Low AND epss is Low THEN Low — **missing path** | explanation only (bounded by R07) |
| R17 | IF blindspot is EPSSHigher AND cox_risk is Low THEN Low | explanation only (bounded by R07) |

Every rule that mentions `cvss` (R03, R05, R06, R14) also requires
`cvss_missing = no`.

**Missing CVSS path.** A row with no CNA score can't fire any severity
rule, in either direction. It can't get the VeryLow cut (R06), and it gets
R16 instead, so unknown severity is neither cut nor boosted. Tested on a
grid: a missing row never ranks below the same row with any non-Critical
CNA score, never above the same row with a Critical one, and its
placeholder CVSS value is inert.

### Changes from the brief, and why

The six required rules are all present. Four of them were widened from
"cox_risk is X" to "cox_risk is X or above": R04, R05, the backbone R09,
and the analogous R11, R12 and R14. R13 was replaced. The reason is
**monotonicity**. The grid test showed that the literal version lowered
priority as cox_risk rose, by up to 0.8 points. Centroid defuzzification
with max aggregation is not monotone just because each rule is. Three
mechanisms were found and fixed:

1. **Two rules on adjacent cox levels with the same consequent.** Take
   "High AND epss VeryHigh → Critical" and "VeryHigh → Critical". As
   cox_risk crosses from High to VeryHigh, the consequent's activation is
   max(fading, rising), which dips to 0.5 where the two cross. Fix:
   cumulative "or above" terms, which are exactly the sum of the sets at
   and above a level and never fall.
2. **A backbone High rule that fades** while Critical is held up by an
   EPSS-capped rule. Mass leaves High and Critical doesn't rise to replace
   it.
3. **High still rising after an EPSS-capped Critical rule has hit its
   cap**, with the centroid already above High's peak of 70. This one
   showed up only on a dense grid (cox step 0.001), as dips of 0.003
   points. Fix: R09 fires from cox_risk Medium upward, so High saturates
   before any capped Critical rule starts to rise.

The old R13 ("blindspot EPSSHigher AND epss High → Medium") weakens as
cox_risk rises while its consequent sits mid-scale. It became the EPSS
floor "epss High → Medium". EPSSHigher moved to R17, whose consequent is
at the bottom.

**Consequence: the thesis rule R02 doesn't change the score.** R02 is
always bounded by R09 (same consequent, and R02's firing ≤ R09's), so under
max aggregation it never moves priority. Its effect is carried by the
backbone. It still fires, on 15% of validation rows, and it is what the
dashboard shows for a row the model ranks above EPSS. The same holds for
R15, R16 and R17. `test_explanation_only_rules_never_change_priority`
checks this by deleting those rules and confirming priority is identical.

`design.py` refuses to write a config that fails the dense check (cox
step 0.001 × 101 epss values × 4 CVSS bands + missing). The frozen
config's worst step is 0.0.

### Ties and the tie-break

The centroid output is flat wherever every firing set is saturated.
**70.6% of validation rows share their exact priority with another row**,
including at the top: 2,735 validation rows (5.1%) tie at the maximum
plateau of 79.52. Recall at a budget that cuts through a tie block would
then depend on row order. So the ranking used for every metric is priority
first, ties broken by `cox_risk_pct`, then `epss_pct_now`
(`fuzzy_layer.ranking_score`). This was adopted because a ranking needs a
total order, not because it scored better. It means that **at budgets up
to about 5%, the fuzzy ranking is mostly the `cox_risk_pct` ordering**.

## Linear-blend reference (c)

A Cox PH model (lifelines, unpenalized) fitted on validation, on
`cox_risk_pct`, `epss_pct_now`, CVSS/10 (0 when missing) and
`cvss_cna_missing`. `blindspot` is not a separate column because it equals
`cox_risk_pct - epss_pct_now` exactly: any weight on it is already
expressible through the other two. Fitted coefficients:

| cox_risk_pct | epss_pct_now | cvss/10 | cvss_cna_missing |
|---|---|---|---|
| 2.646 | 3.068 | 8.326 | 6.479 |

A missing score is worth about the same as a CNA score of 7.8.

A first fit with `penalizer=0.01` shrank every weight towards zero, and
its validation C-index (0.800) came out below Cox alone. lifelines applies
the penalty to the per-row mean log-likelihood, and 55 events in 53k rows
give that almost no curvature. The unpenalized fit was used. This was
decided on validation.

## Validation sanity check (in-sample for Cox; not the result)

| Ranking | C-index | Recall@1% | Recall@5% | Recall@10% | Blind-spot catch @10% |
|---|---|---|---|---|---|
| Fuzzy | 0.858 | 0.236 | 0.473 | 0.691 | 0.485 |
| Cox | 0.859 | 0.255 | 0.527 | 0.673 | 0.455 |
| EPSS | 0.672 | 0.236 | 0.236 | 0.400 | — |
| Linear blend | 0.862 | 0.255 | 0.545 | 0.673 | 0.606 |

55 events; every CI is roughly ±0.2 on recall (see `models/fuzzy_config.json`).

## Test evaluation (run once, after the design commit)

> Original encoding. Corrected tables: [`results_corrected_encoding.md`](results_corrected_encoding.md#fuzzy-layer-vs-references-corrected).
> That re-run is a correctness fix, not a redesign: the design file is unchanged.

178,756 rows, 60,962 CVEs, 268 events. All numbers come from
`scripts/evaluate/common.py`: seed 20260922, 200 whole-CVE resamples, the
same resamples for every ranking. Raw output is in
`scratch/fuzzy_evaluation.json`.

| Ranking | C-index [95% CI] | Recall@1% | Recall@5% | Recall@10% | Blind-spot catch @10% |
|---|---|---|---|---|---|
| **Fuzzy** | 0.844 [0.805, 0.878] | 0.216 [0.150, 0.288] | 0.429 [0.350, 0.533] | 0.552 [0.459, 0.632] | 0.200 [0.113, 0.298] |
| (a) Cox | 0.849 [0.809, 0.886] | 0.224 [0.152, 0.290] | 0.485 [0.383, 0.579] | 0.623 [0.520, 0.714] | 0.310 [0.176, 0.426] |
| (b) EPSS | 0.750 [0.687, 0.804] | 0.190 [0.130, 0.251] | 0.369 [0.282, 0.469] | 0.459 [0.374, 0.544] | 0 (by definition) |
| (c) Linear blend | 0.836 [0.787, 0.872] | 0.205 [0.138, 0.271] | 0.478 [0.387, 0.566] | 0.590 [0.498, 0.662] | 0.317 [0.201, 0.434] |

Paired differences, fuzzy minus reference (point [95% CI]; **bold** = CI
excludes 0):

| vs | C-index | Recall@1% | Recall@5% | Recall@10% | Blind-spot @10% |
|---|---|---|---|---|---|
| (a) Cox | -0.005 [-0.010, +0.001] | -0.007 [-0.033, +0.020] | -0.056 [-0.111, +0.010] | **-0.071 [-0.119, -0.010]** | -0.110 [-0.200, +0.000] |
| (b) EPSS | **+0.094 [+0.060, +0.133]** | +0.026 [-0.025, +0.078] | **+0.060 [+0.031, +0.103]** | **+0.093 [+0.033, +0.153]** | +0.200 (EPSS is 0) |
| (c) Linear blend | +0.008 [-0.009, +0.030] | +0.011 [-0.035, +0.059] | -0.049 [-0.124, +0.024] | -0.037 [-0.126, +0.044] | -0.117 [-0.238, +0.000] |

### Reading

- **Against the linear blend, the deciding reference: a null result.** No
  paired difference excludes zero at any budget, and the point estimates
  at 5% and 10% favour the blend. Fuzzy inference does not earn its place
  as a *ranking* method here. Its case is interpretability: a per-row,
  rule-level explanation that the blend's four coefficients don't give.
- **Against Cox alone, fuzzy is worse.** Recall@10% is 7.1pp lower and
  the CI excludes zero. Every other difference is negative or flat. The
  blind-spot catch rate falls from 0.31 to 0.20 (CI upper bound +0.0004,
  so only just not significant). *Corrected encoding: 0.34 vs 0.21,
  −0.131 [−0.229, −0.024], which now excludes zero.* Adding EPSS and CVSS through rules made
  the Cox ranking worse at the budgets that matter. This is consistent
  with rules R10, R12 and R13, which lift rows that EPSS already rates
  highly, displacing exactly the rows EPSS misses. It is consistent with
  that, not proven by it.
- **Against EPSS alone, fuzzy is clearly better** (C-index +0.094, and
  recall@5% and @10%), as expected from a layer built on Cox.
- **The blend also falls below Cox on test** (0.836 vs 0.849), though it
  scored 0.862 vs 0.859 on validation. With 55 validation events and an
  in-sample Cox, its weights didn't transfer.
- **At 1% and 5% the fuzzy ranking is really the tie-break.** On test the
  top plateau (priority 79.52) holds 10,750 rows (6.0%), more than the
  whole 5% budget. So the top 1% and 5% contain one distinct priority
  value and are ordered entirely by `cox_risk_pct`, then `epss_pct_now`.
  77% of test rows share their priority with another row. Fuzzy@1% ≈
  Cox@1% for that reason, not because the rules discriminate there.
  VeryHigh saturating at the validation 95th percentile, as the brief
  asked, is what flattens the top.

### Explanations

`data/training/fuzzy_priority.parquet` (validation + test rows,
regenerable) holds, per row:

- the inputs, `priority`, and `fuzzy_rank_score`;
- `fire_R01..fire_R17`, each rule's firing strength (antecedent degree,
  before weight);
- `rules_fired`, e.g. `R09=0.83; R01=0.17; R17=0.05`.

The thesis rule R02 fires on 7.9% of test rows.

## Conclusion

Figures below are as originally recorded. Under corrected encoding: recall@10% is 0.534 vs 0.631,
and blind-spot catch is 0.21 vs 0.34 (CI now excludes zero). See
[`results_corrected_encoding.md`](results_corrected_encoding.md).

**Fuzzy inference does not improve ranking over a linear blend of the
same inputs.** No paired difference between the fuzzy ranking and the
validation-fitted blend excludes zero, at any budget or on C-index. The
fuzzy ranking also **underperforms Cox alone**:

- recall@10%: 0.552 vs 0.623 (paired difference −0.071, CI excludes zero);
- blind-spot catch rate at 10%: 0.20 vs 0.31.

What the layer contributes is **per-row interpretability**: for every row,
which rules fired and at what strength (`fire_R01..fire_R17`,
`rules_fired`).

**The system therefore RANKS by Cox and EXPLAINS by fuzzy rules.** The
watchlist and every budget-based ordering use the frozen Cox partial
hazard. The fuzzy priority and its fired rules are shown alongside as the
explanation, never as the ordering.

The layer is final as frozen in `models/fuzzy_config.json`. Test has been
seen, so any change now would be tuning against test results. **A
redesign would require a fresh validation period**, for example data
published after the current 2026-09-20 cutoff, with the test period
re-defined after it.

### Limitations

1. **Validation is in-sample for Cox.** The frozen Cox model was refit on
   the full train set, which contains the validation rows. The blend
   weights and all validation metrics are therefore optimistic. The
   cut-offs are label-free input quantiles and are not affected.
2. **The top of the ranking is one tie.** VeryHigh saturates at the
   validation 95th percentile, which puts about 6% of test rows (10,750) on
   one score (79.52). The top 1-5% is therefore ordered by the tie-break
   (`cox_risk_pct`, then `epss_pct_now`), not by the rules.
3. **R02, the thesis rule, is subsumed by R09** (same consequent, and
   R02's firing ≤ R09's), so it doesn't affect the score. It still fires
   and is shown as an explanation.
4. **Rule weights were left at 1.0.** 55 validation events (one event =
   1.8pp of recall) cannot support a weight search.

### Candidate changes for future work (fresh validation period required)

- Put EPSS's raw score on the same reference distribution as Cox (the
  training-period landmark rows), so that `blindspot = 0` means agreement.
- Break the top-end tie: for example, saturate VeryHigh higher, or add a
  level above it, so the rules discriminate within the top 5%.
- Whether dropping or weakening the rules that lift EPSS-high rows (R10,
  R12, R13) closes the gap to Cox.

### Observations for the redesign: CVE-2023-21716 (2026-10-23)

These come from a dashboard inspection of CVE-2023-21716 (Microsoft Word
RCE, train split, fit period, CNA CVSS 9.8, not KEV-listed). They are
inputs to the redesign, not changes to the frozen layer. The numbers are
from `GET /cve/CVE-2023-21716` and from re-scoring with the frozen config.
(The holdout protocol has no registered-experiment entry yet, so they are
recorded here.)

**1. A concrete instance of the 79.52 top-end tie.**

| Landmark | `cox_risk_pct` | `epss_pct_now` | Priority |
|---|---|---|---|
| Day 7 (2023-02-21) | 0.9949 | 0.6096 | 79.52381 |
| Day 14 (2023-02-28) | 0.9978 | 0.7556 | 79.52381 |

This is the known maximum plateau (79.52). Every set that fires is
saturated at both landmarks:
- `cox_risk` VeryHigh = 1 (above 0.8990).
- `epss` VeryHigh = 1 (above 0.4174).
- `cvss` Critical = 1.

R01, R05, R09, R10, R11 and R14 fire at 1.0 at both landmarks. R03 drops
from 0.417 to 0.006, but Critical is already held at 1.0 by R01/R11/R14
under max aggregation, so that drop cannot move the score. The ranking is
unchanged too, because ties are broken by `cox_risk_pct`.

**2. The EPSS input saturates far below the top of its scale.**
- **Input:** `epss` is `epss_pct_now`, EPSS's own percentile in [0, 1]
  (rank among all CVEs EPSS scores that day). It is **not** the raw
  probability, which for this CVE was 0.01156 on day 7. The universe is
  [0, 1].
- **Sets:** Low trap [0, 0, 0.1020, 0.1634]; Medium tri [0.1020,
  0.1634, 0.2766]; High tri [0.1634, 0.2766, 0.4174]; VeryHigh trap
  [0.2766, 0.4174, 1, 1].
- **Saturation:** VeryHigh starts rising at the 27.7th EPSS percentile and
  **reaches 1.0 at the 41.7th EPSS percentile**. That is the 95th
  percentile of *validation landmark rows*, because young CVEs rank low in
  EPSS's population. This is why R10 fires at 1.00 with EPSS at the 61st
  percentile.
- **Flag:** on EPSS's own scale, VeryHigh saturates well below the 90th
  percentile. Every row above the 41.7th EPSS percentile gets the same EPSS
  memberships, so EPSS cannot discriminate among them.

**3. This CVE shows the EPSS saturation is not the binding cause of the
top tie. Cox saturation is.** Re-scoring with this CVE's `cox_risk_pct`
and CVSS fixed, and only `epss_pct_now` varied:

| `epss_pct_now` | 0.00 | 0.10 | 0.1634 | 0.2766 | 0.35 | 0.4174 | 0.61 | 1.00 |
|---|---|---|---|---|---|---|---|---|
| Priority (cox 0.995) | 79.52 | 79.52 | 79.52 | **69.67** | **72.06** | 79.52 | 79.52 | 79.52 |

The same holds at `cox_risk_pct` 0.85. Once `cox_risk` is VeryHigh and
CVSS is Critical, the Critical and High consequents are already at 1.0
from Cox and CVSS rules alone. So EPSS cannot raise the priority whatever
its value, and moving VeryHigh's saturation point higher would not by
itself break this tie. What binds is `cox_risk` VeryHigh saturating at 0.899,
together with max aggregation. Breaking the tie needs discrimination
there.

**4. Priority is not monotone in EPSS.** The table above shows a **dip of
up to 9.9 points** where EPSS is High (peak at 0.2766). The cause is R13
("epss is High → Medium"): it adds Medium mass that drags the centroid
down, and it switches off again once EPSS reaches VeryHigh. So a CVE at
the 28th EPSS percentile scores *below* the same CVE at the 0th or the
61st. The design's monotonicity check (`design.py`) sweeps `cox_risk` at
fixed EPSS values. It does not test monotonicity *in EPSS*, which is why
this passed. R13 is not the only cause; see "Monotonicity defect" below
for the full per-input sweep.

**5. No exploit-availability contribution.** CVE-2023-21716 has **no
Exploit-DB entry** in `canonical.exploitdb_cve_map`, nor in the raw
`staging.exploitdb_raw` codes or descriptions (snapshot fetched
2026-08-07; the Exploit-DB refresh has not run). Its rows have
`exploit_published_by_asof = False` and `days_to_first_exploit = null` at
both landmarks. Exploit features are Cox inputs, not fuzzy inputs, so they
contributed nothing to its `cox_risk_pct` either. The 99.5 → 99.8 move
comes from the time-varying Cox inputs: `landmark_day` and the EPSS
features (`epss_pct_now` went from 0.61 to 0.76). It was not decomposed
further.

### Monotonicity defect: priority is not monotone in EPSS (2026-10-23)

**The shipped design's monotonicity check varied only `cox_risk`.**
`fuzzy_layer.worst_cox_monotonicity_step`, which `design.py` enforces,
sweeps `cox_risk` on a dense grid with EPSS, the CVSS band and
missingness held fixed. It never varies any other input. "Monotone" in
"Changes from the brief" above therefore means monotone *in cox_risk*.
**Priority is demonstrably non-monotone in EPSS.** R13 ("epss is High →
Medium") is the largest cause (observation 4 above), but not the only one.

**Sweep.** `python -m scripts.eda.fuzzy_monotonicity` re-scores the frozen
`models/fuzzy_config.json` (nothing is changed). It moves each input over
its full range in steps of 0.001 (0.01 for CVSS), with the other inputs
held at representative values:
- `cox_risk` ∈ {0.10, 0.30, 0.50, 0.70, 0.85, 0.95, 0.99}
- `epss` ∈ {0.05, 0.13, 0.20, 0.30, 0.45, 0.70, 0.95}
- CVSS ∈ {2.0, 5.5, 8.0, 9.5, missing}
- blindspot ∈ {−0.30, 0, 0.24, 0.50, 0.80}

It runs in two modes. *Shipped*: blindspot = cox_risk − epss, as
`model_inputs` builds it. *Free*: blindspot held fixed, which is the only
way to sweep blindspot itself. The grid is representative, not exhaustive.

| Input swept | Lines | Non-monotone | Worst single step |
|---|---|---|---|
| `cox_risk` (shipped / free) | 35 / 175 | **0 / 0** | 0 |
| `epss` (shipped) | 35 | **30** | −0.224 |
| `epss` (free) | 175 | **152** | −0.224 |
| CVSS, present, 0–10 | 49 | **0** | 0 |
| blindspot (free), −1 to +1 | 245 | **0** | 0 |

**Every non-monotone region is in EPSS.** In each case below, raising
EPSS lowers priority. Drops are peak-to-trough over the falling interval.

1. **R13 (EPSS entering High, about 0.163 → 0.277, up to 0.342).** Drops
   of up to **9.86 points**. The worst lines have `cox_risk` ≥ 0.85 at any
   CVSS, or lower `cox_risk` with Critical CVSS. Priority recovers once
   EPSS reaches VeryHigh (0.4174). Disabling R13 removes most of the
   non-monotone lines: 30 → 11 shipped, 152 → 40 free.
2. **EPSS-capped Critical crossover, R04 → R11 (with R12 → R10 on the High
   consequent).** EPSS about 0.277 → 0.347, at `cox_risk` 0.70–0.85, any
   CVSS. Drops of up to **3.1 points** with R13 disabled. This is
   mechanism 1 of "Changes from the brief" (two rules on adjacent levels
   with one consequent, max(fading, rising)), but in the EPSS dimension.
   R04 and R12 use EPSS **High**, not a cumulative "or above" term, so
   they fade while R11 and R10 (EPSS VeryHigh) rise. The fix applied for
   `cox_risk` was never applied to EPSS.
3. **Blindspot coupling through R03 (shipped mode only).** With Critical
   CVSS at `cox_risk` 0.3–0.7, raising EPSS lowers blindspot (= cox − epss)
   and fades R03 ("blindspot ModelHigher AND cvss Critical → Critical").
   Drops of up to **7.3 points** (cox 0.5, EPSS 0 → 0.24) and 3.8 points
   (cox 0.3, EPSS 0 → 0.06) with R13 disabled. This doesn't occur in free
   mode, so the cause is that blindspot is derived from EPSS.
4. Small residual steps: up to 0.10 points (EPSS 0.277 → 0.301, cox 0.3;
   R10/R13/R17) and up to 0.04 points (EPSS 0.268 → 0.277).

**`cvss_missing` is crisp**, so it has no order to be monotone in. For the
record:
- A missing score gives up to **10.5 points more** than a present
  non-Critical score (2.0, 5.5 or 8.0). R06's cut ("… AND cvss is not
  Critical → VeryLow") applies only to present scores.
- A missing score gives up to **10.4 points less** than a present Critical
  score (no Critical boost).
- So "unknown severity" can rank above a present High (8.0) score at low
  `cox_risk`/EPSS.

**Not fixed.** This is recorded as an input to the redesign. That happens
as a registered experiment under `docs/holdout_protocol.md`, not as an ad
hoc change. A redesign's acceptance check should sweep *every* input, as
this script does, including blindspot's coupling to EPSS.
