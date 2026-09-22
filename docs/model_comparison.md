# Model comparison — landmark KEV prediction

All numbers below are computed on the SAME test set (published >= 2025-01-01,
178,756 rows / 60,962 CVEs / 268 events) through `scripts/evaluate/common.py`,
using `training.training_dataset` (`dataset_version=landmark_v20260922`,
rebuilt after the CVSS/CWE own-CNA-only source fix — see Limitations). Every
model and EPSS-alone go through the identical bootstrap machinery (same seed,
same CVE-level resampling), so comparisons here are apples-to-apples.

Chosen configs (tuned on the fit/val split, never on test):
- **Cox PH**: penalizer=0.1
- **RSF**: min_samples_leaf=50, max_features=log2, n_estimators=200, max_samples=20,000
- **XGBoost-AFT**: aft_loss_distribution=extreme, aft_loss_distribution_scale=1.2, max_depth=6, learning_rate=0.05, n_rounds=272

## Final comparison table (95% bootstrap CI, 200 resamples of whole CVEs)

| Model | C-index | Recall@1% | Recall@5% | Recall@10% |
|---|---|---|---|---|
| EPSS-alone | 0.750 (0.695–0.803) | 0.190 (0.131–0.255) | 0.369 (0.277–0.471) | 0.459 (0.374–0.541) |
| Cox | 0.849 (0.813–0.888) | 0.224 (0.144–0.282) | 0.485 (0.398–0.563) | 0.623 (0.528–0.714) |
| RSF | 0.812 (0.773–0.851) | 0.284 (0.221–0.364) | 0.489 (0.417–0.564) | 0.575 (0.507–0.650) |
| XGBoost-AFT | 0.785 (0.732–0.827) | 0.250 (0.175–0.324) | 0.425 (0.329–0.507) | 0.511 (0.412–0.597) |

**Cox is the strongest model on this test set** — not XGBoost-AFT, despite
XGBoost-AFT having the more elaborate tuning process. This reordering only
appeared after the CVSS/CWE source fix (see Limitations): before that fix,
XGBoost-AFT and RSF both scored higher than Cox, because their tree-based
splits could exploit the CISA-enrichment artifact more aggressively than
Cox's linear model could.

### Paired comparison vs EPSS-alone (same resamples, difference CI)

| Model | ΔC-index (95% CI) | Excludes 0? | ΔRecall@1% | ΔRecall@5% | ΔRecall@10% |
|---|---|---|---|---|---|
| Cox | +0.100 (0.069, 0.136) | **yes** | +0.026 (−0.027, 0.083) — no | +0.116 (0.060, 0.178) — **yes** | +0.158 (0.085, 0.228) — **yes** |
| RSF | +0.063 (0.005, 0.124) | **yes** | +0.091 (0.036, 0.137) — **yes** | +0.122 (0.024, 0.218) — **yes** | +0.117 (0.017, 0.214) — **yes** |
| XGBoost-AFT | +0.037 (−0.027, 0.099) | no | +0.056 (−0.020, 0.135) — no | +0.057 (−0.042, 0.157) — no | +0.052 (−0.062, 0.164) — no |

Cox and RSF both beat EPSS-alone with CIs excluding zero on C-index and
most recall budgets. **XGBoost-AFT's improvement over EPSS-alone is not
statistically distinguishable from zero at any budget** in this paired
test, despite scoring numerically higher — its CIs are wide because it's
the model whose behavior is most sensitive to which specific CVEs the
resample includes (consistent with the trajectory-ablation finding below).

## Per-landmark C-index (point estimates)

| Landmark | EPSS-alone | Cox | RSF | XGBoost-AFT |
|---|---|---|---|---|
| 7 | 0.761 | 0.857 | 0.812 | 0.765 |
| 14 | 0.766 | 0.857 | 0.816 | 0.792 |
| 30 | 0.714 | 0.830 | 0.806 | 0.845 |

## Trajectory ablation (XGBoost-AFT config fixed, reporting only)

| Feature set | C-index | Recall@10% |
|---|---|---|
| a) Full model | 0.785 | 0.511 |
| b) Minus trajectory features (drop `epss_pct_7d_ago`, `epss_pct_7d_ago_missing`, `epss_pct_delta_7d`, `epss_pct_first`, `epss_pct_max_to_date`, `days_to_first_epss`; keep `epss_pct_now`) | 0.814 | 0.571 |
| c) Minus ALL EPSS features | 0.825 | 0.541 |

Paired (a) − (b), same resamples: ΔC-index = −0.029 (95% CI −0.073, 0.007 —
does not exclude zero), **ΔRecall@10% = −0.059 (95% CI −0.112, −0.007 —
excludes zero)**.

**This is a real, counterintuitive finding, not noise**: for this specific
XGBoost-AFT configuration (max_depth=6, fairly deep), the EPSS trajectory
features (7-day-ago percentile, delta, first-observed, running max,
days-to-first-observation) make recall@10% measurably *worse*, and dropping
EPSS entirely does even better than keeping only `epss_pct_now`. The most
likely explanation is overfitting: six correlated, somewhat noisy trajectory
features give a depth-6 tree model many ways to find spurious splits, while
`cna_kev_rate_expanding` and CVSS carry most of the real signal (matching
RSF's permutation importances, where `cna_kev_rate_expanding` and
`cvss_base_score` rank far above any EPSS feature). This does not mean EPSS
trajectory is worthless — Cox (linear, less prone to this failure mode)
still benefits from the full feature set — but it's a concrete reason not to
treat XGBoost-AFT's current tuning as final.

## Blind-spot catch rate at 10% budget

Among test positives that EPSS-alone does NOT place in its own top 10%
(i.e., cases EPSS misses), what fraction does each model catch in *its*
top 10%:

| Model | Catch rate (95% CI) |
|---|---|
| Cox | 0.310 (0.176, 0.426) |
| RSF | 0.352 (0.248, 0.488) |
| **XGBoost-AFT** | **0.421 (0.283, 0.535)** |

Interesting reversal from the headline table: **XGBoost-AFT catches the
largest share of EPSS's specific blind spots**, even though its overall
C-index/recall are the weakest of the three. This is plausibly the same
mechanism as the trajectory-ablation finding — non-EPSS signal
(`cna_kev_rate_expanding`, CVSS) is what catches EPSS's misses, and
XGBoost-AFT's tree structure leans on that signal most heavily (at some
cost to overall recall from EPSS-trajectory noise). Worth keeping in mind
if the actual goal is specifically closing EPSS's blind spots rather than
maximizing pooled recall.

## RSF run-to-run variance

Same config (`min_samples_leaf=50, max_features=log2`), 3 different
`random_state` values, refit from scratch each time:

| random_state | Test C-index |
|---|---|
| 0 | 0.8122 |
| 1 | 0.8150 |
| 2 | 0.8184 |

Spread = 0.0062, std = 0.0025. Small relative to the ~0.04–0.10 gaps between
models in the headline table, but real — RSF's own tuning-time config
selection was also observed to be non-reproducible across runs (see
Limitations). Any RSF number in this document should be read as "≈0.81 ±
0.01," not a fixed point value.

![Recall at alert budget](figures/recall_at_budget.png)

## Limitations

- **CVSS/CWE source fix, applied this session**: the original "CNA-sourced"
  filter accepted any metric with `source != nvd@nist.gov`, which
  (unintentionally) admitted CISA's own ADP (Vulnrichment) contributions —
  confirmed via raw payload inspection that source
  `134c704f-9b21-4f2e-91b3-4a467353bcc0` carries
  `ssvcData.role="CISA Coordinator"`. Since CISA runs KEV, CISA choosing to
  enrich a CVE with its own CVSS/CWE is a direct circularity with the label.
  The rule is now "source equals the CVE's own `sourceIdentifier`" (its
  actual reporting CNA). This removed ~18% of accepted CVSS metrics and ~20%
  of accepted CWE mappings and dropped every model's test C-index
  meaningfully (XGBoost-AFT: 0.852→0.785; RSF: 0.839→0.812; Cox: 0.849→0.849,
  essentially unaffected — Cox's linear form apparently couldn't exploit the
  artifact the way the tree models could). All numbers in this document are
  post-fix.
- **Validation-vs-test bias asymmetry, not fully resolved**: even after the
  fix, CVSS-presence still correlates with the label — positives are less
  likely to be missing a CVSS score than negatives, by 2.8pp on train and
  6.2pp on test (both now under the pre-fix 20.9pp/6.0pp gaps, but not
  zero). Because the gap is larger in the earlier (fit/val) era than in the
  test era, validation-set model selection somewhat over-credits this
  residual signal relative to what test shows — treat validation C-index as
  optimistic versus test, always report test numbers as the real answer.
- **`disclosure@vulncheck.com` as a CNA**: this source has the highest
  positive rate (6.5%) among the top-20 CNAs by positive count in train
  (n=46 CVEs, 3 positives). VulnCheck is a vulnerability-intelligence vendor
  whose business is specifically tracking exploited vulnerabilities — CNA
  assignment under that identifier plausibly correlates with "already known
  to be interesting" at the time of CNA assignment. This is different from
  the CISA case: VulnCheck's CVSS/CWE, if assigned before or independent of
  its KEV date, is legitimate publication-time information (a CNA's
  professional judgment about severity, not the KEV-deciding body scoring
  its own future decision) — but it's flagged here because the *n* is small
  and the mechanism (a threat-intel firm as CNA) is different enough from
  ordinary vendor PSIRTs to warrant a closer look before leaning on
  `cna_kev_rate_expanding` without caveat.
- **RSF non-determinism**: despite `random_state=0`, sksurv's
  `RandomSurvivalForest` under `n_jobs=-1` picked a *different* winning
  hyperparameter configuration across two otherwise-identical tuning runs on
  the same data, and test C-index varies by up to 0.0062 across
  `random_state` values at a fixed config (see above). Any RSF result in
  this project should be treated as approximate, not a fixed reproducible
  number, unless `n_jobs=1` is used (untested here, would be much slower).
