# dashboard/

A local demo dashboard (React 18 + Vite + Recharts) over the read-only API
in `api/`. No auth; it binds to 127.0.0.1 only.

**Design decision shown throughout the UI: the system RANKS by Cox and
EXPLAINS by fuzzy rules.** On test, the fuzzy layer did no better than a
linear blend of its inputs and was worse than Cox at recall@10%
(`docs/fuzzy_layer.md`, `docs/results_corrected_encoding.md`). Every
ordering here is therefore the frozen Cox partial hazard. Fuzzy priority
and fired rules appear only as the explanation.

## Run

```sh
uv run uvicorn api.main:app --host 127.0.0.1 --port 8000   # from the repo root
cd dashboard && npm install && npm run dev                    # http://127.0.0.1:5173
```

Vite proxies `/api/*` to the API, so there is no CORS setup.

## Views

- **CVE lookup** (`#/cve/CVE-…`): the EPSS percentile trajectory overlaid
  with Cox's cumulative P(KEV) curve from each landmark; Cox risk
  percentile per landmark; the fuzzy priority with each fired rule and its
  strength (rules that never move the score are tagged "explanation
  only"); and CVSS/CWE context with the CVE's own CNA highlighted.
- **Blind-spot watchlist** (`#/watchlist`): the top budget (1/5/10/20%)
  of test-period rows by Cox. Rows outside EPSS's own top budget are
  highlighted as EPSS blind spots. KEV dates are retrospective.
- **Backtesting** (`#/backtest`): the corrected-encoding test results
  (`GET /backtest`). This is the model comparison with CIs, the paired
  difference vs EPSS, blind-spot rates, the recall-at-budget curve, and
  the fuzzy-vs-reference table.

Cox's survival probabilities are under-dispersed (see the calibration
note in `docs/model_comparison.md`). Read the curves for their shape and
rank, not their height.
