# api/

Read-only FastAPI service over the frozen artifacts in `models/`, reading
from Postgres. **Ranks by Cox, explains by fuzzy rules**
(`docs/fuzzy_layer.md`, Conclusion). Nothing is fit at request time.

Run: `uv run uvicorn api.main:app` (docs at `/docs`).

| Endpoint | Returns |
|---|---|
| `GET /cve/{id}` | CVE metadata, CVSS metrics, CWEs, KEV entry, EPSS history; per landmark (7/14/30): Cox partial hazard, `cox_risk_pct`, survival curve (days 1-365 after the landmark), fuzzy priority and the rules that fired; and why any landmark has no row |
| `GET /watchlist?budget=0.10` | Top `budget` of test-period landmark rows **by Cox partial hazard**, each with its fuzzy explanation and `epss_ranks_low` (outside EPSS's own top `budget`, the blind-spot definition). Optional `landmark_day`, `limit`, `offset` |
| `GET /backtest` | Corrected-encoding test results (`models/backtest_corrected_encoding.json`, from `scripts/evaluate/backtest_export.py`): model table, paired vs EPSS, blind-spot rates, fuzzy vs references, recall-at-budget curve |
| `GET /model` | Frozen Cox/RSF/XGBoost metadata and test metrics, percentile-reference and serving-preprocessing metadata, the fuzzy rule base and cut-offs, known issues |

Files:

- `artifacts.py`: loads the frozen model, the percentile reference, the
  fuzzy config and the imputation medians once.
- `scoring.py`: request-time scoring.
- `db.py`: queries.
- `schemas.py`: pydantic response models.

The watchlist pool is the historical test period, scored once per process.
`kev_date_added` is therefore retrospective.

Serving uses `scripts/evaluate/features.py::encode_for_model`, not the
batch `one_hot` used at freeze time (see docs/STATUS.md, test-time encoding
addendum). Its Cox scores reproduce the fit-time scores exactly on all
training rows, and they differ from the recorded test evaluation for
84,684 test rows.

Probabilities are under-dispersed, so survival curves are for ordering,
not calibrated risk.
