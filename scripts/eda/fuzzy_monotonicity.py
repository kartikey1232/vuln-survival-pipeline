"""
Monotonicity of the frozen fuzzy priority in EACH input, one at a time.

The shipped design check (fuzzy_layer.worst_cox_monotonicity_step, enforced
by design.py) sweeps cox_risk only. This sweeps every input over its full
range with the others held at representative values, and reports every
grid line on which priority falls as the input rises, with the interval
where it falls and the rules whose firing changes there. Diagnostic only:
it changes nothing in models/fuzzy_config.json (the redesign happens under
docs/holdout_protocol.md, not ad hoc).

Two modes for the inputs blindspot is derived from:
  shipped  blindspot = cox_risk - epss, as fuzzy_layer.model_inputs builds it
  free     blindspot held fixed, the swept input moves alone (the only way
           to sweep blindspot itself)

Usage: python -m scripts.eda.fuzzy_monotonicity
"""

from __future__ import annotations

import itertools
import json

import numpy as np
import pandas as pd

import scripts.fuzzy.fuzzy_layer as fl
from config.config_schema import get_config

COX = (0.10, 0.30, 0.50, 0.70, 0.85, 0.95, 0.99)
EPSS = (0.05, 0.13, 0.20, 0.30, 0.45, 0.70, 0.95)
CVSS = ((2.0, False), (5.5, False), (8.0, False), (9.5, False), (0.0, True))
BLINDSPOT = (-0.30, 0.00, 0.24, 0.50, 0.80)
TOL = -1e-6  # steps below this count as a decrease


def _grid(swept: str, values: np.ndarray, fixed: list[dict]) -> tuple[dict, list[dict]]:
    cols = {k: [] for k in ("cox_risk", "epss", "cvss", "cvss_missing", "blindspot")}
    for f in fixed:
        for k in cols:
            cols[k].append(values if k == swept else np.full(len(values), f[k], dtype=float))
        if f["derive_blindspot"]:
            cols["blindspot"][-1] = cols["cox_risk"][-1] - cols["epss"][-1]
    return {k: np.concatenate(v) for k, v in cols.items()}, fixed


def sweep(config: dict, swept: str, values: np.ndarray, fixed: list[dict]) -> pd.DataFrame:
    inputs, fixed = _grid(swept, values, fixed)
    priority, firing = fl.score(inputs, config)
    n = len(values)
    out = []
    for i, f in enumerate(fixed):
        p = priority[i * n:(i + 1) * n]
        step = np.diff(p)
        down = np.where(step < TOL)[0]
        row = {k: f[k] for k in f if k != swept}
        row.update({"worst_step": float(step.min()), "monotone": down.size == 0})
        if down.size:
            fr = firing.iloc[i * n:(i + 1) * n].to_numpy()
            moved = np.abs(np.diff(fr, axis=0))[down].max(axis=0) > 1e-9
            row.update({"falls_from": float(values[down.min()]), "falls_to": float(values[down.max() + 1]),
                        "max_drop": float(p[:down.max() + 2].max() - p[down.min():].min()) if down.size else 0.0,
                        "rules_moving": ",".join(np.array(fl.RULE_IDS)[moved])})
        out.append(row)
    return pd.DataFrame(out)


def main() -> None:
    cfg = get_config()
    config = json.loads((cfg.project_root / "models" / "fuzzy_config.json").read_text())
    unit = np.linspace(0, 1, 1001)
    results = {}

    def fixed_sets(over: dict, derive: bool) -> list[dict]:
        keys = list(over)
        return [dict(zip(keys, combo)) | {"derive_blindspot": derive} for combo in itertools.product(*over.values())]

    def with_cvss(rows: list[dict]) -> list[dict]:
        return [r | {"cvss": c, "cvss_missing": float(m)} for r in rows for c, m in CVSS]

    results["cox_risk (shipped)"] = sweep(config, "cox_risk", unit,
                                          with_cvss(fixed_sets({"epss": EPSS, "blindspot": [np.nan]}, True)))
    results["cox_risk (free)"] = sweep(config, "cox_risk", unit,
                                       with_cvss(fixed_sets({"epss": EPSS, "blindspot": BLINDSPOT}, False)))
    results["epss (shipped)"] = sweep(config, "epss", unit,
                                      with_cvss(fixed_sets({"cox_risk": COX, "blindspot": [np.nan]}, True)))
    results["epss (free)"] = sweep(config, "epss", unit,
                                   with_cvss(fixed_sets({"cox_risk": COX, "blindspot": BLINDSPOT}, False)))
    cvss_values = np.round(np.linspace(0, 10, 1001), 4)
    results["cvss (present)"] = sweep(config, "cvss", cvss_values,
                                      [r | {"cvss_missing": 0.0, "cvss": np.nan} for r in
                                       fixed_sets({"cox_risk": COX, "epss": EPSS, "blindspot": [np.nan]}, True)])
    results["blindspot (free)"] = sweep(config, "blindspot", np.linspace(-1, 1, 2001),
                                        with_cvss(fixed_sets({"cox_risk": COX, "epss": EPSS}, False)))

    for name, df in results.items():
        bad = df[~df["monotone"]]
        print(f"\n== {name}: {len(df)} lines, {len(bad)} non-monotone, worst step {df['worst_step'].min():+.3f}")
        if len(bad):
            cols = [c for c in bad.columns if c not in ("monotone", "derive_blindspot", "worst_step")]
            summary = (bad.groupby(["falls_from", "falls_to", "rules_moving"])
                       .agg(lines=("max_drop", "size"), max_drop=("max_drop", "max")).reset_index()
                       .sort_values("max_drop", ascending=False))
            print(summary.to_string(index=False, float_format=lambda v: f"{v:.3f}"))
            print("fixed values on the non-monotone lines:")
            print(bad[cols].drop(columns=["falls_from", "falls_to", "rules_moving"], errors="ignore")
                  .drop_duplicates().to_string(index=False, float_format=lambda v: f"{v:.3f}"))

    # cvss_missing is crisp: compare missing vs a present score at each fixed point
    rows = fixed_sets({"cox_risk": COX, "epss": EPSS}, True)
    for r in rows:
        r["blindspot"] = r["cox_risk"] - r["epss"]
    base = {k: np.array([r[k] for r in rows], dtype=float) for k in ("cox_risk", "epss", "blindspot")}
    miss, _ = fl.score(base | {"cvss": np.zeros(len(rows)), "cvss_missing": np.ones(len(rows))}, config)
    print("\n== cvss_missing (crisp): priority with score missing minus with each CVSS band present")
    for c in (2.0, 5.5, 8.0, 9.5):
        pres, _ = fl.score(base | {"cvss": np.full(len(rows), c), "cvss_missing": np.zeros(len(rows))}, config)
        d = miss - pres
        print(f"  vs cvss {c}: min {d.min():+.3f}, max {d.max():+.3f}")


if __name__ == "__main__":
    main()
