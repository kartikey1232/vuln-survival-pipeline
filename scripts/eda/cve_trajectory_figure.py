"""
Generates the dashboard's "EPSS trajectory and Cox survival curve" chart for
one CVE as a static figure: docs/figures/cve_trajectory_<CVE>.png, plus the
plotted values as a CSV beside it.

- Left axis: the CVE's EPSS percentile over time (canonical.epss_timeline).
- Right axis: for each landmark (day 7/14/30) the CVE has a row at, the
  frozen Cox model's cumulative probability of KEV listing, 1 - S(t), at
  t = 1, 7, 14, 30, 60, 90, 180 and 365 days after that landmark's as-of
  date.
- A vertical line at the KEV listing date, if the CVE is listed.

The data and scoring are the API's own (api/db.py, api/artifacts.py,
api/scoring.py), the same code `GET /cve/{id}` serves to the dashboard
(dashboard/src/views/CveLookup.jsx), so the figure shows the same numbers.
Nothing is refit. Cox probabilities are under-dispersed: read the curves'
shape and rank, not their height.

Usage: python -m scripts.eda.cve_trajectory_figure CVE-2026-31976 [--out PATH]
"""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.ticker import FuncFormatter

from api import db, scoring
from api.artifacts import load_artifacts
from config.config_schema import get_config
from database.engine import get_engine

EPSS_COLOR = "#e8833a"
LANDMARK_STYLE = {7: ("#3b5bdb", "-"), 14: ("#2b9a8a", "-"), 30: ("#868e96", "--")}
KEV_COLOR = "#e03131"


def curve_data(cve_id: str) -> tuple[dict, pd.DataFrame, pd.DataFrame]:
    """(CVE record, EPSS history, Cox cumulative-probability points)."""
    cfg = get_config()
    engine = get_engine()
    record = db.cve_record(engine, cve_id)
    if record is None:
        raise SystemExit(f"{cve_id} not found in canonical.cve")
    epss = pd.DataFrame(record["epss_history"])
    epss["snapshot_date"] = pd.to_datetime(epss["snapshot_date"])
    epss["percentile"] = epss["percentile"].astype(float)

    rows = db.landmark_rows_for_cve(engine, cve_id)
    points = []
    if len(rows):
        art = load_artifacts(cfg.project_root / "models")
        curves = scoring.survival_curves(rows, art)
        for i, r in rows.iterrows():
            for day, s in zip(scoring.SURVIVAL_CURVE_DAYS, curves[i]):
                points.append({"landmark_day": int(r["landmark_day"]), "as_of_date": r["as_of_date"],
                               "day": day, "date": r["as_of_date"] + pd.Timedelta(days=day),
                               "cumulative_p_kev": 1 - float(s)})
    return record, epss, pd.DataFrame(points)


def plot(cve_id: str, record: dict, epss: pd.DataFrame, cox: pd.DataFrame, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.plot(epss["snapshot_date"], epss["percentile"] * 100, color=EPSS_COLOR, lw=2, label="EPSS percentile")
    ax.set_ylim(0, 100)
    ax.set_ylabel("EPSS percentile", color=EPSS_COLOR)
    ax.tick_params(axis="y", colors=EPSS_COLOR)
    ax.grid(True, ls=":", alpha=0.6)

    ax2 = ax.twinx()
    for lm, g in cox.groupby("landmark_day") if len(cox) else []:
        color, ls = LANDMARK_STYLE.get(lm, ("black", "-"))
        ax2.plot(g["date"], g["cumulative_p_kev"] * 100, color=color, ls=ls, marker="o", ms=3,
                 label=f"Cox P(KEV) from day {lm}")
    ax2.set_ylim(bottom=0)
    ax2.set_ylabel("Cox cumulative P(KEV listing), %")
    ax2.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:.2f}%"))

    if record["kev"]:
        kev = pd.Timestamp(record["kev"]["date_added"])
        ax.axvline(kev, color=KEV_COLOR, lw=1.5)
        ax.text(kev, 97, " KEV", color=KEV_COLOR, va="top")

    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d"))
    fig.autofmt_xdate()
    lines = ax.get_legend_handles_labels()
    lines2 = ax2.get_legend_handles_labels()
    ax.legend(lines[0] + lines2[0], lines[1] + lines2[1], loc="upper center", bbox_to_anchor=(0.5, -0.18),
              ncol=4, frameon=False)
    published = pd.Timestamp(record["published_date"]).date()
    kev_note = f", KEV-listed {record['kev']['date_added']}" if record["kev"] else ", not KEV-listed"
    ax.set_title(f"{cve_id}: EPSS trajectory and Cox survival curve (published {published}{kev_note})")
    fig.text(0.01, 0.005, "Cox probabilities are under-dispersed: read the curves' shape and rank, not their height.",
             fontsize=8, color="#555")
    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("cve_id")
    parser.add_argument("--out", type=Path, default=None, help="default: docs/figures/cve_trajectory_<CVE>.png")
    args = parser.parse_args()
    cve_id = args.cve_id.upper()
    out = args.out or get_config().project_root / "docs" / "figures" / f"cve_trajectory_{cve_id}.png"

    record, epss, cox = curve_data(cve_id)
    plot(cve_id, record, epss, cox, out)
    data = pd.concat([epss.assign(series="EPSS percentile")[["series", "snapshot_date", "percentile"]]
                      .rename(columns={"snapshot_date": "date", "percentile": "value"}),
                      cox.assign(series=cox["landmark_day"].map(lambda lm: f"Cox P(KEV) from day {lm}"))
                      [["series", "date", "cumulative_p_kev"]].rename(columns={"cumulative_p_kev": "value"})
                      if len(cox) else None])
    data.to_csv(out.with_suffix(".csv"), index=False)
    print(f"wrote {out} and {out.with_suffix('.csv')}")
    if len(cox):
        last = cox[cox["day"] == cox["day"].max()]
        for r in last.itertuples():
            print(f"  day {r.landmark_day}: cumulative P(KEV) at {r.day} days = {r.cumulative_p_kev:.4%}")


if __name__ == "__main__":
    main()
