"""
One-off exploratory analysis of the landmark training data — NOT a
pipeline stage (not wired into `vsp`), run directly for a progress review.
Produces docs/figures/*.png and the numbers behind docs/eda_summary.md.

Usage: python -m scripts.eda.landmark_eda
"""

from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from lifelines import KaplanMeierFitter
from lifelines.statistics import multivariate_logrank_test

from config.config_schema import get_config
from database.engine import get_engine

FIG_DIR = None


def _cvss_band(score: float | None) -> str:
    if score is None or pd.isna(score):
        return "unknown"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _epss_band(pct: float | None) -> str:
    if pct is None or pd.isna(pct):
        return "unknown"
    if pct < 0.5:
        return "bottom 50%"
    if pct < 0.9:
        return "50-90%"
    return "top 10%"


def km_by_cvss(df7_train: pd.DataFrame) -> dict:
    df = df7_train.copy()
    df["band"] = df["cvss_base_score"].apply(_cvss_band)
    df = df[df["band"] != "unknown"]

    order = ["low", "medium", "high", "critical"]
    fig, ax = plt.subplots(figsize=(8, 6))
    for band in order:
        sub = df[df["band"] == band]
        if sub.empty:
            continue
        kmf = KaplanMeierFitter()
        kmf.fit(sub["event_time"], sub["composite_event"], label=f"{band} (n={len(sub)})")
        kmf.plot_survival_function(ax=ax)

    result = multivariate_logrank_test(df["event_time"], df["band"], df["composite_event"])
    ax.set_title(f"Time-to-KEV from day-7 landmark, by CVSS severity band\nlog-rank p = {result.p_value:.4g}")
    ax.set_xlabel("Days since day-7 landmark")
    ax.set_ylabel("Survival probability (not yet KEV-listed)")
    fig.tight_layout()
    path = FIG_DIR / "km_by_cvss_band.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return {"path": path, "p_value": result.p_value, "n": len(df), "counts": df["band"].value_counts().to_dict()}


def km_by_epss(df7_train: pd.DataFrame) -> dict:
    df = df7_train.copy()
    df["band"] = df["epss_pct_now"].apply(_epss_band)
    df = df[df["band"] != "unknown"]

    order = ["bottom 50%", "50-90%", "top 10%"]
    fig, ax = plt.subplots(figsize=(8, 6))
    for band in order:
        sub = df[df["band"] == band]
        if sub.empty:
            continue
        kmf = KaplanMeierFitter()
        kmf.fit(sub["event_time"], sub["composite_event"], label=f"{band} (n={len(sub)})")
        kmf.plot_survival_function(ax=ax)

    result = multivariate_logrank_test(df["event_time"], df["band"], df["composite_event"])
    ax.set_title(f"Time-to-KEV from day-7 landmark, by EPSS percentile band\nlog-rank p = {result.p_value:.4g}")
    ax.set_xlabel("Days since day-7 landmark")
    ax.set_ylabel("Survival probability (not yet KEV-listed)")
    fig.tight_layout()
    path = FIG_DIR / "km_by_epss_band.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return {"path": path, "p_value": result.p_value, "n": len(df), "counts": df["band"].value_counts().to_dict()}


def kev_timing_bar_chart(engine) -> dict:
    q = """
    with study as (
      select cve_id, published_date from canonical.cve
      where published_date >= '2022-01-01' and published_date <= (date '2026-09-20' - interval '180 days')
    ),
    modeling_set as (
      select s.cve_id, s.published_date from study s
      where exists (select 1 from canonical.epss_timeline t where t.cve_id = s.cve_id and t.snapshot_date = s.published_date + 30)
    ),
    positives as (
      select m.cve_id, (k.date_added - m.published_date) as days_to_kev,
             (m.published_date < '2025-01-01') as is_train
      from modeling_set m join canonical.kev k on k.cve_id = m.cve_id
    )
    select is_train, days_to_kev from positives
    """
    df = pd.read_sql(q, engine)

    def bucket(d):
        if d <= 0:
            return "<=0"
        if d <= 7:
            return "1-7"
        if d <= 14:
            return "8-14"
        if d <= 30:
            return "15-30"
        if d <= 90:
            return "31-90"
        if d <= 180:
            return "91-180"
        return ">180"

    order = ["<=0", "1-7", "8-14", "15-30", "31-90", "91-180", ">180"]
    df["bucket"] = df["days_to_kev"].apply(bucket)
    df["split"] = np.where(df["is_train"], "train", "test")
    counts = df.groupby(["bucket", "split"]).size().unstack(fill_value=0).reindex(order)

    fig, ax = plt.subplots(figsize=(9, 6))
    x = np.arange(len(order))
    width = 0.35
    ax.bar(x - width / 2, counts["train"], width, label="train")
    ax.bar(x + width / 2, counts["test"], width, label="test")
    ax.set_xticks(x)
    ax.set_xticklabels(order)
    ax.set_xlabel("Days from publication to KEV date_added")
    ax.set_ylabel("Count of KEV positives")
    ax.set_title("KEV listing timing relative to NVD publication (689 in-window positives)")
    ax.legend()
    fig.tight_layout()
    path = FIG_DIR / "kev_timing_histogram.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return {"path": path, "counts": counts.to_dict()}


def epss_by_version_boxplot(engine) -> dict:
    versions = [
        (None, "2022-02-04", "unversioned"),
        ("2022-02-04", "2023-03-07", "v2022.01.01"),
        ("2023-03-07", "2025-03-17", "v2023.03.01"),
        ("2025-03-17", "2026-06-15", "v2025.03.14"),
        ("2026-06-15", None, "v2026.06.15"),
    ]
    order = [v[2] for v in versions]
    samples = {}
    for lo, hi, name in versions:
        where = []
        if lo:
            where.append(f"snapshot_date >= '{lo}'")
        if hi:
            where.append(f"snapshot_date < '{hi}'")
        where_clause = " AND ".join(where) if where else "TRUE"
        q = f"SELECT epss_score FROM canonical.epss_timeline WHERE {where_clause} ORDER BY random() LIMIT 50000"
        samples[name] = pd.read_sql(q, engine)["epss_score"].values

    fig, ax = plt.subplots(figsize=(9, 6))
    data = [samples[v] for v in order]
    ax.boxplot(data, tick_labels=order, showfliers=False)
    ax.set_yscale("log")
    ax.set_ylabel("EPSS raw score (log scale)")
    ax.set_title("EPSS score distribution by model version (50k-row random sample per version)")
    fig.tight_layout()
    path = FIG_DIR / "epss_by_version_boxplot.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return {"path": path, "sample_sizes": {k: len(v) for k, v in samples.items()}}


def main() -> None:
    global FIG_DIR
    cfg = get_config()
    FIG_DIR = cfg.project_root / "docs" / "figures"
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    engine = get_engine()

    df7 = pd.read_sql(
        "SELECT cve_id, as_of_date, cvss_base_score, epss_pct_now, event_time, composite_event "
        "FROM training.training_dataset WHERE checkpoint_day = 7 AND as_of_date < '2025-01-01'",
        engine,
    )

    r1 = km_by_cvss(df7)
    r2 = km_by_epss(df7)
    r3 = kev_timing_bar_chart(engine)
    r4 = epss_by_version_boxplot(engine)

    print("km_by_cvss:", r1)
    print("km_by_epss:", r2)
    print("kev_timing:", r3)
    print("epss_by_version:", r4)


if __name__ == "__main__":
    main()
