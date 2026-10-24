"""
Enrichment-bias presence gap: positive-vs-negative difference in CNA-CVSS
presence and in NVD vulnStatus distribution, at landmark-row level. This is
the residual-bias test behind STATUS.md's "2.8pp train / 6.2pp test"
figures; run with no arguments it reproduces them from the stored
landmark_v20260922 rows (train -2.76pp, test +6.23pp: gap = negatives'
cvss_cna_missing rate minus positives', so the train sign is opposite to
test).

docs/holdout_protocol.md requires this to be run on the 2026 holdout
cohort, and reported beside the frozen test figure, BEFORE any model is
evaluated on the cohort. vulnStatus is read from canonical.cve, i.e. as of
each CVE's last NVD fetch (source_last_fetched_at); the age-at-fetch summary
printed alongside is what the two populations' enrichment maturity
actually differs by.

Usage:
  python -m scripts.eda.enrichment_gap                         # stored train/test
  python -m scripts.eda.enrichment_gap --rules                 # + pre-fix source rules
  python -m scripts.eda.enrichment_gap --by-cna                # test gap within CNA strata
  python -m scripts.eda.enrichment_gap --cohort <dataset_version>   # training.holdout_2026
"""

from __future__ import annotations

import argparse

import numpy as np
import pandas as pd
from sqlalchemy import text

from database.engine import get_engine
from scripts.evaluate.data_splits import load_full_train_and_test

RECORDED_TEST_GAP_PP = 6.23  # landmark_v20260922 test rows, own-CNA source rule
RECORDED_TRAIN_GAP_PP = -2.76


def presence_gap(rows: pd.DataFrame, cve: pd.DataFrame) -> dict:
    x = rows[["cve_id", "composite_event", "cvss_cna_missing"]].merge(cve, on="cve_id", how="left")
    pos = x["composite_event"].astype(bool)
    missing = x["cvss_cna_missing"].astype(float)
    age = (pd.to_datetime(x["source_last_fetched_at"]).dt.tz_localize(None)
           - pd.to_datetime(x["published_date"])).dt.days
    return {
        "rows": len(x), "positive_rows": int(pos.sum()),
        "cna_cvss_missing_neg": missing[~pos].mean(), "cna_cvss_missing_pos": missing[pos].mean(),
        "cna_cvss_gap_pp": 100 * (missing[~pos].mean() - missing[pos].mean()),
        "vuln_status": pd.crosstab(pos.rename("positive"), x["vuln_status"].fillna("<none>"), normalize="index"),
        "age_at_fetch_days": age.quantile([0, 0.25, 0.5, 0.75, 1]).tolist(),
    }


def _report(name: str, r: dict) -> None:
    print(f"\n== {name}: {r['rows']:,} rows, {r['positive_rows']} positive")
    print(f"CNA-CVSS missing: negatives {r['cna_cvss_missing_neg']:.4f}, positives {r['cna_cvss_missing_pos']:.4f}, "
          f"gap {r['cna_cvss_gap_pp']:+.2f}pp")
    print("vulnStatus share by label:")
    print(r["vuln_status"].round(3).to_string())
    print("age at NVD fetch (days, min/q1/median/q3/max):", [int(a) for a in r["age_at_fetch_days"]])


def source_rule_gaps(engine, train: pd.DataFrame, test: pd.DataFrame) -> pd.DataFrame:
    """CNA-CVSS and primary_cwe_id missingness gaps under each CVSS/CWE source
    rule the project has used, on the stored landmark rows (the rebuild was a
    feature swap, not a population change, so the rows are the same under
    every rule): 'any' (no filter), 'not_nvd' (first pass, source !=
    nvd@nist.gov), 'own_cna' (current, source = the CVE's own
    sourceIdentifier). Presence = at least one CVSS metric / CWE mapping
    passing the rule. Read-only."""
    own = ("SELECT DISTINCT ON (cve_id) cve_id, payload->>'sourceIdentifier' AS sid "
           "FROM staging.nvd_cve_raw ORDER BY cve_id, fetched_at DESC")
    present = {}
    for kind, table in (("cvss", "canonical.cvss_metric"), ("cwe", "canonical.cve_cwe_map")):
        for rule, where in (("any", "TRUE"), ("not_nvd", "t.source <> 'nvd@nist.gov'"), ("own_cna", "t.source = o.sid")):
            ids = pd.read_sql(text(f"SELECT DISTINCT t.cve_id FROM {table} t JOIN ({own}) o USING (cve_id) WHERE {where}"),
                              engine).cve_id
            present[(kind, rule)] = set(ids)
    out = []
    for split, rows in (("train", train), ("test", test)):
        pos = rows["composite_event"].astype(bool).values
        for (kind, rule), ids in present.items():
            missing = ~rows["cve_id"].isin(ids).values
            neg_rate, pos_rate = missing[~pos].mean(), missing[pos].mean()
            gap = 100 * (neg_rate - pos_rate)
            out.append({"split": split, "feature": kind, "rule": rule, "missing_neg": neg_rate, "missing_pos": pos_rate,
                        "gap_pp": gap, "in_words": "positives LESS often missing" if gap > 0 else
                        "positives MORE often missing" if gap < 0 else "no difference"})
    # sanity check: the own-CNA CVSS rule must reproduce the stored cvss_cna_missing exactly
    for rows in (train, test):
        assert (~rows["cve_id"].isin(present[("cvss", "own_cna")])).equals(rows["cvss_cna_missing"].astype(bool))
    return pd.DataFrame(out)


def _mh_gap(x: pd.DataFrame, stratum: str) -> tuple[float, int, int]:
    """Mantel-Haenszel risk difference (negatives' missing rate minus
    positives') pooled over `stratum`, weight n_pos*n_neg/n per stratum.
    Strata with no positives or no negatives carry zero weight. Returns
    (gap_pp, informative strata, rows in them)."""
    g = x.groupby([stratum, "pos"])["missing"].agg(["sum", "count"]).unstack("pos", fill_value=0)
    n1, n0 = g[("count", True)], g[("count", False)]
    ok = (n1 > 0) & (n0 > 0)
    n1, n0, m1, m0 = n1[ok], n0[ok], g[("sum", True)][ok], g[("sum", False)][ok]
    w = n1 * n0 / (n1 + n0)
    rd = m0 / n0 - m1 / n1
    return 100 * (w * rd).sum() / w.sum(), int(ok.sum()), int((n1 + n0).sum())


def cna_stratified_gap(engine, test: pd.DataFrame, top_ns=(5, 10, 20), n_boot: int = 200,
                       seed: int = 20260922) -> None:
    """Is the test CNA-CVSS gap explained by CNA composition? Crude gap,
    gap restricted to the top-N CNAs by test CVE volume, and the
    Mantel-Haenszel gap conditioned on CNA (sourceIdentifier), each with a
    whole-CVE bootstrap interval (rows of one CVE are not independent).
    Read-only; interpretation only, not a feature or model change."""
    sid = pd.read_sql(text("SELECT DISTINCT ON (cve_id) cve_id, payload->>'sourceIdentifier' AS cna "
                           "FROM staging.nvd_cve_raw ORDER BY cve_id, fetched_at DESC"), engine)
    x = test[["cve_id", "composite_event", "cvss_cna_missing"]].merge(sid, on="cve_id", how="left")
    x["pos"] = x["composite_event"].astype(bool)
    x["missing"] = x["cvss_cna_missing"].astype(bool)
    x["cna"] = x["cna"].fillna("<none>")

    per_cve = x.groupby("cve_id").agg(cna=("cna", "first"), pos=("pos", "max"), missing=("missing", "first"))
    volume = per_cve["cna"].value_counts()
    print(f"\n== test CNA composition: {per_cve['cna'].nunique()} CNAs, {len(per_cve):,} CVEs, "
          f"{int(per_cve['pos'].sum())} positive CVEs")
    pos_cna = per_cve[per_cve["pos"]]["cna"].value_counts()
    neg_cna = per_cve[~per_cve["pos"]]["cna"].value_counts()
    comp = pd.DataFrame({"pos_cves": pos_cna, "neg_cves": neg_cna}).fillna(0).astype(int)
    comp["pos_share"] = comp["pos_cves"] / comp["pos_cves"].sum()
    comp["neg_share"] = comp["neg_cves"] / comp["neg_cves"].sum()
    comp["volume_rank"] = volume.rank(ascending=False, method="first").reindex(comp.index).astype(int)
    comp["cna_cvss_missing"] = per_cve.groupby("cna")["missing"].mean().reindex(comp.index)
    comp = comp.sort_values(["pos_cves", "neg_cves"], ascending=False)
    print("CNAs of positive CVEs (and the 10 largest by volume), CVE level:")
    show = comp[(comp["pos_cves"] > 0) | (comp["volume_rank"] <= 10)]
    print(show.to_string(float_format=lambda v: f"{v:.3f}"))
    print(f"positives: {comp['pos_cves'].gt(0).sum()} CNAs; top-10-by-volume CNAs hold "
          f"{comp.loc[comp['volume_rank'] <= 10, 'pos_share'].sum():.1%} of positive CVEs vs "
          f"{comp.loc[comp['volume_rank'] <= 10, 'neg_share'].sum():.1%} of negative CVEs")

    # CNA-level missingness is close to all-or-nothing; how much within-CNA variation is there?
    cna_rate = x.groupby("cna")["missing"].mean()
    mixed = cna_rate[(cna_rate > 0) & (cna_rate < 1)].index
    print(f"rows in CNAs whose CNA-CVSS presence varies across their CVEs: "
          f"{x['cna'].isin(mixed).mean():.1%} (positives {x.loc[x['pos'], 'cna'].isin(mixed).mean():.1%})")

    def estimates(d: pd.DataFrame) -> dict:
        crude = 100 * (d.loc[~d["pos"], "missing"].mean() - d.loc[d["pos"], "missing"].mean())
        out = {"crude": crude, "MH | CNA": _mh_gap(d, "cna")[0]}
        for n in top_ns:
            top = d[d["cna"].isin(volume.index[:n])]
            out[f"crude, top-{n} CNAs"] = 100 * (top.loc[~top["pos"], "missing"].mean()
                                                  - top.loc[top["pos"], "missing"].mean())
            out[f"MH | CNA, top-{n}"] = _mh_gap(top, "cna")[0]
        return out

    point = estimates(x)
    rng = np.random.default_rng(seed)
    cves = per_cve.index.to_numpy()
    rows_by_cve = x.groupby("cve_id").indices
    boots = []
    for _ in range(n_boot):
        idx = np.concatenate([rows_by_cve[c] for c in rng.choice(cves, size=len(cves), replace=True)])
        boots.append(estimates(x.iloc[idx]))
    boots = pd.DataFrame(boots)
    _, n_strata, n_rows = _mh_gap(x, "cna")
    print(f"\n== test CNA-CVSS gap (row level; + = positives less often missing); "
          f"MH uses {n_strata} CNAs with both labels ({n_rows:,} rows); {n_boot} whole-CVE resamples")
    for k, v in point.items():
        lo, hi = np.nanpercentile(boots[k], [2.5, 97.5])
        n_rows_k = len(x) if "top" not in k else int(x["cna"].isin(volume.index[:int(k.split("top-")[1].split()[0].rstrip(","))]).sum())
        print(f"  {k:<22} {v:+6.2f}pp  [{lo:+6.2f}, {hi:+6.2f}]  rows {n_rows_k:,}")


def main(cohort: str | None = None, rules: bool = False, by_cna: bool = False) -> None:
    engine = get_engine()
    cve = pd.read_sql(text("SELECT cve_id, vuln_status, published_date, source_last_fetched_at FROM canonical.cve"),
                      engine)
    train, test = load_full_train_and_test()
    _report("frozen train", presence_gap(train, cve))
    _report("frozen test", presence_gap(test, cve))
    if rules:
        print("\n== gap by source rule (row level; gap = negatives' missing rate - positives')")
        print(source_rule_gaps(engine, train, test).to_string(index=False, float_format=lambda v: f"{v:.4f}"))
    if by_cna:
        cna_stratified_gap(engine, test)
    if cohort:
        rows = pd.read_sql(text("SELECT cve_id, composite_event, cvss_cna_missing, spans_version_transition "
                                "FROM training.holdout_2026 WHERE dataset_version = :v"), engine, params={"v": cohort})
        if rows.empty:
            raise SystemExit(f"no training.holdout_2026 rows for dataset_version {cohort!r}")
        # the frozen figures are on default-export rows (no version-transition rows); compare like with like
        r = presence_gap(rows[~rows["spans_version_transition"]], cve)
        _report(f"cohort {cohort}, default rows (no version-transition rows)", r)
        _report(f"cohort {cohort}, all rows", presence_gap(rows, cve))
        print(f"\nCNA-CVSS gap: cohort {r['cna_cvss_gap_pp']:+.2f}pp vs frozen test {RECORDED_TEST_GAP_PP:+.2f}pp "
              f"(difference {r['cna_cvss_gap_pp'] - RECORDED_TEST_GAP_PP:+.2f}pp)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cohort", help="training.holdout_2026 dataset_version of the holdout cohort")
    parser.add_argument("--rules", action="store_true", help="also report gaps under each CVSS/CWE source rule")
    parser.add_argument("--by-cna", action="store_true", help="test gap conditioned on CNA (sourceIdentifier)")
    args = parser.parse_args()
    main(args.cohort, args.rules, args.by_cna)
