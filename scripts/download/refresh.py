"""
Resumable, idempotent data refresh for the 2026 holdout cohort
(docs/holdout_protocol.md). Four steps, always in this order (clean_kev,
clean_epss and clean_exploitdb need the CVEs clean_nvd ingests):

  nvd        NVD CVEs PUBLISHED in [2026-03-25, 2026-10-21] only, then
             clean_nvd. Historical CVEs are never re-fetched, so their
             newest staged payload stays the 2026-09-20 one.
  kev        today's KEV catalog, then clean_kev.
  epss       EPSS daily files 2026-09-21..2026-10-21, then clean_epss. Its
             "historical_cve_rows_added" check only confirms the 90-day window
             was applied; history immutability is checked separately against
             the pre-refresh backup ("history_immutability").
  exploitdb  today's Exploit-DB index, then clean_exploitdb.

Each step:
  1. is skipped if its completion record already exists in
     staging.file_manifest (a re-run after a dropped connection resumes at
     the first unfinished step);
  2. runs its downloader, which is itself idempotent at page/file level
     (one transaction per page or file, already-recorded files skipped),
     then its cleaner (idempotent: re-derives canonical rows from staging);
  3. verifies its own scope and that no historical input changed, raising
     (and stopping every later step) if not;
  4. writes data/raw/<source>/refresh/<step>.json (what was fetched, the
     source's as-of date, counts, verification results) and records it in
     staging.file_manifest with status 'parsed' and snapshot_date = the
     source's as-of date. That row is the step's completion record.

Usage: python -m scripts.download.refresh [--step nvd|kev|epss|exploitdb]
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime, timedelta, timezone

import numpy as np
import pandas as pd
from sqlalchemy import text

from config.config_schema import get_config
from database.engine import get_engine, session_scope
from scripts.common.checksums import sha256_file
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.common.manifest import already_downloaded, upsert_manifest

logger = get_logger(__name__, category="download")

NVD_PUB_START, NVD_PUB_END = date(2026, 3, 25), date(2026, 10, 21)
NVD_RESULTS_PER_PAGE = 500  # 2,000-result pages take ~84s, past the client's 60s read timeout
EPSS_START, EPSS_END = date(2026, 9, 21), date(2026, 10, 21)
# last snapshot date any pre-cohort CVE can have: published <= 2026-03-24, kept for 90 days
EPSS_HISTORY_END = NVD_PUB_START - timedelta(days=1) + timedelta(days=90)  # 2026-06-22
PRE_REFRESH_BACKUP = "data/backups/vuln_survival_pre_refresh_20261022.dump"
STUDY_MAX_ASOF = date(2026, 4, 23)  # latest as_of_date in training.training_dataset
STEPS = ("nvd", "kev", "epss", "exploitdb")


class RefreshVerificationError(RuntimeError):
    pass


def _completion_path(cfg, step: str):
    return cfg.paths.data_raw / step / "refresh" / f"refresh_{step}.json"


def _completed(cfg, step: str) -> bool:
    path = _completion_path(cfg, step)
    with session_scope() as session:
        return already_downloaded(session, source=step, file_path=str(path.relative_to(cfg.project_root))) is not None


def _record_completion(cfg, step: str, asof: date, summary: dict) -> None:
    path = _completion_path(cfg, step)
    path.parent.mkdir(parents=True, exist_ok=True)
    finished = datetime.now(tz=timezone.utc)
    path.write_text(json.dumps({"step": step, "source_asof": asof.isoformat(),
                                "completed_at": finished.isoformat(), **summary}, indent=2, default=str))
    with session_scope() as session:
        upsert_manifest(session, source=step, file_path=str(path.relative_to(cfg.project_root)),
                        url=f"refresh:{step}", fetched_at=finished, sha256=sha256_file(path),
                        byte_size=path.stat().st_size, status="parsed", snapshot_date=asof,
                        row_count=summary.get("rows"))
    log_with_fields(logger, logging.INFO, "refresh step complete", step=step, source_asof=asof.isoformat())


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise RefreshVerificationError(message)


def _q(sql: str, **params) -> pd.DataFrame:
    return pd.read_sql(text(sql), get_engine(), params=params)


# --- steps ---------------------------------------------------------------

def step_nvd(cfg) -> tuple[date, dict]:
    from scripts.clean import clean_nvd
    from scripts.download import download_nvd

    download_nvd.main(start_date=NVD_PUB_START.isoformat(), end_date=NVD_PUB_END.isoformat(),
                      results_per_page=NVD_RESULTS_PER_PAGE)
    pattern = f"data/raw/nvd/%_pp{NVD_RESULTS_PER_PAGE}/page_%"
    staged = _q(
        "SELECT count(*) AS rows, count(DISTINCT r.cve_id) AS cves, "
        "min((r.payload->>'published')::date) AS min_pub, max((r.payload->>'published')::date) AS max_pub, "
        "count(*) FILTER (WHERE (r.payload->>'published')::date NOT BETWEEN :s AND :e) AS out_of_scope "
        "FROM staging.nvd_cve_raw r JOIN staging.file_manifest m "
        "  ON m.source = 'nvd' AND m.fetched_at = r.fetched_at AND m.file_path LIKE :p",
        s=NVD_PUB_START, e=NVD_PUB_END, p=pattern).iloc[0]
    manifest_rows = int(_q("SELECT coalesce(sum(row_count), 0) AS n FROM staging.file_manifest "
                           "WHERE source = 'nvd' AND file_path LIKE :p", p=pattern).n[0])
    log_with_fields(logger, logging.INFO, "NVD publish-date range actually fetched",
                    min_published=str(staged.min_pub), max_published=str(staged.max_pub),
                    rows=int(staged.rows), cves=int(staged.cves), out_of_scope=int(staged.out_of_scope))
    _check(int(staged.out_of_scope) == 0, f"NVD staged {staged.out_of_scope} rows published outside scope")
    _check(int(staged.rows) == manifest_rows, f"NVD staged {staged.rows} rows but manifest pages hold {manifest_rows}")
    _check(staged.min_pub is None or staged.min_pub >= NVD_PUB_START, f"NVD min published {staged.min_pub}")

    clean_nvd.main()
    return NVD_PUB_END, {"publish_range_requested": [NVD_PUB_START, NVD_PUB_END],
                         "publish_range_fetched": [staged.min_pub, staged.max_pub],
                         "results_per_page": NVD_RESULTS_PER_PAGE, "rows": int(staged.rows), "cves": int(staged.cves)}


def step_kev(cfg) -> tuple[date, dict]:
    from scripts.clean import clean_kev
    from scripts.download import download_kev

    before = _q("SELECT cve_id, date_added FROM canonical.kev")
    download_kev.main()
    clean_kev.main()
    latest = _q("SELECT file_path, snapshot_date FROM staging.file_manifest WHERE source = 'kev' "
                "AND url NOT LIKE 'refresh:%' ORDER BY fetched_at DESC LIMIT 1").iloc[0]
    _check(latest.snapshot_date is not None, "latest KEV manifest row has no snapshot_date (catalog as-of)")
    after = _q("SELECT cve_id, date_added FROM canonical.kev")
    m = before.merge(after, on="cve_id", how="left", suffixes=("_before", "_after"))
    _check(m["date_added_after"].notna().all(), "a KEV entry disappeared from canonical.kev")
    changed = int((m["date_added_before"] != m["date_added_after"]).sum())
    _check(changed == 0, f"{changed} existing KEV entries changed date_added")
    new = after[~after["cve_id"].isin(before["cve_id"])]
    stored = _q("SELECT t.cve_id, t.as_of_date, c.published_date FROM training.training_dataset t "
                "JOIN canonical.cve c USING (cve_id) WHERE t.dataset_version = 'landmark_v20260922'")
    label_affecting, other = label_affecting_listings(new, stored)
    return latest.snapshot_date, {"catalog_file": latest.file_path, "rows": len(after), "new_entries": len(new),
                                  "existing_date_added_changed": changed,
                                  "new_entries_affecting_stored_labels": label_affecting.to_dict("records"),
                                  "stored_rows_with_changed_labels": int(label_affecting["rows"].sum()),
                                  "new_entries_with_rows_not_affecting_labels": other.to_dict("records")}


def label_affecting_listings(new: pd.DataFrame, stored: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split new KEV listings (cve_id, date_added) for CVEs with stored landmark
    rows (cve_id, as_of_date, published_date) into those that change a stored
    label and those that don't. A stored row's label observes until its
    split's cutoff (compute_labels): TRAIN_TEST_CUTOFF for train CVEs, which
    censor there, DATA_CUTOFF for test. A listing changes the label only if
    it falls on or before that cutoff. Returns (affecting, not affecting),
    one record per CVE with its split, label cutoff and stored row count."""
    from scripts.features.build_landmark_dataset import DATA_CUTOFF, TRAIN_TEST_CUTOFF

    rows = stored.assign(published_date=pd.to_datetime(stored["published_date"]))
    per_cve = rows.groupby("cve_id").agg(published_date=("published_date", "first"), rows=("as_of_date", "size"))
    m = new.assign(date_added=pd.to_datetime(new["date_added"])).merge(per_cve, left_on="cve_id", right_index=True)
    is_train = m["published_date"].dt.date < TRAIN_TEST_CUTOFF
    m["split"] = np.where(is_train, "train", "test")
    m["label_cutoff"] = pd.to_datetime(np.where(is_train, pd.Timestamp(TRAIN_TEST_CUTOFF), pd.Timestamp(DATA_CUTOFF)))
    affects = m["date_added"] <= m["label_cutoff"]
    out = m[["cve_id", "date_added", "split", "label_cutoff", "rows"]].sort_values("date_added", ascending=False)
    fmt = lambda d: d.assign(date_added=d["date_added"].dt.date.astype(str),
                             label_cutoff=d["label_cutoff"].dt.date.astype(str),
                             rows=d["rows"].astype(int)).reset_index(drop=True)
    return fmt(out[affects.loc[out.index]]), fmt(out[~affects.loc[out.index]])


def step_epss(cfg) -> tuple[date, dict]:
    from scripts.clean import clean_epss
    from scripts.download import download_epss

    download_epss.main(start_date=EPSS_START.isoformat(), end_date=EPSS_END.isoformat())
    days = pd.date_range(EPSS_START, EPSS_END).date
    recorded = set(_q("SELECT snapshot_date FROM staging.file_manifest WHERE source = 'epss' "
                      "AND status IN ('verified', 'parsed') AND snapshot_date BETWEEN :s AND :e",
                      s=EPSS_START, e=EPSS_END).snapshot_date)
    missing = [d for d in days if d not in recorded]
    _check(not missing, f"EPSS days not recorded in the manifest: {missing}")
    before = epss_history_checksum(_live_epss_lines())  # history is frozen; clean_epss must not touch it
    clean_epss.main()
    # WINDOW check, not an immutability check: download_epss keeps a snapshot only within 90 days of
    # publication, so a CVE published before NVD_PUB_START can never get a row dated >= EPSS_START.
    # This confirms the window was applied; it passes whatever happened to stored history.
    historical = int(_q("SELECT count(*) AS n FROM canonical.epss_timeline e JOIN canonical.cve c USING (cve_id) "
                        "WHERE e.snapshot_date >= :s AND c.published_date < :p",
                        s=EPSS_START, p=NVD_PUB_START).n[0])
    _check(historical == 0, f"{historical} new EPSS snapshots for CVEs published before {NVD_PUB_START}")
    # IMMUTABILITY check: every row dated on or before EPSS_HISTORY_END, identical to the pre-refresh backup
    # (row count + order-independent checksums) and unchanged across this step's clean.
    after = epss_history_checksum(_live_epss_lines())
    backup = epss_history_checksum(_backup_epss_lines(cfg.project_root / PRE_REFRESH_BACKUP))
    _check(after == before == backup, f"EPSS history <= {EPSS_HISTORY_END} changed: backup {backup}, "
                                      f"before clean {before}, after clean {after}")
    rows = int(_q("SELECT count(*) AS n FROM canonical.epss_timeline WHERE snapshot_date >= :s", s=EPSS_START).n[0])
    return EPSS_END, {"days": [EPSS_START, EPSS_END], "rows": rows, "historical_cve_rows_added": historical,
                      "historical_cve_rows_added_note": EPSS_WINDOW_NOTE,
                      "history_immutability": {"through": EPSS_HISTORY_END, "backup": PRE_REFRESH_BACKUP,
                                               "matches_backup": True, **after}}


EPSS_WINDOW_NOTE = ("window check only: confirms the 90-day post-publication window was applied (a CVE published "
                    "before 2026-03-25 cannot get a snapshot dated >= 2026-09-21). It does NOT test that stored "
                    "history is unchanged; see history_immutability for that.")
EPSS_COLUMNS = ("cve_id", "snapshot_date", "epss_score", "percentile", "is_observed", "fill_method")


def epss_history_checksum(lines, through: date | None = None) -> dict:
    """Row count and two order-independent checksums (per-row sha256 summed mod 2**256) over
    canonical.epss_timeline COPY text lines dated on or before `through`: one over (cve_id, snapshot_date,
    epss_score, percentile), one over the full row. Any added, missing, duplicated or changed row moves
    them."""
    import hashlib

    cutoff = (through or EPSS_HISTORY_END).isoformat()
    n, key4, full, mod = 0, 0, 0, 1 << 256
    for line in lines:
        line = line.rstrip("\n")
        f = line.split("\t")
        if len(f) != len(EPSS_COLUMNS) or f[1] > cutoff:
            continue
        n += 1
        key4 = (key4 + int.from_bytes(hashlib.sha256("\t".join(f[:4]).encode()).digest(), "big")) % mod
        full = (full + int.from_bytes(hashlib.sha256(line.encode()).digest(), "big")) % mod
    return {"rows": n, "checksum_key4": f"{key4:064x}", "checksum_full_row": f"{full:064x}"}


def _live_epss_lines():
    with get_engine().raw_connection() as conn, conn.cursor() as cur:
        with cur.copy(f"COPY (SELECT {', '.join(EPSS_COLUMNS)} FROM canonical.epss_timeline "
                      f"WHERE snapshot_date <= '{EPSS_HISTORY_END}') TO STDOUT") as copy:
            pending = ""  # COPY text blocks don't align with rows; same bytes pg_dump writes
            for block in copy:
                pending += bytes(block).decode()
                *complete, pending = pending.split("\n")
                yield from complete
            if pending:
                yield pending


def _backup_epss_lines(dump_path):
    import subprocess

    proc = subprocess.Popen(["pg_restore", "-f", "-", "--data-only", "-n", "canonical", "-t", "epss_timeline",
                             str(dump_path)], stdout=subprocess.PIPE, text=True)
    copying = False
    for line in proc.stdout:
        if line.startswith("COPY canonical.epss_timeline"):
            _check(line.split("(")[1].split(")")[0].split(", ") == list(EPSS_COLUMNS),
                   f"backup epss_timeline columns differ: {line.strip()}")
            copying = True
        elif copying and line.startswith("\\."):
            copying = False
        elif copying:
            yield line
    _check(proc.wait() == 0, f"pg_restore failed on {dump_path}")


def step_exploitdb(cfg) -> tuple[date, dict]:
    from scripts.clean import clean_exploitdb
    from scripts.download import download_exploitdb

    first_exploit_sql = ("SELECT m.cve_id, min(x.date_published) AS first_exploit FROM canonical.exploitdb_cve_map m "
                         "JOIN canonical.exploitdb x USING (exploit_id) GROUP BY m.cve_id")
    before = _q(first_exploit_sql)
    download_exploitdb.main()
    clean_exploitdb.main()
    after = _q(first_exploit_sql)
    m = after.merge(before, on="cve_id", how="outer", suffixes=("", "_before"))
    first, first_before = pd.to_datetime(m["first_exploit"]), pd.to_datetime(m["first_exploit_before"])
    differs = ~((first == first_before) | (first.isna() & first_before.isna()))
    # a historical feature can change only if a CVE's first exploit date changed and either value is on/before
    # the study's last as_of (exploit_published_by_asof / days_to_first_exploit read nothing later)
    cutoff = pd.Timestamp(STUDY_MAX_ASOF)
    moved = m[differs & ((first <= cutoff) | (first_before <= cutoff))]
    _check(moved.empty, f"{len(moved)} CVEs' first exploit date changed to on/before {STUDY_MAX_ASOF}: "
                        f"{moved['cve_id'].head(10).tolist()}")
    asof = datetime.now(tz=timezone.utc).date()
    return asof, {"rows": len(after), "cves_with_changed_first_exploit": int(differs.sum()),
                  "historical_first_exploit_changed": 0}


STEP_FUNCS = {"nvd": step_nvd, "kev": step_kev, "epss": step_epss, "exploitdb": step_exploitdb}


def main(only: str | None = None) -> None:
    cfg = get_config()
    for step in STEPS:
        if only and step != only:
            continue
        if _completed(cfg, step):
            log_with_fields(logger, logging.INFO, "refresh step already complete, skipping", step=step)
            continue
        log_with_fields(logger, logging.INFO, "refresh step starting", step=step)
        asof, summary = STEP_FUNCS[step](cfg)
        _record_completion(cfg, step, asof, summary)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--step", choices=STEPS, help="run one step only (it still skips if already complete)")
    main(parser.parse_args().step)
