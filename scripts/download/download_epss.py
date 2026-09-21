"""
Downloads FIRST EPSS historical daily snapshot files. Unlike NVD/KEV/CWE,
EPSS has no bulk historical archive — reconstruction requires one file per
day (https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz),
available from 2021-04-14 onward. Every daily file is immutable and NEVER
overwritten: staging.epss_scores_raw has a UNIQUE(cve_id, snapshot_date)
constraint that makes this structurally impossible, and days already
recorded in the manifest are skipped entirely.

Scope (config.sources.epss.scope, or --start-date/--end-date):
  bounded       -> last `bounded_lookback_days` days (default: last 2 years)
  full_backfill -> earliest_available_date (2021-04-14) through today

--- Two-phase design (replaces an earlier single-phase asyncio downloader) ---
An earlier version of this module used asyncio (a semaphore-bounded pool of
concurrent download+parse+DB-write tasks). It passed small-scale tests
(16 days, then 44 days, zero failures) but did not hold at full backfill
scale: a ~1,785-day run degraded to 350-430s/file and kept failing, having
already produced a ~70% failure rate on an earlier attempt from
self-inflicted resource exhaustion (unbounded in-flight tasks each holding
a 200k-350k-row list, competing for a handful of DB connections — see git
history for the specifics of that bug and the fix that didn't fully hold).
Rather than keep iterating on async concurrency, this module now does the
simplest thing that can't reproduce that failure mode:

PHASE A (fetch_all / `phase_a_fetch`) — plain ThreadPoolExecutor, NOT
asyncio, max_workers=4. Downloads every requested day straight to
data/raw/epss/ with NO database involvement at all — no session, no
manifest check via the DB (existence + gzip integrity of the file on disk
is the skip check), nothing that could interact with connection pools or
event loops. At most 4 real OS threads are ever downloading at once,
full stop; there is no unbounded-queueing failure mode here because
nothing is queued beyond what ThreadPoolExecutor itself bounds. Every
failure logs the actual exception type and message (the old single-phase
version's "EPSS download failed" log line never carried a cause — this
was a real gap, fixed here). Raises loudly at the end if any requested
date still has no valid file, listing every one.

PHASE B (load_all / `phase_b_load`) — fully sequential, no concurrency at
all. One file per transaction: parses the on-disk file, keeps only rows
for a CVE already in canonical.cve whose snapshot_date falls within
[published_date, published_date + 90 days] (see the longer comment above
phase_b_load for why — in short, an earlier unfiltered load reached 159M
rows / 28GB covering under half the target date range, to serve features
that only ever read a 90-day window per CVE), then COPYs the filtered
rows into staging.epss_scores_raw and writes the staging.file_manifest
row in the SAME transaction (atomic — see the note below on why that's
what makes COPY without ON CONFLICT safe), then moves to the next day.
Slower than any concurrent design could be, but a sequential loop cannot
reproduce either of the earlier bugs (there is nothing to serialize on,
and nothing unbounded to grow).

The per-file row insert uses a raw COPY (psycopg's copy protocol) rather
than a chunked INSERT ... ON CONFLICT DO NOTHING — COPY of ~200k rows
measured at ~11s vs ~27s for the chunked insert (staging.epss_scores_raw
has grown to 10M+ rows across 4 indexes, which is what makes either path
nontrivial). ON CONFLICT DO NOTHING was dropped as unneeded, not just
replaced: the manifest write and the row insert share one transaction,
and a day already in the manifest is skipped before this runs — so a
(cve_id, snapshot_date) collision within one successful run is not
reachable. The UNIQUE constraint stays as a real invariant; COPY will
fail loudly (transaction rolled back) if it's ever actually violated,
which is preferable to silently swallowing something that should never
happen. This COPY path is NOT row-level idempotent the way the old
ON CONFLICT DO NOTHING insert was — its safety depends entirely on
"manifest checked before every load" + "manifest write and row insert
are one atomic transaction" both continuing to hold. If staging row
counts or a unique-violation crash ever look wrong, check those two
invariants first.

Usage: python -m scripts.download.download_epss [--start-date] [--end-date]
Also reachable via `vsp download epss`.
"""

from __future__ import annotations

import csv
import gzip
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import httpx
from sqlalchemy import text

from config.config_schema import get_config
from database.engine import session_scope
from scripts.common.checksums import sha256_bytes
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.common.manifest import already_downloaded, upsert_manifest

logger = get_logger(__name__, category="download")

USER_AGENT = "vuln-survival-pipeline/0.1 (capstone research; contact via project repo)"
PHASE_A_TIMEOUT_SECONDS = 60.0
PHASE_A_MAX_ATTEMPTS = 3
PHASE_A_BACKOFF_BASE_SECONDS = 2.0


def _date_range(cfg, start_date: str | None, end_date: str | None) -> list[date]:
    epss_cfg = cfg.sources.epss
    earliest = date.fromisoformat(epss_cfg.earliest_available_date)
    today = datetime.now(tz=timezone.utc).date()

    if start_date:
        start = date.fromisoformat(start_date)
    elif epss_cfg.scope.mode == "full_backfill":
        start = earliest
    else:
        start = today - timedelta(days=epss_cfg.scope.bounded_lookback_days)
    start = max(start, earliest)

    end = date.fromisoformat(end_date) if end_date else today
    end = min(end, today)

    if start > end:
        return []
    return [start + timedelta(days=i) for i in range((end - start).days + 1)]


def _dest_path(cfg, day: date) -> Path:
    return cfg.paths.data_raw / "epss" / f"epss_scores-{day.isoformat()}.csv.gz"


def _is_valid_gzip(path: Path) -> bool:
    """Cheap integrity check: does it decompress at all. Doesn't read the
    whole file (these are up to ~2.4MB, not worth fully re-parsing here)."""
    try:
        with gzip.open(path, "rb") as f:
            f.read(1024)
        return True
    except OSError:
        return False


def _parse_epss_csv_gz(raw_bytes: bytes) -> list[dict]:
    text = gzip.decompress(raw_bytes).decode("utf-8")
    lines = text.splitlines()
    data_lines = [ln for ln in lines if not ln.startswith("#")]
    reader = csv.DictReader(data_lines)
    rows = []
    for row in reader:
        try:
            rows.append(
                {
                    "cve_id": row["cve"],
                    "epss_score": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                }
            )
        except (KeyError, ValueError):
            continue
    return rows


# =============================================================================
# PHASE A — thread pool, disk only, no DB
# =============================================================================


def _fetch_one_day(day: date, dest_path: Path, url_template: str) -> tuple[date, str, str | None]:
    """Synchronous — runs in a worker thread. Returns (day, status, error_repr).
    status in {'already_ok', 'ok', 'not_found', 'failed'}."""
    if dest_path.exists() and _is_valid_gzip(dest_path):
        return day, "already_ok", None

    url = url_template.format(date=day.isoformat())
    last_exc: Exception | None = None

    for attempt in range(PHASE_A_MAX_ATTEMPTS):
        try:
            with httpx.Client(
                headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=PHASE_A_TIMEOUT_SECONDS
            ) as client:
                resp = client.get(url)
            if resp.status_code in (404, 403):
                # Confirmed via direct curl for 2022-07-14 and 2024-12-01 (both
                # reproducible, neighboring dates 200 OK): this S3-backed host
                # returns 403 rather than 404 for a date it has no file for,
                # not an access/auth problem — treated the same as a real 404.
                return day, "not_found", f"HTTP {resp.status_code}"
            resp.raise_for_status()

            tmp_path = dest_path.with_suffix(dest_path.suffix + ".part")
            tmp_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path.write_bytes(resp.content)
            if not _is_valid_gzip(tmp_path):
                raise ValueError("downloaded file failed gzip integrity check")
            tmp_path.replace(dest_path)
            return day, "ok", None
        except Exception as e:  # noqa: BLE001 — logged with type below, then re-raised as a return value
            last_exc = e
            if attempt < PHASE_A_MAX_ATTEMPTS - 1:
                time.sleep(PHASE_A_BACKOFF_BASE_SECONDS * (2**attempt))

    error_repr = f"{type(last_exc).__name__}: {last_exc}"
    logger.error(
        "EPSS Phase A download failed",
        extra={"extra_fields": {
            "date": day.isoformat(), "exception_type": type(last_exc).__name__, "error": str(last_exc),
        }},
    )
    return day, "failed", error_repr


def phase_a_fetch(cfg, days: list[date]) -> dict[str, list[date] | dict[date, str]]:
    """Downloads every day in `days` to disk with a 4-worker thread pool, no
    DB involvement. Returns a summary dict; raises RuntimeError listing any
    date still missing a valid file at the end."""
    url_template = cfg.sources.epss.daily_url_template
    summary: dict[str, list] = {"already_ok": [], "ok": [], "not_found": [], "failed": []}
    errors: dict[date, str] = {}

    with ThreadPoolExecutor(max_workers=cfg.sources.epss.concurrency) as pool:
        futures = {
            pool.submit(_fetch_one_day, d, _dest_path(cfg, d), url_template): d for d in days
        }
        for fut in as_completed(futures):
            d, status, err = fut.result()
            summary[status].append(d)
            if err:
                errors[d] = err

    log_with_fields(
        logger, logging.INFO, "EPSS Phase A (fetch) complete",
        days_requested=len(days),
        already_ok=len(summary["already_ok"]),
        ok=len(summary["ok"]),
        not_found=len(summary["not_found"]),
        failed=len(summary["failed"]),
    )

    # A 404 is EPSS legitimately having no file for that date, not a failure of
    # ours — only `failed` (genuinely missing after retries) blocks progress.
    still_missing = sorted(summary["failed"])
    if still_missing:
        raise RuntimeError(
            f"Phase A: {len(still_missing)} date(s) still have no valid file after "
            f"{PHASE_A_MAX_ATTEMPTS} attempts each: "
            f"{', '.join(d.isoformat() for d in still_missing)}. "
            f"Exception types seen: {sorted(set(errors[d].split(':', 1)[0] for d in still_missing))}"
        )

    return summary


# =============================================================================
# PHASE B — sequential, disk to DB, no concurrency, WINDOWED to publication+90d
# =============================================================================
#
# staging.epss_scores_raw is loaded ONLY for (cve_id, snapshot_date) pairs
# where snapshot_date falls within [published_date, published_date + 90 days]
# for that CVE in canonical.cve. Every temporal feature this project plans
# to build (EPSS at day 7/14/30 checkpoints, forward-filled) only ever reads
# inside that window — loading EPSS for every CVE on every day it was ever
# scored would load ~500M rows (measured: an earlier unfiltered load reached
# 159M rows / 28GB after covering under half the date range, and was still
# growing) to serve a few million rows of actual feature input. CVEs not yet
# in canonical.cve (i.e. clean_nvd.py hasn't ingested them) contribute
# nothing here and are silently skipped — re-run clean_nvd.py first if a
# CVE's EPSS data looks missing.
#
# The full unfiltered daily series is NOT lost: every raw file stays in
# data/raw/epss/ (Phase A never deletes anything), so this windowed load can
# be dropped and rebuilt with a wider or different window at any time by
# re-running Phase B — nothing needs re-downloading.


def _load_cve_publication_dates() -> dict[str, date]:
    """One query, once, not per file — cfg.paths etc. not needed here."""
    with session_scope() as session:
        rows = session.execute(text("SELECT cve_id, published_date FROM canonical.cve")).all()
    return {cve_id: published_date for cve_id, published_date in rows}


def _load_one_day(cfg, day: date, cve_pub_dates: dict[str, date], window_days: int) -> tuple[str, int, int]:
    """Synchronous, one file, one transaction. Returns
    (status, rows_in_file, rows_kept). status in
    {'skipped', 'loaded', 'missing_file'}."""
    dest_path = _dest_path(cfg, day)
    file_path_str = str(dest_path.relative_to(cfg.project_root))
    url = cfg.sources.epss.daily_url_template.format(date=day.isoformat())

    with session_scope() as session:
        if already_downloaded(session, source="epss", file_path=file_path_str):
            return "skipped", 0, 0

        if not dest_path.exists():
            logger.error("EPSS Phase B: file missing on disk", extra={"extra_fields": {"date": day.isoformat()}})
            return "missing_file", 0, 0

        raw_bytes = dest_path.read_bytes()
        all_rows = _parse_epss_csv_gz(raw_bytes)

        kept_rows = []
        for r in all_rows:
            pub_date = cve_pub_dates.get(r["cve_id"])
            if pub_date is None:
                continue
            if pub_date <= day <= pub_date + timedelta(days=window_days):
                kept_rows.append(r)

        manifest_id = upsert_manifest(
            session,
            source="epss",
            file_path=file_path_str,
            url=url,
            fetched_at=datetime.now(tz=timezone.utc),
            snapshot_date=day,
            sha256=sha256_bytes(raw_bytes),
            byte_size=len(raw_bytes),
            row_count=len(kept_rows),
            status="verified",
            http_status=200,
        )

        if kept_rows:
            raw_conn = session.connection().connection.driver_connection
            with raw_conn.cursor() as cur:
                with cur.copy(
                    "COPY staging.epss_scores_raw "
                    "(cve_id, snapshot_date, epss_score, percentile, manifest_id) "
                    "FROM STDIN"
                ) as copy:
                    for r in kept_rows:
                        copy.write_row((r["cve_id"], day, r["epss_score"], r["percentile"], manifest_id))

    return "loaded", len(all_rows), len(kept_rows)


def phase_b_load(cfg, days: list[date], *, window_days: int = 90) -> dict[str, int]:
    """Sequentially loads every day in `days` from disk into
    staging.epss_scores_raw, keeping only rows for CVEs already in
    canonical.cve whose snapshot_date falls in
    [published_date, published_date + window_days]. No concurrency — one
    file, one transaction, then the next."""
    cve_pub_dates = _load_cve_publication_dates()
    log_with_fields(logger, logging.INFO, "EPSS Phase B: CVE publication-date lookup built", cve_count=len(cve_pub_dates))

    summary = {"loaded": 0, "skipped": 0, "missing_file": 0}
    total_rows_in_files = 0
    total_rows_kept = 0
    for day in days:
        status, rows_in_file, rows_kept = _load_one_day(cfg, day, cve_pub_dates, window_days)
        summary[status] += 1
        total_rows_in_files += rows_in_file
        total_rows_kept += rows_kept

    log_with_fields(
        logger, logging.INFO, "EPSS Phase B (load) complete",
        days_requested=len(days), total_rows_in_files=total_rows_in_files, total_rows_kept=total_rows_kept,
        **summary,
    )
    return summary


# =============================================================================
# Orchestration
# =============================================================================


def main(*, start_date: str | None = None, end_date: str | None = None) -> None:
    cfg = get_config()
    days = _date_range(cfg, start_date, end_date)
    if not days:
        logger.info("No dates to download for the configured EPSS scope")
        return

    phase_a_fetch(cfg, days)
    phase_b_load(cfg, days)


if __name__ == "__main__":
    main()
