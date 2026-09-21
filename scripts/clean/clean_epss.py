"""
Cleans staging.epss_scores_raw into canonical.epss_timeline — one row per
(cve_id, snapshot_date), marked is_observed=TRUE, fill_method='observed'.

This is NOT the same as EPSS reconstruction: it only materializes days that
were actually observed in a downloaded snapshot. Forward-filling the gaps
between observed days into a dense daily timeline is
scripts/epss_reconstruct/reconstruct_epss_timeline.py (not implemented
yet) — canonical.epss_timeline.fill_method='ffill' rows do not exist until
that script runs.

canonical.epss_timeline.cve_id has a foreign key to canonical.cve, so only
staged EPSS rows for CVEs already cleaned by clean_nvd.py are inserted;
everything else is counted and skipped. In practice this match rate should
be at or near 100% as of the windowed Phase B load in download_epss.py
(scripts/download/download_epss.py) — it already excludes any cve_id not
in canonical.cve before ever staging a row, so this check here is a
defensive backstop, not the primary filter.

Usage: python -m scripts.clean.clean_epss
Also reachable via `vsp clean epss`.
"""

from __future__ import annotations

import logging

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from database.engine import session_scope
from database.models import EpssScoresRaw, EpssTimeline
from scripts.common.logging_utils import get_logger, log_with_fields

logger = get_logger(__name__, category="clean")

_CHUNK_SIZE = 5000


def main(*, test: bool = False) -> None:
    with session_scope(test=test) as session:
        rows_staged_count = session.execute(
            text("SELECT count(*) FROM staging.epss_scores_raw")
        ).scalar_one()

        if not rows_staged_count:
            log_with_fields(logger, logging.INFO, "No staged EPSS rows to clean", rows_staged=0)
            return

        # known_cves as a Python set + filtering client-side (not a SQL IN
        # clause) deliberately — at this scale (canonical.cve now has 100k+
        # rows since the full backfill, staging.epss_scores_raw tens of
        # millions) an IN(...) over either set blows Postgres's 65535 bound
        # parameter limit. Streaming the staged rows with .yield_per() and
        # filtering in Python keeps this at O(1) extra round trips and
        # bounded memory regardless of table size.
        known_cves = set(session.execute(text("SELECT cve_id FROM canonical.cve")).scalars().all())

        distinct_staged_cves: set[str] = set()
        matched_cve_ids: set[str] = set()
        rows_inserted = 0
        buffer: list[dict] = []

        result = session.execute(
            select(
                EpssScoresRaw.cve_id, EpssScoresRaw.snapshot_date,
                EpssScoresRaw.epss_score, EpssScoresRaw.percentile,
            )
        ).yield_per(_CHUNK_SIZE)

        for cve_id, snapshot_date, epss_score, percentile in result:
            distinct_staged_cves.add(cve_id)
            if cve_id not in known_cves:
                continue
            matched_cve_ids.add(cve_id)
            buffer.append(
                {
                    "cve_id": cve_id,
                    "snapshot_date": snapshot_date,
                    "epss_score": epss_score,
                    "percentile": percentile,
                    "is_observed": True,
                    "fill_method": "observed",
                }
            )
            if len(buffer) >= _CHUNK_SIZE:
                rows_inserted += _flush(session, buffer)
                buffer = []

        if buffer:
            rows_inserted += _flush(session, buffer)

    log_with_fields(
        logger, logging.INFO, "clean_epss complete",
        rows_staged=rows_staged_count,
        distinct_cves_in_staging=len(distinct_staged_cves),
        distinct_cves_matched_to_canonical=len(matched_cve_ids),
        cve_match_rate=round(len(matched_cve_ids) / len(distinct_staged_cves), 4) if distinct_staged_cves else 0.0,
        epss_timeline_rows_inserted=rows_inserted,
    )


def _flush(session, buffer: list[dict]) -> int:
    stmt = pg_insert(EpssTimeline).values(buffer)
    stmt = stmt.on_conflict_do_update(
        index_elements=["cve_id", "snapshot_date"],
        set_={
            "epss_score": stmt.excluded.epss_score,
            "percentile": stmt.excluded.percentile,
            "is_observed": stmt.excluded.is_observed,
            "fill_method": stmt.excluded.fill_method,
        },
    )
    session.execute(stmt)
    return len(buffer)


if __name__ == "__main__":
    main()
