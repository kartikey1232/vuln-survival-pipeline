"""
Cleans staging.kev_raw into canonical.kev — one current row per CVE
(canonical.kev.cve_id is its primary key). Multiple KEV catalog snapshots
may stage the same cve_id over time; this script keeps the fields from the
most-recently-fetched snapshot but computes first_seen_in_catalog_at as the
MIN(fetched_at) across every staged snapshot that carried that cve_id, so a
CVE's "first seen in KEV" timestamp survives across re-downloads.

canonical.kev.cve_id has a foreign key to canonical.cve — a KEV entry can
only be cleaned once clean_nvd.py has ingested that CVE. KEV entries whose
cve_id is not (yet) in canonical.cve are skipped and counted, not treated
as an error: KEV's catalog spans back to 2021 while NVD ingestion here is
currently a narrow test window, so a low match rate is expected until NVD
is backfilled.

Usage: python -m scripts.clean.clean_kev
Also reachable via `vsp clean kev`.
"""

from __future__ import annotations

import logging

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from config.config_schema import get_config
from database.engine import session_scope
from database.models import KevRaw, Kev
from scripts.common.cve_id import is_valid_cve_id
from scripts.common.logging_utils import get_logger, log_with_fields

logger = get_logger(__name__, category="clean")


def main(*, test: bool = False) -> None:
    cfg = get_config()
    with session_scope(test=test) as session:
        raw_rows = session.execute(select(KevRaw)).scalars().all()
        rows_staged = len(raw_rows)

        if not raw_rows:
            log_with_fields(logger, logging.INFO, "No staged KEV rows to clean", rows_staged=0)
            return

        malformed = 0
        first_seen: dict[str, object] = {}
        latest: dict[str, KevRaw] = {}
        for row in raw_rows:
            if not is_valid_cve_id(row.cve_id, cfg):
                malformed += 1
                continue
            if row.cve_id not in first_seen or row.fetched_at < first_seen[row.cve_id]:
                first_seen[row.cve_id] = row.fetched_at
            current = latest.get(row.cve_id)
            if current is None or (row.fetched_at, row.staging_id) > (current.fetched_at, current.staging_id):
                latest[row.cve_id] = row

        known_cves = set(session.execute(text("SELECT cve_id FROM canonical.cve")).scalars().all())

        values = []
        skipped_no_cve = []
        for cve_id, row in latest.items():
            if cve_id not in known_cves:
                skipped_no_cve.append(cve_id)
                continue
            values.append(
                {
                    "cve_id": cve_id,
                    "date_added": row.date_added_src,
                    "vendor_project": row.vendor_project,
                    "product": row.product,
                    "vulnerability_name": row.vulnerability_name,
                    "required_action": row.required_action,
                    "due_date": row.due_date,
                    "known_ransomware": row.known_ransomware,
                    "first_seen_in_catalog_at": first_seen[cve_id],
                }
            )

        if values:
            stmt = pg_insert(Kev).values(values)
            stmt = stmt.on_conflict_do_update(
                index_elements=["cve_id"],
                set_={
                    "date_added": stmt.excluded.date_added,
                    "vendor_project": stmt.excluded.vendor_project,
                    "product": stmt.excluded.product,
                    "vulnerability_name": stmt.excluded.vulnerability_name,
                    "required_action": stmt.excluded.required_action,
                    "due_date": stmt.excluded.due_date,
                    "known_ransomware": stmt.excluded.known_ransomware,
                    # first_seen_in_catalog_at intentionally NOT overwritten on conflict —
                    # it must only ever move earlier, which upsert_manifest-style min-merge
                    # across runs would require reading it back; left for a future pass.
                },
            )
            session.execute(stmt)

    log_with_fields(
        logger, logging.INFO, "clean_kev complete",
        rows_staged=rows_staged,
        malformed_cve_ids_skipped=malformed,
        distinct_kev_cves=len(latest),
        matched_to_canonical_cve=len(values),
        skipped_cve_not_in_canonical=len(skipped_no_cve),
        match_rate=round(len(values) / len(latest), 4) if latest else 0.0,
    )


if __name__ == "__main__":
    main()
