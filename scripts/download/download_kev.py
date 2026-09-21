"""
Downloads the CISA Known Exploited Vulnerabilities (KEV) catalog — a single
JSON file, full catalog every time (no per-day history from CISA directly).
Saved as a dated snapshot under data/raw/kev/, parsed, and loaded into
staging.kev_raw (one row per CVE in the catalog, all sharing this run's
fetched_at timestamp) so clean_kev.py can later diff snapshots to detect
newly-added CVEs.

Usage: python -m scripts.download.download_kev
Also reachable via `vsp download kev`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import date, datetime, timezone

from config.config_schema import get_config
from database.engine import session_scope
from database.models import KevRaw
from scripts.common.http import DownloadError, download_file, make_client
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.common.manifest import already_downloaded, upsert_manifest

logger = get_logger(__name__, category="download")


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    return date.fromisoformat(value)


async def _run() -> None:
    cfg = get_config()
    kev_cfg = cfg.sources.kev

    fetched_at = datetime.now(tz=timezone.utc)
    dest_dir = cfg.paths.data_raw / "kev"
    dest_path = dest_dir / f"known_exploited_vulnerabilities_{fetched_at:%Y%m%d}.json"
    file_path_str = str(dest_path.relative_to(cfg.project_root))

    async with make_client() as client:
        with session_scope() as session:
            existing = already_downloaded(session, source="kev", file_path=file_path_str)
            if existing:
                logger.info("KEV catalog already downloaded today, skipping fetch", extra={
                    "extra_fields": {"file_path": file_path_str}
                })
            else:
                try:
                    result = await download_file(client, kev_cfg.url, dest_path, retry_cfg=kev_cfg.retry)
                except DownloadError:
                    logger.exception("KEV download failed")
                    raise

                payload = json.loads(dest_path.read_text())
                vulns = payload.get("vulnerabilities", [])

                upsert_manifest(
                    session,
                    source="kev",
                    file_path=file_path_str,
                    url=kev_cfg.url,
                    fetched_at=fetched_at,
                    sha256=result.sha256,
                    byte_size=result.byte_size,
                    row_count=len(vulns),
                    status="verified",
                    http_status=result.http_status,
                )

                for vuln in vulns:
                    session.add(
                        KevRaw(
                            cve_id=vuln["cveID"],
                            fetched_at=fetched_at,
                            date_added_src=_parse_date(vuln.get("dateAdded")),
                            vendor_project=vuln.get("vendorProject"),
                            product=vuln.get("product"),
                            vulnerability_name=vuln.get("vulnerabilityName"),
                            required_action=vuln.get("requiredAction"),
                            due_date=_parse_date(vuln.get("dueDate")),
                            known_ransomware=vuln.get("knownRansomwareCampaignUse") == "Known",
                        )
                    )

                log_with_fields(
                    logger, logging.INFO, "KEV catalog downloaded and staged",
                    vulnerability_count=len(vulns), catalog_version=payload.get("catalogVersion"),
                )


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
