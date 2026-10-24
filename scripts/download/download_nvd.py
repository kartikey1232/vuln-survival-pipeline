"""
Downloads CVE records from the NVD API 2.0 (the current, only-working
source — the old downloadable JSON feed files were retired by NVD in
December 2023).

Paginated via startIndex/resultsPerPage (max 2000/page), and date-windowed
via pubStartDate/pubEndDate since NVD enforces a ~120-day max span per
request for date-filtered queries. Rate-limited to 5 requests/30s
unauthenticated or 50/30s with an API key (config.sources.nvd.api_key /
NVD_API_KEY env var) via a shared SlidingWindowRateLimiter.

Scope (config.sources.nvd.scope, or --start-date/--end-date/--mode):
  bounded       -> last `bounded_lookback_days` days by publish date (default: 2 years)
  full_backfill -> full_backfill_start_date (1999-01-01) through today

Each page's raw JSON response is saved to
data/raw/nvd/<window_start>_<window_end>/page_<NNNN>.json and recorded in
staging.file_manifest — already-downloaded pages are skipped on rerun, so
re-running the same window is a fast no-op. Every CVE in every page is
inserted into staging.nvd_cve_raw (append-only: one row per (cve_id,
fetched_at) pull, by design — this is not deduplicated until clean_nvd.py).

Usage: python -m scripts.download.download_nvd [--start-date] [--end-date] [--mode bounded|full_backfill]
Also reachable via `vsp download nvd`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import date, datetime, timedelta, timezone

from config.config_schema import get_config
from database.engine import session_scope
from database.models import NvdCveRaw
from scripts.common.http import DownloadError, SlidingWindowRateLimiter, fetch_json, make_client
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.common.manifest import already_downloaded, upsert_manifest

logger = get_logger(__name__, category="download")


def _nvd_datetime(d: date, *, end_of_day: bool = False) -> str:
    t = "23:59:59.999" if end_of_day else "00:00:00.000"
    return f"{d.isoformat()}T{t}"


def _windows(start: date, end: date, max_span_days: int) -> list[tuple[date, date]]:
    windows = []
    cursor = start
    while cursor <= end:
        window_end = min(cursor + timedelta(days=max_span_days - 1), end)
        windows.append((cursor, window_end))
        cursor = window_end + timedelta(days=1)
    return windows


def _resolve_range(cfg, start_date: str | None, end_date: str | None, mode: str | None) -> tuple[date, date]:
    nvd_cfg = cfg.sources.nvd
    today = datetime.now(tz=timezone.utc).date()
    effective_mode = mode or nvd_cfg.scope.mode

    if start_date:
        start = date.fromisoformat(start_date)
    elif effective_mode == "full_backfill":
        start = date.fromisoformat(nvd_cfg.scope.full_backfill_start_date)
    else:
        start = today - timedelta(days=nvd_cfg.scope.bounded_lookback_days)

    end = date.fromisoformat(end_date) if end_date else today
    return start, end


def _parse_nvd_datetime(value: str) -> datetime:
    """NVD timestamps are UTC but carry no offset (e.g. '2024-01-02T00:00:00.000')."""
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def _fetch_window(
    window_start: date,
    window_end: date,
    client,
    rate_limiter: SlidingWindowRateLimiter,
    cfg,
    results_per_page: int | None = None,
) -> tuple[int, int]:
    """Returns (pages_fetched, cves_staged) for this window.

    `results_per_page` overrides config for this run. Page files are named by
    page number, so a non-default page size gets its own window directory
    (<start>_<end>_pp<N>): a re-run can then never skip a page that was
    cached under a different page size."""
    nvd_cfg = cfg.sources.nvd
    per_page = results_per_page or nvd_cfg.results_per_page
    suffix = "" if per_page == nvd_cfg.results_per_page else f"_pp{per_page}"
    window_dir = cfg.paths.data_raw / "nvd" / f"{window_start.isoformat()}_{window_end.isoformat()}{suffix}"
    start_index = 0
    total_results: int | None = None
    pages_fetched = 0
    cves_staged = 0

    while total_results is None or start_index < total_results:
        page_num = start_index // per_page
        dest_path = window_dir / f"page_{page_num:04d}.json"
        file_path_str = str(dest_path.relative_to(cfg.project_root))

        with session_scope() as session:
            existing = already_downloaded(session, source="nvd", file_path=file_path_str)

        if existing is None:
            params = {
                "resultsPerPage": per_page,
                "startIndex": start_index,
                "pubStartDate": _nvd_datetime(window_start),
                "pubEndDate": _nvd_datetime(window_end, end_of_day=True),
            }
            headers = {"apiKey": nvd_cfg.api_key} if nvd_cfg.api_key else None

            try:
                payload = await fetch_json(
                    client, nvd_cfg.base_url, params=params, headers=headers,
                    retry_cfg=nvd_cfg.retry, rate_limiter=rate_limiter,
                )
            except DownloadError as exc:
                cause = exc.__cause__.last_attempt.exception() if hasattr(exc.__cause__, "last_attempt") else None
                logger.exception("NVD page fetch failed", extra={"extra_fields": {
                    "window": f"{window_start}_{window_end}", "start_index": start_index,
                    "results_per_page": per_page, "last_error": repr(cause),
                }})
                raise

            window_dir.mkdir(parents=True, exist_ok=True)
            dest_path.write_text(json.dumps(payload))
            byte_size = dest_path.stat().st_size

            from scripts.common.checksums import sha256_file
            sha = sha256_file(dest_path)

            fetched_at = datetime.now(tz=timezone.utc)
            vulns = payload.get("vulnerabilities", [])

            with session_scope() as session:
                upsert_manifest(
                    session,
                    source="nvd",
                    file_path=file_path_str,
                    url=nvd_cfg.base_url,
                    fetched_at=fetched_at,
                    sha256=sha,
                    byte_size=byte_size,
                    row_count=len(vulns),
                    status="verified",
                    http_status=200,
                )
                for item in vulns:
                    cve = item["cve"]
                    session.add(
                        NvdCveRaw(
                            cve_id=cve["id"],
                            fetched_at=fetched_at,
                            last_modified_src=_parse_nvd_datetime(cve["lastModified"]),
                            payload=cve,
                        )
                    )
                cves_staged += len(vulns)

            total_results = payload.get("totalResults", 0)
        else:
            payload = json.loads((cfg.project_root / file_path_str).read_text())
            total_results = payload.get("totalResults", 0)

        pages_fetched += 1
        start_index += per_page

    return pages_fetched, cves_staged


async def _run(start_date: str | None, end_date: str | None, mode: str | None,
               results_per_page: int | None = None) -> None:
    cfg = get_config()
    nvd_cfg = cfg.sources.nvd
    start, end = _resolve_range(cfg, start_date, end_date, mode)

    if start > end:
        logger.info("No date range to download for NVD")
        return

    windows = _windows(start, end, nvd_cfg.max_date_window_days)
    rate_limiter = SlidingWindowRateLimiter(nvd_cfg.effective_rate_limit, nvd_cfg.rate_limit.window_seconds)

    total_pages = 0
    total_cves = 0
    async with make_client() as client:
        for window_start, window_end in windows:
            pages, cves = await _fetch_window(window_start, window_end, client, rate_limiter, cfg, results_per_page)
            total_pages += pages
            total_cves += cves
            log_with_fields(
                logger, logging.INFO, "NVD window complete",
                window=f"{window_start}_{window_end}", pages=pages, cves_staged=cves,
            )

    log_with_fields(
        logger, logging.INFO, "NVD download complete",
        date_range=f"{start}_{end}", windows=len(windows), total_pages=total_pages, total_cves_staged=total_cves,
        authenticated=bool(nvd_cfg.api_key),
    )


def main(*, start_date: str | None = None, end_date: str | None = None, mode: str | None = None,
         results_per_page: int | None = None) -> None:
    asyncio.run(_run(start_date, end_date, mode, results_per_page))


if __name__ == "__main__":
    main()
