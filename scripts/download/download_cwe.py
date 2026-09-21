"""
Downloads the MITRE CWE catalog (a single ZIP containing the full XML
weakness catalog), extracts it, and stages one staging.cwe_raw row per
<Weakness> element (id, name, description, and the serialized XML fragment
for audit/reprocessing). Relationship-graph extraction (ChildOf/ParentOf/...)
happens later in clean_cwe.py, which re-parses the XML directly rather than
per-row fragments, since relationships span across weaknesses.

Usage: python -m scripts.download.download_cwe
Also reachable via `vsp download cwe`.
"""

from __future__ import annotations

import asyncio
import logging
import zipfile
from datetime import datetime, timezone

from lxml import etree

from config.config_schema import get_config
from database.engine import session_scope
from database.models import CweRaw
from scripts.common.http import DownloadError, download_file, make_client
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.common.manifest import already_downloaded, upsert_manifest

logger = get_logger(__name__, category="download")

CWE_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}


def _local_name(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _extract_weaknesses(xml_path) -> list[dict]:
    tree = etree.parse(str(xml_path))
    root = tree.getroot()
    weaknesses = []
    for elem in root.iter():
        if _local_name(elem.tag) != "Weakness":
            continue
        cwe_id = f"CWE-{elem.get('ID')}"
        name = elem.get("Name")
        description = None
        for child in elem:
            if _local_name(child.tag) == "Description":
                description = "".join(child.itertext()).strip()
                break
        fragment = etree.tostring(elem, encoding="unicode")
        weaknesses.append(
            {"cwe_id": cwe_id, "name": name, "description": description, "raw_xml_fragment": fragment}
        )
    return weaknesses


async def _run() -> None:
    cfg = get_config()
    cwe_cfg = cfg.sources.cwe
    fetched_at = datetime.now(tz=timezone.utc)

    dest_dir = cfg.paths.data_raw / "cwe"
    zip_path = dest_dir / f"cwec_latest_{fetched_at:%Y%m%d}.zip"
    file_path_str = str(zip_path.relative_to(cfg.project_root))

    async with make_client() as client:
        with session_scope() as session:
            existing = already_downloaded(session, source="cwe", file_path=file_path_str)
            if existing:
                logger.info("CWE catalog already downloaded today, skipping fetch")
                return

            try:
                result = await download_file(client, cwe_cfg.url, zip_path, retry_cfg=cwe_cfg.retry)
            except DownloadError:
                logger.exception("CWE download failed")
                raise

            with zipfile.ZipFile(zip_path) as zf:
                xml_names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
                if not xml_names:
                    raise DownloadError(f"No XML file found inside {zip_path}")
                xml_path = dest_dir / f"cwec_latest_{fetched_at:%Y%m%d}.xml"
                with zf.open(xml_names[0]) as src, xml_path.open("wb") as dst:
                    dst.write(src.read())

            weaknesses = _extract_weaknesses(xml_path)

            upsert_manifest(
                session,
                source="cwe",
                file_path=file_path_str,
                url=cwe_cfg.url,
                fetched_at=fetched_at,
                sha256=result.sha256,
                byte_size=result.byte_size,
                row_count=len(weaknesses),
                status="verified",
                http_status=result.http_status,
            )

            for w in weaknesses:
                session.add(CweRaw(fetched_at=fetched_at, **w))

            log_with_fields(logger, logging.INFO, "CWE catalog downloaded and staged", weakness_count=len(weaknesses))


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
