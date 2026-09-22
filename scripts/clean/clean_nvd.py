"""
Cleans staging.nvd_cve_raw into the canonical schema: one current row per
CVE (canonical.cve), its CVSS metrics (canonical.cvss_metric, exactly one
flagged is_primary per CVE per config.cvss.preference_order), its CWE
mappings (canonical.cve_cwe_map), and its vendor/product CPE breakdown
(canonical.cpe_product, vendor-normalized via generic string cleanup only).

staging.nvd_cve_raw is append-only (one row per fetch, not deduplicated) —
this script picks, per cve_id, the row with the latest fetched_at (ties
broken by staging_id) as the current version of that CVE.

Idempotent: for every cve_id touched by a run, existing cvss_metric /
cve_cwe_map / cpe_product rows for that cve_id are deleted and replaced
before re-insert (canonical.cve itself is upserted). Safe to re-run.

CWE mapping requires canonical.cwe to already be populated (FK) — run
clean_cwe.py first. A weakness referencing a cwe_id not in canonical.cwe
(most commonly a deprecated/withdrawn CWE ID) is skipped and counted rather
than failing the whole run.

vendor_normalized is computed with generic string cleanup ONLY (see
scripts/common/vendor_normalize.py) — never via config/vendor_aliases.yaml,
which is a KEV-specific translation table for a different purpose. See that
module's docstring for why mixing the two would leak the KEV label into a
feature available for every CVE.

Usage: python -m scripts.clean.clean_nvd
Also reachable via `vsp clean nvd`.
"""

from __future__ import annotations

import logging
import re
from datetime import date, datetime, timezone

from sqlalchemy import delete, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from config.config_schema import get_config
from database.engine import session_scope
from database.models import Cve, CveCweMap, CpeProduct, CvssMetric, NvdCveRaw
from scripts.common.cve_id import is_valid_cve_id
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.common.vendor_normalize import generic_normalize

logger = get_logger(__name__, category="clean")

_CWE_ID_RE = re.compile(r"^CWE-\d+$")
_CHUNK_SIZE = 3000  # keeps every bulk statement well under Postgres's 65535 bound-parameter limit

# NVD field name -> canonical.cvss_metric column. v3.0/v3.1/v4.0 all share
# the AV/AC/PR/UI axis vocabulary; v4.0 renames the three impact axes
# (vulnConfidentialityImpact etc. — it also has sub-component impact axes,
# not used here). v2.0 uses a wholly different vocabulary
# (accessVector/accessComplexity/authentication, no UI axis) that doesn't
# map onto AV/AC/PR/UI, so those four columns are left null for v2.0 rows
# rather than guessed at.
_CVSS_ROW_COLUMNS = (
    "attack_vector", "attack_complexity", "privileges_required", "user_interaction",
    "confidentiality_impact", "integrity_impact", "availability_impact",
)
_AV_AC_PR_UI_FIELD_MAP = {
    "attackVector": "attack_vector",
    "attackComplexity": "attack_complexity",
    "privilegesRequired": "privileges_required",
    "userInteraction": "user_interaction",
}
_V2_V3_IMPACT_FIELD_MAP = {
    "confidentialityImpact": "confidentiality_impact",
    "integrityImpact": "integrity_impact",
    "availabilityImpact": "availability_impact",
}
_V4_IMPACT_FIELD_MAP = {
    "vulnConfidentialityImpact": "confidentiality_impact",
    "vulnIntegrityImpact": "integrity_impact",
    "vulnAvailabilityImpact": "availability_impact",
}
_METRIC_KEY_TO_VERSION = {
    "cvssMetricV2": "2.0",
    "cvssMetricV30": "3.0",
    "cvssMetricV31": "3.1",
    "cvssMetricV40": "4.0",
}


def _latest_rows_by_cve(session) -> dict[str, NvdCveRaw]:
    rows = session.execute(select(NvdCveRaw)).scalars().all()
    latest: dict[str, NvdCveRaw] = {}
    for row in rows:
        current = latest.get(row.cve_id)
        if current is None or (row.fetched_at, row.staging_id) > (current.fetched_at, current.staging_id):
            latest[row.cve_id] = row
    return latest


def _primary_description(payload: dict) -> str | None:
    for d in payload.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value")
    return None


def _parse_date(value: str) -> date:
    dt = datetime.fromisoformat(value)
    return dt.date()


def _extract_cvss_rows(cve_id: str, payload: dict, preference_order: list[str]) -> list[dict]:
    metrics = payload.get("metrics", {})
    by_key: dict[tuple[str, str], dict] = {}  # (version, source) -> row, first entry wins

    for metric_key, version in _METRIC_KEY_TO_VERSION.items():
        for entry in metrics.get(metric_key, []):
            source = entry.get("source") or "nvd"
            key = (version, source)
            if key in by_key:
                continue
            cvss_data = entry.get("cvssData", {})
            row = {
                "cve_id": cve_id,
                "cvss_version": version,
                "vector_string": cvss_data.get("vectorString", ""),
                "base_score": cvss_data.get("baseScore"),
                "base_severity": entry.get("baseSeverity") or cvss_data.get("baseSeverity"),
                "scope": cvss_data.get("scope"),
                "is_primary": False,
                "source": source,
                **{col: None for col in _CVSS_ROW_COLUMNS},
            }
            if version != "2.0":
                for src_field, dst_field in _AV_AC_PR_UI_FIELD_MAP.items():
                    row[dst_field] = cvss_data.get(src_field)
            impact_map = _V4_IMPACT_FIELD_MAP if version == "4.0" else _V2_V3_IMPACT_FIELD_MAP
            for src_field, dst_field in impact_map.items():
                row[dst_field] = cvss_data.get(src_field)
            by_key[key] = row

    rows = list(by_key.values())
    if rows:
        for preferred in preference_order:
            candidates = [r for r in rows if r["cvss_version"] == preferred]
            if candidates:
                candidates[0]["is_primary"] = True
                break
    return rows


def _extract_cwe_ids(payload: dict) -> set[tuple[str, str]]:
    """Returns (cwe_id, source) pairs — source is the real per-weakness
    sourceIdentifier (e.g. 'nvd@nist.gov' for NVD's own analysis, or a
    CNA's identifier for a CNA-supplied weakness), NOT a hardcoded literal.
    This matters because features built on top of this (see
    scripts/features/build_landmark_dataset.py) must be able to tell CNA-
    sourced (available at publication time) from NVD-sourced (added only
    once NVD analyst-reviews the CVE, which happens preferentially for
    KEV-listed CVEs — see docs/enrichment_leakage.md) CWE assignments."""
    pairs: set[tuple[str, str]] = set()
    for w in payload.get("weaknesses", []):
        source = w.get("source") or payload.get("sourceIdentifier") or "unknown"
        for desc in w.get("description", []):
            value = desc.get("value", "")
            if _CWE_ID_RE.match(value):
                pairs.add((value, source))
    return pairs


def _extract_cpe_rows(cve_id: str, payload: dict) -> list[dict]:
    seen_uris: set[str] = set()
    rows = []
    for config_block in payload.get("configurations", []):
        for node in config_block.get("nodes", []):
            for match in node.get("cpeMatch", []):
                uri = match.get("criteria")
                if not uri or uri in seen_uris:
                    continue
                seen_uris.add(uri)
                parts = uri.split(":")
                if len(parts) < 5:
                    continue
                vendor_raw = parts[3].replace("_", " ")
                product_raw = parts[4].replace("_", " ")
                rows.append(
                    {
                        "cve_id": cve_id,
                        "vendor_raw": vendor_raw,
                        "vendor_normalized": generic_normalize(vendor_raw),
                        "product_raw": product_raw,
                        "product_normalized": generic_normalize(product_raw),
                        "cpe23_uri": uri,
                    }
                )
    return rows


def main(*, test: bool = False) -> None:
    cfg = get_config()

    with session_scope(test=test) as session:
        latest_by_cve = _latest_rows_by_cve(session)
        rows_staged = session.execute(select(NvdCveRaw.staging_id)).scalars().all()
        rows_staged_count = len(rows_staged)

        malformed = [cid for cid in latest_by_cve if not is_valid_cve_id(cid, cfg)]
        for cid in malformed:
            del latest_by_cve[cid]

        if not latest_by_cve:
            log_with_fields(
                logger, logging.INFO, "No staged NVD rows to clean",
                rows_staged=rows_staged_count, malformed_cve_ids_skipped=len(malformed),
            )
            return

        existing_cwe_ids = set(session.execute(text("SELECT cwe_id FROM canonical.cwe")).scalars().all())

        cve_ids = list(latest_by_cve.keys())

        cve_values = []
        cvss_rows: list[dict] = []
        cwe_map_rows: list[dict] = []
        cpe_rows: list[dict] = []
        cwe_mapped = 0
        cwe_skipped_missing_catalog = 0
        primary_cvss_count = 0

        for cve_id, raw_row in latest_by_cve.items():
            payload = raw_row.payload
            this_cvss = _extract_cvss_rows(cve_id, payload, cfg.cvss.preference_order)
            cvss_rows.extend(this_cvss)
            primary_cvss_count += sum(1 for r in this_cvss if r["is_primary"])

            cve_values.append(
                {
                    "cve_id": cve_id,
                    "published_date": _parse_date(payload["published"]),
                    "last_modified_date": _parse_date(payload["lastModified"]),
                    "description": _primary_description(payload),
                    "vuln_status": payload.get("vulnStatus"),
                    "source_last_fetched_at": raw_row.fetched_at,
                    # no CVSS metric of any tracked version was reported for this CVE —
                    # row is kept (never dropped), just flagged for downstream handling.
                    "cvss_missing": not this_cvss,
                }
            )

            for cwe_id, cwe_source in _extract_cwe_ids(payload):
                if cwe_id in existing_cwe_ids:
                    cwe_map_rows.append({"cve_id": cve_id, "cwe_id": cwe_id, "source": cwe_source})
                    cwe_mapped += 1
                else:
                    cwe_skipped_missing_catalog += 1

            cpe_rows.extend(_extract_cpe_rows(cve_id, payload))

        # --- replace-in-place: clear existing derived rows for these CVEs ---
        for i in range(0, len(cve_ids), _CHUNK_SIZE):
            chunk = cve_ids[i : i + _CHUNK_SIZE]
            session.execute(delete(CvssMetric).where(CvssMetric.cve_id.in_(chunk)))
            session.execute(delete(CveCweMap).where(CveCweMap.cve_id.in_(chunk)))
            session.execute(delete(CpeProduct).where(CpeProduct.cve_id.in_(chunk)))

        # --- upsert canonical.cve ---
        for i in range(0, len(cve_values), _CHUNK_SIZE):
            chunk = cve_values[i : i + _CHUNK_SIZE]
            stmt = pg_insert(Cve).values(chunk)
            stmt = stmt.on_conflict_do_update(
                index_elements=["cve_id"],
                set_={
                    "published_date": stmt.excluded.published_date,
                    "last_modified_date": stmt.excluded.last_modified_date,
                    "description": stmt.excluded.description,
                    "vuln_status": stmt.excluded.vuln_status,
                    "source_last_fetched_at": stmt.excluded.source_last_fetched_at,
                    "cvss_missing": stmt.excluded.cvss_missing,
                },
            )
            session.execute(stmt)

        for i in range(0, len(cvss_rows), _CHUNK_SIZE):
            session.execute(pg_insert(CvssMetric).values(cvss_rows[i : i + _CHUNK_SIZE]))

        for i in range(0, len(cwe_map_rows), _CHUNK_SIZE):
            chunk = cwe_map_rows[i : i + _CHUNK_SIZE]
            session.execute(
                pg_insert(CveCweMap).values(chunk).on_conflict_do_nothing(
                    index_elements=["cve_id", "cwe_id", "source"]
                )
            )

        for i in range(0, len(cpe_rows), _CHUNK_SIZE):
            session.execute(pg_insert(CpeProduct).values(cpe_rows[i : i + _CHUNK_SIZE]))

    log_with_fields(
        logger, logging.INFO, "clean_nvd complete",
        rows_staged=rows_staged_count,
        distinct_cves=len(cve_ids),
        malformed_cve_ids_skipped=len(malformed),
        cvss_metric_rows=len(cvss_rows),
        cves_with_primary_cvss=primary_cvss_count,
        cves_with_cvss_missing=sum(1 for v in cve_values if v["cvss_missing"]),
        cve_cwe_map_rows_inserted=cwe_mapped,
        cve_cwe_map_rows_skipped_missing_catalog=cwe_skipped_missing_catalog,
        cpe_product_rows=len(cpe_rows),
    )
    if cwe_skipped_missing_catalog:
        logger.warning(
            f"{cwe_skipped_missing_catalog} CWE mappings skipped — referenced cwe_id not found in "
            "canonical.cwe (run clean_cwe.py if it hasn't run yet; otherwise these are most likely "
            "deprecated/withdrawn CWE IDs no longer in the current catalog)"
        )


if __name__ == "__main__":
    main()
