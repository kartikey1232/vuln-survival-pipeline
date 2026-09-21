"""
Cleans the CWE catalog into canonical.cwe and canonical.cwe_relationship.

Unlike the other clean_*.py scripts, this one does NOT read staging.cwe_raw
row-by-row — per download_cwe.py's docstring, relationship extraction needs
the whole XML tree (relationships span across <Weakness> elements), so this
re-parses the extracted XML file directly. The path is resolved from the
most recent verified staging.file_manifest row for source='cwe' (its
file_path points at the .zip; download_cwe.py always extracts the XML
alongside it with the same date-stamped basename).

canonical.cwe_relationship.relationship_type's CHECK constraint covers the
full CWE 4.x+ Nature vocabulary observed in this catalog: ChildOf,
ParentOf, PeerOf, CanFollow, CanPrecede, CanAlsoBe, Requires, StartsWith.
(It originally covered only the first four — widened via a hand-written
Alembic migration once the other four turned up in the real data. Nature
values outside even this set are still skipped and counted rather than
crashing the load, in case a future CWE release adds new ones.)

Usage: python -m scripts.clean.clean_cwe
Also reachable via `vsp clean cwe`.
"""

from __future__ import annotations

import logging
from datetime import date, datetime

from lxml import etree
from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from config.config_schema import get_config
from database.engine import session_scope
from database.models import Cwe, CweRelationship
from scripts.common.logging_utils import get_logger, log_with_fields

logger = get_logger(__name__, category="clean")

_VALID_RELATIONSHIP_TYPES = {
    "ChildOf", "ParentOf", "PeerOf", "CanFollow",
    "CanPrecede", "CanAlsoBe", "Requires", "StartsWith",
}


def _local_name(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _latest_cwe_xml_path(session, cfg) -> object | None:
    row = session.execute(
        text(
            "SELECT file_path FROM staging.file_manifest "
            "WHERE source = 'cwe' AND status = 'verified' "
            "ORDER BY fetched_at DESC LIMIT 1"
        )
    ).first()
    if row is None:
        return None
    zip_path = cfg.project_root / row[0]
    xml_path = zip_path.with_suffix(".xml")
    return xml_path if xml_path.exists() else None


def _text_of(elem) -> str | None:
    if elem is None:
        return None
    value = "".join(elem.itertext()).strip()
    return value or None


def main(*, test: bool = False) -> None:
    cfg = get_config()

    with session_scope(test=test) as session:
        xml_path = _latest_cwe_xml_path(session, cfg)
        if xml_path is None:
            log_with_fields(logger, logging.INFO, "No staged CWE catalog found to clean")
            return

        tree = etree.parse(str(xml_path))
        root = tree.getroot()

        cwe_values = []
        relationship_pairs: set[tuple[str, str, str]] = set()
        skipped_relationship_types: dict[str, int] = {}

        for elem in root.iter():
            if _local_name(elem.tag) != "Weakness":
                continue
            cwe_id = f"CWE-{elem.get('ID')}"
            description = None
            for child in elem:
                tag = _local_name(child.tag)
                if tag == "Description":
                    description = _text_of(child)
                elif tag == "Related_Weaknesses":
                    for rel in child:
                        if _local_name(rel.tag) != "Related_Weakness":
                            continue
                        nature = rel.get("Nature")
                        parent_id = f"CWE-{rel.get('CWE_ID')}"
                        if nature not in _VALID_RELATIONSHIP_TYPES:
                            skipped_relationship_types[nature] = skipped_relationship_types.get(nature, 0) + 1
                            continue
                        relationship_pairs.add((cwe_id, parent_id, nature))

            cwe_values.append(
                {
                    "cwe_id": cwe_id,
                    "name": elem.get("Name") or cwe_id,
                    "description": description,
                    "abstraction": elem.get("Abstraction"),
                    "status": elem.get("Status"),
                }
            )

        stmt = pg_insert(Cwe).values(cwe_values)
        stmt = stmt.on_conflict_do_update(
            index_elements=["cwe_id"],
            set_={
                "name": stmt.excluded.name,
                "description": stmt.excluded.description,
                "abstraction": stmt.excluded.abstraction,
                "status": stmt.excluded.status,
            },
        )
        session.execute(stmt)

        known_ids = {v["cwe_id"] for v in cwe_values}
        relationship_values = [
            {"child_cwe_id": child, "parent_cwe_id": parent, "relationship_type": nature}
            for child, parent, nature in relationship_pairs
            if child in known_ids and parent in known_ids
        ]
        relationship_dropped_dangling = len(relationship_pairs) - len(relationship_values)

        if relationship_values:
            session.execute(
                pg_insert(CweRelationship)
                .values(relationship_values)
                .on_conflict_do_nothing(
                    index_elements=["child_cwe_id", "parent_cwe_id", "relationship_type"]
                )
            )

    log_with_fields(
        logger, logging.INFO, "clean_cwe complete",
        source_xml=str(xml_path),
        cwe_rows=len(cwe_values),
        relationship_rows_inserted=len(relationship_values),
        relationship_rows_skipped_invalid_type=sum(skipped_relationship_types.values()),
        relationship_rows_dropped_dangling_ref=relationship_dropped_dangling,
    )
    if skipped_relationship_types:
        logger.warning(
            "canonical.cwe_relationship.relationship_type CHECK constraint doesn't cover the "
            f"full CWE vocabulary — skipped by Nature: {skipped_relationship_types}"
        )


if __name__ == "__main__":
    main()
