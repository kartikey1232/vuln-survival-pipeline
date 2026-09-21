"""Introspects information_schema on the test DB to assert every table,
primary key, foreign key, and unique constraint from database/schema.sql
actually exists as applied — not just that schema.sql parses."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

EXPECTED_TABLE_COUNTS = {
    "staging": 6,
    "canonical": 10,
    "features": 3,
    "training": 3,
}

EXPECTED_TABLES = {
    "staging": {
        "file_manifest",
        "nvd_cve_raw",
        "epss_scores_raw",
        "kev_raw",
        "exploitdb_raw",
        "cwe_raw",
    },
    "canonical": {
        "cve",
        "cvss_metric",
        "cwe",
        "cwe_relationship",
        "cve_cwe_map",
        "cpe_product",
        "epss_timeline",
        "kev",
        "exploitdb",
        "exploitdb_cve_map",
    },
    "features": {"static_features", "temporal_features", "derived_features"},
    "training": {"survival_labels", "training_dataset", "prediction"},
}


def _tables_in_schema(session: Session, schema: str) -> set[str]:
    rows = session.execute(
        text("SELECT table_name FROM information_schema.tables WHERE table_schema = :s"),
        {"s": schema},
    ).scalars().all()
    return set(rows)


def test_all_schemas_exist(db_session: Session) -> None:
    rows = db_session.execute(
        text("SELECT schema_name FROM information_schema.schemata WHERE schema_name IN "
             "('staging','canonical','features','training')")
    ).scalars().all()
    assert set(rows) == {"staging", "canonical", "features", "training"}


def test_expected_tables_present(db_session: Session) -> None:
    for schema, expected in EXPECTED_TABLES.items():
        actual = _tables_in_schema(db_session, schema)
        assert expected <= actual, f"missing tables in {schema}: {expected - actual}"


def test_table_counts_match(db_session: Session) -> None:
    for schema, expected_count in EXPECTED_TABLE_COUNTS.items():
        actual = len(_tables_in_schema(db_session, schema))
        assert actual == expected_count, f"{schema}: expected {expected_count} tables, found {actual}"


def test_every_table_has_primary_key(db_session: Session) -> None:
    for schema, tables in EXPECTED_TABLES.items():
        pk_tables = set(
            db_session.execute(
                text(
                    "SELECT tc.table_name FROM information_schema.table_constraints tc "
                    "WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = :s"
                ),
                {"s": schema},
            ).scalars().all()
        )
        missing = tables - pk_tables
        assert not missing, f"{schema} tables missing a primary key: {missing}"


def test_foreign_keys_present(db_session: Session) -> None:
    fk_count = db_session.execute(
        text(
            "SELECT count(*) FROM information_schema.table_constraints "
            "WHERE constraint_type = 'FOREIGN KEY' AND table_schema IN "
            "('staging','canonical','features','training')"
        )
    ).scalar_one()
    assert fk_count >= 18, f"expected at least 18 foreign keys, found {fk_count}"


def test_key_indexes_present(db_session: Session) -> None:
    expected_indexes = {
        ("canonical", "epss_timeline", "idx_epsstl_date"),
        ("canonical", "cve", "idx_cve_published"),
        ("canonical", "cpe_product", "idx_cpe_vendor"),
        ("features", "temporal_features", "idx_tempfeat_checkpoint"),
        ("training", "survival_labels", "idx_labels_checkpoint"),
        ("staging", "epss_scores_raw", "idx_epss_raw_date"),
    }
    for schema, table, index_name in expected_indexes:
        found = db_session.execute(
            text(
                "SELECT count(*) FROM pg_indexes WHERE schemaname = :schema "
                "AND tablename = :table AND indexname = :idx"
            ),
            {"schema": schema, "table": table, "idx": index_name},
        ).scalar_one()
        assert found == 1, f"expected index {index_name} on {schema}.{table}"


def test_epss_scores_raw_unique_constraint_blocks_overwrite(db_session: Session) -> None:
    """The core append-only guarantee: two rows for the same (cve_id,
    snapshot_date) must be structurally impossible."""
    db_session.execute(
        text(
            "INSERT INTO staging.epss_scores_raw (cve_id, snapshot_date, epss_score, percentile) "
            "VALUES ('CVE-2024-00001', '2024-01-01', 0.5, 0.9)"
        )
    )
    db_session.commit()

    from sqlalchemy.exc import IntegrityError

    try:
        db_session.execute(
            text(
                "INSERT INTO staging.epss_scores_raw (cve_id, snapshot_date, epss_score, percentile) "
                "VALUES ('CVE-2024-00001', '2024-01-01', 0.9, 0.99)"
            )
        )
        db_session.commit()
        raised = False
    except IntegrityError:
        db_session.rollback()
        raised = True

    assert raised, "duplicate (cve_id, snapshot_date) should violate the UNIQUE constraint"
