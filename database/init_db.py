"""
Applies database/schema.sql (the DDL source of truth) to the target
database. Idempotent — every statement in schema.sql uses IF NOT EXISTS, so
re-running is always safe.

Usage:
    python -m database.init_db                # apply to the main DB
    python -m database.init_db --drop-existing # destructive: drop schemas first
Also reachable via `vsp db init`.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import text

from database.engine import get_engine
from scripts.common.logging_utils import get_logger

logger = get_logger(__name__, category="db")

SCHEMA_SQL_PATH = Path(__file__).resolve().parent / "schema.sql"
SCHEMAS = ["staging", "canonical", "features", "training"]


def main(*, drop_existing: bool = False, test: bool = False) -> None:
    engine = get_engine(test=test)
    schema_sql = SCHEMA_SQL_PATH.read_text()

    with engine.begin() as conn:
        if drop_existing:
            logger.warning("Dropping existing schemas (destructive)", extra={"extra_fields": {"schemas": SCHEMAS}})
            for schema in SCHEMAS:
                conn.execute(text(f"DROP SCHEMA IF EXISTS {schema} CASCADE"))

        conn.exec_driver_sql(schema_sql)

    logger.info("Schema applied successfully", extra={"extra_fields": {"database": engine.url.database}})

    with engine.connect() as conn:
        counts = {}
        for schema in SCHEMAS:
            rows = conn.execute(
                text(
                    "SELECT count(*) FROM information_schema.tables "
                    "WHERE table_schema = :schema"
                ),
                {"schema": schema},
            ).scalar_one()
            counts[schema] = rows
        logger.info("Table counts per schema", extra={"extra_fields": counts})


if __name__ == "__main__":
    main()
