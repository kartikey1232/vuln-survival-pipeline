"""
Shared pytest fixtures.

Tests run against a second local database (`vuln_survival_test`, see
.env `TEST_DB_NAME`) on the same Homebrew Postgres instance used for
development — never SQLite (would silently diverge from Postgres-only
features like JSONB and window functions) and never the production
database.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from database.engine import get_engine, session_scope
from database.init_db import main as init_db_main

_TRUNCATE_SCHEMAS = ["training", "features", "canonical", "staging"]


@pytest.fixture(scope="session", autouse=True)
def _test_schema() -> Iterator[None]:
    """Applies schema.sql to the test DB once per test session."""
    init_db_main(test=True)
    yield


@pytest.fixture()
def db_session() -> Iterator[Session]:
    with session_scope(test=True) as session:
        yield session


@pytest.fixture(autouse=True)
def _clean_tables() -> Iterator[None]:
    """Truncates every table in the test DB before each test, so tests never
    depend on execution order or leak fixtures into each other."""
    yield
    engine = get_engine(test=True)
    with engine.begin() as conn:
        for schema in _TRUNCATE_SCHEMAS:
            tables = conn.execute(
                text("SELECT table_name FROM information_schema.tables WHERE table_schema = :s"),
                {"s": schema},
            ).scalars().all()
            for table in tables:
                conn.execute(text(f'TRUNCATE TABLE "{schema}"."{table}" CASCADE'))
