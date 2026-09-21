"""initial schema

Applies database/schema.sql verbatim — that file is the DDL source of
truth for the initial 4-schema layout (staging/canonical/features/training).
Every statement in it uses IF NOT EXISTS, so this revision is safe to run
even if `vsp db init` already applied the same DDL directly. Incremental
schema changes from here on should be made via `models.py` +
`alembic revision --autogenerate`, not by hand-editing schema.sql.

Revision ID: 9a065e8ca641
Revises:
Create Date: 2026-08-07 10:05:25.219912

"""
from pathlib import Path
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '9a065e8ca641'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA_SQL_PATH = Path(__file__).resolve().parents[2] / "schema.sql"
SCHEMAS = ["staging", "canonical", "features", "training"]


def upgrade() -> None:
    op.execute(SCHEMA_SQL_PATH.read_text())


def downgrade() -> None:
    for schema in SCHEMAS:
        op.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
