"""add cvss_missing flag to cve and static_features

Hand-written rather than `alembic revision --autogenerate`: this project's
tables were created by executing schema.sql's raw DDL, so Postgres assigned
its own default constraint/index names, which don't match the names
SQLAlchemy's naming convention would generate from models.py. Autogenerate
diffs against those default names and — on top of the two real column
additions below — proposes dropping and recreating essentially every index
and CHECK constraint in the database purely over naming, plus (spuriously)
dropping the alembic_version table itself. None of that is a schema change
this revision is about, so it's written by hand instead: exactly the two
columns requested.

Revision ID: 4a0248f4d0fa
Revises: 9a065e8ca641
Create Date: 2026-09-20

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "4a0248f4d0fa"
down_revision: Union[str, Sequence[str], None] = "9a065e8ca641"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "cve",
        sa.Column("cvss_missing", sa.Boolean(), nullable=False, server_default=sa.false()),
        schema="canonical",
    )
    op.alter_column("cve", "cvss_missing", server_default=None, schema="canonical")
    op.create_index(
        "idx_cve_cvss_missing", "cve", ["cvss_missing"], unique=False, schema="canonical"
    )

    op.add_column(
        "static_features",
        sa.Column("cvss_missing", sa.Boolean(), nullable=False, server_default=sa.false()),
        schema="features",
    )
    op.alter_column("static_features", "cvss_missing", server_default=None, schema="features")


def downgrade() -> None:
    op.drop_column("static_features", "cvss_missing", schema="features")
    op.drop_index("idx_cve_cvss_missing", table_name="cve", schema="canonical")
    op.drop_column("cve", "cvss_missing", schema="canonical")
