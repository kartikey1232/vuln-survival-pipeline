"""add landmark-design feature columns

Hand-written, not autogenerate — same reason as the prior two migrations on
this branch (schema.sql-created tables have Postgres-default constraint/
index names that don't match SQLAlchemy's naming convention, so autogenerate
proposes renaming/dropping most of the database's indexes and constraints
over that alone). Written by hand instead: exactly the columns needed for
the landmark-prediction feature design (see scripts/features/
build_landmark_dataset.py) — replaces the single day-30-checkpoint design.

Revision ID: 4c6644a13a09
Revises: 8ac18967d9fb
Create Date: 2026-09-21

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "4c6644a13a09"
down_revision: Union[str, Sequence[str], None] = "8ac18967d9fb"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TEMPORAL_NEW_COLS = [
    ("epss_pct_now", sa.Numeric(8, 6)),
    ("epss_pct_7d_ago", sa.Numeric(8, 6)),
    ("epss_pct_7d_ago_missing", sa.Boolean()),
    ("epss_pct_delta_7d", sa.Numeric(9, 6)),
    ("epss_pct_first", sa.Numeric(8, 6)),
    ("epss_pct_max_to_date", sa.Numeric(8, 6)),
    ("days_to_first_epss", sa.Integer()),
    ("epss_model_version_at_asof", sa.Text()),
    ("epss_score_at_asof_raw", sa.Numeric(8, 6)),
    ("spans_version_transition", sa.Boolean()),
    ("cwe_kev_rate_expanding", sa.Numeric(8, 6)),
    ("vendor_kev_rate_expanding", sa.Numeric(8, 6)),
    ("product_count", sa.Integer()),
    ("exploit_published_by_asof", sa.Boolean()),
    ("days_to_first_exploit", sa.Integer()),
]
_BOOLEAN_DEFAULTS_FALSE = {
    "epss_pct_7d_ago_missing", "spans_version_transition", "exploit_published_by_asof",
}


def upgrade() -> None:
    op.add_column("static_features", sa.Column("vendor_count", sa.Integer()), schema="features")

    for name, col_type in _TEMPORAL_NEW_COLS:
        kwargs = {}
        if name in _BOOLEAN_DEFAULTS_FALSE:
            kwargs = {"nullable": False, "server_default": sa.false()}
        op.add_column("temporal_features", sa.Column(name, col_type, **kwargs), schema="features")
        if name in _BOOLEAN_DEFAULTS_FALSE:
            op.alter_column("temporal_features", name, server_default=None, schema="features")

    op.add_column("training_dataset", sa.Column("vendor_count", sa.Integer()), schema="training")
    for name, col_type in _TEMPORAL_NEW_COLS:
        kwargs = {}
        if name in _BOOLEAN_DEFAULTS_FALSE:
            kwargs = {"nullable": False, "server_default": sa.false()}
        op.add_column("training_dataset", sa.Column(name, col_type, **kwargs), schema="training")
        if name in _BOOLEAN_DEFAULTS_FALSE:
            op.alter_column("training_dataset", name, server_default=None, schema="training")


def downgrade() -> None:
    for name, _ in reversed(_TEMPORAL_NEW_COLS):
        op.drop_column("training_dataset", name, schema="training")
    op.drop_column("training_dataset", "vendor_count", schema="training")

    for name, _ in reversed(_TEMPORAL_NEW_COLS):
        op.drop_column("temporal_features", name, schema="features")

    op.drop_column("static_features", "vendor_count", schema="features")
