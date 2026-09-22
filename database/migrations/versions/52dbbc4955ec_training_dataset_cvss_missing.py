"""add cvss_missing to training.training_dataset

Hand-written, not autogenerate — same reason as prior migrations on this
branch. Fixes a real gap: the original cvss_missing migration
(4a0248f4d0fa) added the column to canonical.cve and
features.static_features but missed training.training_dataset, the flat
export table — found when the preliminary Cox baseline
(scripts/eda/cox_preliminary.py) tried to read it and got a KeyError.

Revision ID: 52dbbc4955ec
Revises: 4c6644a13a09
Create Date: 2026-09-22

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "52dbbc4955ec"
down_revision: Union[str, Sequence[str], None] = "4c6644a13a09"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "training_dataset",
        sa.Column("cvss_missing", sa.Boolean(), nullable=False, server_default=sa.false()),
        schema="training",
    )
    op.alter_column("training_dataset", "cvss_missing", server_default=None, schema="training")


def downgrade() -> None:
    op.drop_column("training_dataset", "cvss_missing", schema="training")
