"""add publication-time (CNA-sourced) feature columns

Hand-written, not autogenerate — same reason as prior migrations on this
branch. Part of the enrichment-leakage fix (docs/enrichment_leakage.md):
CVSS/CWE data added by NVD's own analysis (source='nvd@nist.gov') is only
present once NVD has analyst-reviewed a CVE, which happens preferentially
for KEV-listed CVEs — so using it as a feature leaks the label. These
columns are the CNA-sourced-only replacements. The OLD `cvss_missing` /
`vendor_kev_rate_expanding` / `vendor_count` / `product_count` columns in
features.temporal_features and training.training_dataset are left in
place (unused going forward, not dropped) rather than risk a destructive
rename; canonical.cve.cvss_missing and features.static_features.cvss_missing
keep their original meaning ("no CVSS at all") and are untouched.

Revision ID: 0a055ae4fff8
Revises: 52dbbc4955ec
Create Date: 2026-09-22

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0a055ae4fff8"
down_revision: Union[str, Sequence[str], None] = "52dbbc4955ec"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_NEW_COLS = [
    ("cvss_cna_missing", sa.Boolean()),
    ("cna_kev_rate_expanding", sa.Numeric(8, 6)),
]


def upgrade() -> None:
    for name, col_type in _NEW_COLS:
        op.add_column(
            "temporal_features",
            sa.Column(name, col_type, nullable=False, server_default=sa.false())
            if name == "cvss_cna_missing"
            else sa.Column(name, col_type),
            schema="features",
        )
        if name == "cvss_cna_missing":
            op.alter_column("temporal_features", name, server_default=None, schema="features")

    for name, col_type in _NEW_COLS:
        op.add_column(
            "training_dataset",
            sa.Column(name, col_type, nullable=False, server_default=sa.false())
            if name == "cvss_cna_missing"
            else sa.Column(name, col_type),
            schema="training",
        )
        if name == "cvss_cna_missing":
            op.alter_column("training_dataset", name, server_default=None, schema="training")


def downgrade() -> None:
    for name, _ in _NEW_COLS:
        op.drop_column("training_dataset", name, schema="training")
    for name, _ in _NEW_COLS:
        op.drop_column("temporal_features", name, schema="features")
