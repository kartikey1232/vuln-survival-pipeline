"""widen cwe_relationship.relationship_type CHECK constraint

Hand-written, not autogenerate — same reason as 4a0248f4d0fa (add
cvss_missing): this project's tables were created by executing schema.sql's
raw DDL, so Postgres assigned its own default constraint/index names that
don't match what SQLAlchemy's naming convention would generate, and
autogenerate proposes renaming/dropping most of the database's indexes and
constraints over that alone. Written by hand instead: exactly the one CHECK
constraint this revision is about.

clean_cwe.py found that real CWE 4.x+ XML uses a Nature vocabulary broader
than the original constraint (ChildOf, ParentOf, PeerOf, CanFollow) — CWE's
own catalog also uses CanPrecede, CanAlsoBe, Requires, and StartsWith. This
widens the constraint to match; it does not change what any query does
with the data (the relationship graph isn't used for features).

Revision ID: 8ac18967d9fb
Revises: 4a0248f4d0fa
Create Date: 2026-09-20

"""
from typing import Sequence, Union

from alembic import op

revision: str = "8ac18967d9fb"
down_revision: Union[str, Sequence[str], None] = "4a0248f4d0fa"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_OLD_TYPES = "('ChildOf','ParentOf','PeerOf','CanFollow')"
_NEW_TYPES = (
    "('ChildOf','ParentOf','PeerOf','CanFollow','CanPrecede','CanAlsoBe','Requires','StartsWith')"
)


def upgrade() -> None:
    op.drop_constraint(
        "cwe_relationship_relationship_type_check",
        "cwe_relationship",
        schema="canonical",
        type_="check",
    )
    op.create_check_constraint(
        "cwe_relationship_relationship_type_check",
        "cwe_relationship",
        f"relationship_type IN {_NEW_TYPES}",
        schema="canonical",
    )


def downgrade() -> None:
    op.drop_constraint(
        "cwe_relationship_relationship_type_check",
        "cwe_relationship",
        schema="canonical",
        type_="check",
    )
    op.create_check_constraint(
        "cwe_relationship_relationship_type_check",
        "cwe_relationship",
        f"relationship_type IN {_OLD_TYPES}",
        schema="canonical",
    )
