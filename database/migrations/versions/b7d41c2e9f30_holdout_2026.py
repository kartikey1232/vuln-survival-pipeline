"""add training.holdout_2026 and the holdout/training CVE-overlap constraint

Hand-written, not autogenerate (CLAUDE.md rule 6). The same DDL is in
database/schema.sql, which is what the test database bootstraps from.

training.holdout_2026 holds the 2026 holdout cohort
(scripts/features/build_holdout_cohort.py, docs/holdout_protocol.md). A CHECK
constraint cannot read another table, so "no CVE in both holdout_2026 and
training_dataset" is enforced by a constraint trigger on each table.

Revision ID: b7d41c2e9f30
Revises: 0a055ae4fff8
Create Date: 2026-10-24

"""
from typing import Sequence, Union

from alembic import op

revision: str = "b7d41c2e9f30"
down_revision: Union[str, Sequence[str], None] = "0a055ae4fff8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

UPGRADE_SQL = r"""
-- 2026 holdout cohort (docs/holdout_protocol.md): CVEs published
-- 2026-03-25..2026-09-21, labels censored at 2026-10-21. Same feature
-- columns and rules as training_dataset's model features
-- (scripts/features/build_holdout_cohort.py); no legacy or enrichment
-- columns. Every row is stored, version-transition rows included (flagged);
-- the 180-day follow-up rule is applied at evaluation, from followup_days.
CREATE TABLE IF NOT EXISTS training.holdout_2026 (
    cve_id                      VARCHAR(20) NOT NULL,
    checkpoint_day              INTEGER NOT NULL,
    published_date              DATE NOT NULL,
    as_of_date                  DATE NOT NULL,
    epss_pct_now                NUMERIC(8,6),
    epss_pct_7d_ago             NUMERIC(8,6),
    epss_pct_7d_ago_missing     BOOLEAN NOT NULL,
    epss_pct_delta_7d           NUMERIC(9,6),
    epss_pct_first              NUMERIC(8,6),
    epss_pct_max_to_date        NUMERIC(8,6),
    days_to_first_epss          INTEGER,
    epss_model_version_at_asof  TEXT,
    cvss_base_score             NUMERIC(3,1),
    attack_vector               TEXT,
    attack_complexity           TEXT,
    privileges_required         TEXT,
    user_interaction            TEXT,
    confidentiality_impact      TEXT,
    integrity_impact            TEXT,
    availability_impact         TEXT,
    cvss_version                TEXT,
    cvss_cna_missing            BOOLEAN NOT NULL,
    cwe_kev_rate_expanding      NUMERIC(8,6),
    cna_kev_rate_expanding      NUMERIC(8,6),
    exploit_published_by_asof   BOOLEAN NOT NULL,
    days_to_first_exploit       INTEGER,
    epss_score_at_asof_raw      NUMERIC(8,6), -- baseline only, not a model feature
    spans_version_transition    BOOLEAN NOT NULL,
    event_time                  INTEGER NOT NULL,
    composite_event             BOOLEAN NOT NULL,
    observation_window_end      DATE NOT NULL,
    followup_days               INTEGER NOT NULL,
    dataset_version             TEXT NOT NULL,
    exported_at                 TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cve_id, checkpoint_day, dataset_version),
    CONSTRAINT holdout_2026_published_window CHECK (published_date BETWEEN DATE '2026-03-25' AND DATE '2026-09-21'),
    CONSTRAINT holdout_2026_as_of_is_landmark CHECK (as_of_date = published_date + checkpoint_day),
    CONSTRAINT holdout_2026_followup CHECK (followup_days = observation_window_end - as_of_date AND followup_days >= 0),
    CONSTRAINT holdout_2026_event_within_followup CHECK (event_time >= 0 AND event_time <= followup_days)
);
CREATE INDEX IF NOT EXISTS idx_holdout_2026_version ON training.holdout_2026 (dataset_version);

-- No CVE may be in both training.training_dataset (any dataset_version) and
-- training.holdout_2026. A CHECK cannot read another table, so this is a
-- constraint trigger on each side (it appears in pg_constraint as
-- holdout_2026_no_training_overlap / training_dataset_no_holdout_overlap).
-- Both PKs lead with cve_id, so each check is an index probe. (No percent sign in
-- this DDL: init_db runs schema.sql through psycopg, which reads it as a
-- placeholder.)
CREATE OR REPLACE FUNCTION training.reject_holdout_training_overlap() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'holdout_2026' THEN
        IF EXISTS (SELECT 1 FROM training.training_dataset WHERE cve_id = NEW.cve_id) THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'holdout_2026_no_training_overlap',
                MESSAGE = 'holdout_2026: ' || NEW.cve_id || ' is in training.training_dataset';
        END IF;
    ELSIF EXISTS (SELECT 1 FROM training.holdout_2026 WHERE cve_id = NEW.cve_id) THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'training_dataset_no_holdout_overlap',
            MESSAGE = 'training_dataset: ' || NEW.cve_id || ' is in training.holdout_2026';
    END IF;
    RETURN NULL;
END
$$;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'holdout_2026_no_training_overlap') THEN
        CREATE CONSTRAINT TRIGGER holdout_2026_no_training_overlap
            AFTER INSERT OR UPDATE OF cve_id ON training.holdout_2026
            FOR EACH ROW EXECUTE FUNCTION training.reject_holdout_training_overlap();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'training_dataset_no_holdout_overlap') THEN
        CREATE CONSTRAINT TRIGGER training_dataset_no_holdout_overlap
            AFTER INSERT OR UPDATE OF cve_id ON training.training_dataset
            FOR EACH ROW EXECUTE FUNCTION training.reject_holdout_training_overlap();
    END IF;
END
$$;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS training_dataset_no_holdout_overlap ON training.training_dataset")
    op.execute("DROP TABLE IF EXISTS training.holdout_2026")  # drops its own trigger
    op.execute("DROP FUNCTION IF EXISTS training.reject_holdout_training_overlap()")
