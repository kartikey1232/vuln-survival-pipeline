-- Trajectory-Aware Survival Analysis Pipeline — canonical schema DDL.
-- This file is the source of truth; database/models.py mirrors it exactly.
-- Applied by database/init_db.py. Idempotent (IF NOT EXISTS everywhere).
--
-- Four schemas:
--   staging    — append-only, one row per raw snapshot/parse. Never UPDATE.
--   canonical  — cleaned/deduped, one current row per entity.
--   features   — engineered features, one row per (cve, checkpoint_day).
--   training   — survival labels + final flat export + prediction placeholder.

CREATE SCHEMA IF NOT EXISTS staging;
CREATE SCHEMA IF NOT EXISTS canonical;
CREATE SCHEMA IF NOT EXISTS features;
CREATE SCHEMA IF NOT EXISTS training;

-- =============================================================================
-- STAGING — append-only raw ingestion
-- =============================================================================

CREATE TABLE IF NOT EXISTS staging.file_manifest (
    manifest_id     BIGSERIAL PRIMARY KEY,
    source          TEXT NOT NULL CHECK (source IN ('nvd','epss','kev','exploitdb','cwe')),
    file_path       TEXT NOT NULL,
    url             TEXT NOT NULL,
    fetched_at      TIMESTAMPTZ NOT NULL,
    snapshot_date   DATE,
    sha256          CHAR(64) NOT NULL,
    byte_size       BIGINT NOT NULL,
    row_count       INTEGER,
    status          TEXT NOT NULL CHECK (status IN ('downloaded','verified','failed','parsed')),
    http_status     INTEGER,
    UNIQUE (source, file_path)
);
CREATE INDEX IF NOT EXISTS idx_manifest_source_snapshot ON staging.file_manifest (source, snapshot_date);

CREATE TABLE IF NOT EXISTS staging.nvd_cve_raw (
    staging_id          BIGSERIAL PRIMARY KEY,
    cve_id              VARCHAR(20) NOT NULL,
    fetched_at          TIMESTAMPTZ NOT NULL,
    last_modified_src   TIMESTAMPTZ NOT NULL,
    payload             JSONB NOT NULL,
    manifest_id         BIGINT REFERENCES staging.file_manifest (manifest_id)
);
CREATE INDEX IF NOT EXISTS idx_nvd_raw_cve ON staging.nvd_cve_raw (cve_id);
CREATE INDEX IF NOT EXISTS idx_nvd_raw_lastmod ON staging.nvd_cve_raw (last_modified_src);

CREATE TABLE IF NOT EXISTS staging.epss_scores_raw (
    staging_id      BIGSERIAL PRIMARY KEY,
    cve_id          VARCHAR(20) NOT NULL,
    snapshot_date   DATE NOT NULL,
    epss_score      NUMERIC(8,6) NOT NULL CHECK (epss_score >= 0 AND epss_score <= 1),
    percentile      NUMERIC(8,6) NOT NULL CHECK (percentile >= 0 AND percentile <= 1),
    manifest_id     BIGINT REFERENCES staging.file_manifest (manifest_id),
    UNIQUE (cve_id, snapshot_date)
);
CREATE INDEX IF NOT EXISTS idx_epss_raw_cve ON staging.epss_scores_raw (cve_id);
CREATE INDEX IF NOT EXISTS idx_epss_raw_date ON staging.epss_scores_raw (snapshot_date);

CREATE TABLE IF NOT EXISTS staging.kev_raw (
    staging_id          BIGSERIAL PRIMARY KEY,
    cve_id              VARCHAR(20) NOT NULL,
    fetched_at          TIMESTAMPTZ NOT NULL,
    date_added_src      DATE NOT NULL,
    vendor_project      TEXT,
    product             TEXT,
    vulnerability_name  TEXT,
    required_action     TEXT,
    due_date            DATE,
    known_ransomware    BOOLEAN,
    manifest_id         BIGINT REFERENCES staging.file_manifest (manifest_id)
);
CREATE INDEX IF NOT EXISTS idx_kev_raw_cve ON staging.kev_raw (cve_id);

CREATE TABLE IF NOT EXISTS staging.exploitdb_raw (
    staging_id          BIGSERIAL PRIMARY KEY,
    exploit_id          INTEGER NOT NULL,
    fetched_at          TIMESTAMPTZ NOT NULL,
    description         TEXT,
    date_published_src  DATE,
    author              TEXT,
    type                TEXT,
    platform            TEXT,
    codes_raw           TEXT,
    manifest_id         BIGINT REFERENCES staging.file_manifest (manifest_id)
);
CREATE INDEX IF NOT EXISTS idx_exploitdb_raw_id ON staging.exploitdb_raw (exploit_id);

CREATE TABLE IF NOT EXISTS staging.cwe_raw (
    staging_id          BIGSERIAL PRIMARY KEY,
    cwe_id               VARCHAR(20) NOT NULL,
    fetched_at           TIMESTAMPTZ NOT NULL,
    name                 TEXT,
    description          TEXT,
    raw_xml_fragment     TEXT,
    manifest_id          BIGINT REFERENCES staging.file_manifest (manifest_id)
);
CREATE INDEX IF NOT EXISTS idx_cwe_raw_id ON staging.cwe_raw (cwe_id);

-- =============================================================================
-- CANONICAL — cleaned, deduped, normalized
-- =============================================================================

CREATE TABLE IF NOT EXISTS canonical.cve (
    cve_id                  VARCHAR(20) PRIMARY KEY,
    published_date          DATE NOT NULL,
    last_modified_date      DATE NOT NULL,
    description             TEXT,
    vuln_status             TEXT,
    source_last_fetched_at  TIMESTAMPTZ NOT NULL,
    cvss_missing            BOOLEAN NOT NULL DEFAULT FALSE -- TRUE iff no CVSS metric of any tracked version was reported; row is kept either way, never dropped
);
CREATE INDEX IF NOT EXISTS idx_cve_published ON canonical.cve (published_date);
CREATE INDEX IF NOT EXISTS idx_cve_cvss_missing ON canonical.cve (cvss_missing);

CREATE TABLE IF NOT EXISTS canonical.cvss_metric (
    cvss_metric_id          BIGSERIAL PRIMARY KEY,
    cve_id                  VARCHAR(20) NOT NULL REFERENCES canonical.cve (cve_id),
    cvss_version            TEXT NOT NULL CHECK (cvss_version IN ('2.0','3.0','3.1','4.0')),
    vector_string            TEXT NOT NULL,
    base_score               NUMERIC(3,1) NOT NULL CHECK (base_score >= 0 AND base_score <= 10),
    base_severity             TEXT,
    attack_vector             TEXT,
    attack_complexity         TEXT,
    privileges_required       TEXT,
    user_interaction          TEXT,
    scope                     TEXT,
    confidentiality_impact    TEXT,
    integrity_impact          TEXT,
    availability_impact       TEXT,
    is_primary                BOOLEAN NOT NULL DEFAULT FALSE,
    source                    TEXT NOT NULL DEFAULT 'nvd',
    UNIQUE (cve_id, cvss_version, source)
);
CREATE INDEX IF NOT EXISTS idx_cvss_cve ON canonical.cvss_metric (cve_id);
CREATE INDEX IF NOT EXISTS idx_cvss_primary ON canonical.cvss_metric (cve_id, is_primary);

CREATE TABLE IF NOT EXISTS canonical.cwe (
    cwe_id          VARCHAR(20) PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT,
    abstraction     TEXT,
    status          TEXT
);

CREATE TABLE IF NOT EXISTS canonical.cwe_relationship (
    relationship_id     BIGSERIAL PRIMARY KEY,
    child_cwe_id        VARCHAR(20) NOT NULL REFERENCES canonical.cwe (cwe_id),
    parent_cwe_id        VARCHAR(20) NOT NULL REFERENCES canonical.cwe (cwe_id),
    relationship_type    TEXT NOT NULL CHECK (relationship_type IN ('ChildOf','ParentOf','PeerOf','CanFollow','CanPrecede','CanAlsoBe','Requires','StartsWith')),
    UNIQUE (child_cwe_id, parent_cwe_id, relationship_type)
);
CREATE INDEX IF NOT EXISTS idx_cwe_rel_child ON canonical.cwe_relationship (child_cwe_id);
CREATE INDEX IF NOT EXISTS idx_cwe_rel_parent ON canonical.cwe_relationship (parent_cwe_id);

CREATE TABLE IF NOT EXISTS canonical.cve_cwe_map (
    cve_id      VARCHAR(20) NOT NULL REFERENCES canonical.cve (cve_id),
    cwe_id      VARCHAR(20) NOT NULL REFERENCES canonical.cwe (cwe_id),
    source      TEXT NOT NULL DEFAULT 'nvd',
    PRIMARY KEY (cve_id, cwe_id, source)
);
CREATE INDEX IF NOT EXISTS idx_cvecwe_cwe ON canonical.cve_cwe_map (cwe_id);

CREATE TABLE IF NOT EXISTS canonical.cpe_product (
    cpe_product_id       BIGSERIAL PRIMARY KEY,
    cve_id                VARCHAR(20) NOT NULL REFERENCES canonical.cve (cve_id),
    vendor_raw            TEXT,
    vendor_normalized     TEXT NOT NULL,
    product_raw           TEXT,
    product_normalized    TEXT,
    cpe23_uri             TEXT
);
CREATE INDEX IF NOT EXISTS idx_cpe_cve ON canonical.cpe_product (cve_id);
CREATE INDEX IF NOT EXISTS idx_cpe_vendor ON canonical.cpe_product (vendor_normalized);

CREATE TABLE IF NOT EXISTS canonical.epss_timeline (
    cve_id          VARCHAR(20) NOT NULL REFERENCES canonical.cve (cve_id),
    snapshot_date   DATE NOT NULL,
    epss_score      NUMERIC(8,6) NOT NULL CHECK (epss_score >= 0 AND epss_score <= 1),
    percentile      NUMERIC(8,6) NOT NULL CHECK (percentile >= 0 AND percentile <= 1),
    is_observed     BOOLEAN NOT NULL,
    fill_method     TEXT NOT NULL CHECK (fill_method IN ('observed','ffill')),
    PRIMARY KEY (cve_id, snapshot_date)
);
CREATE INDEX IF NOT EXISTS idx_epsstl_date ON canonical.epss_timeline (snapshot_date);

CREATE TABLE IF NOT EXISTS canonical.kev (
    cve_id                     VARCHAR(20) PRIMARY KEY REFERENCES canonical.cve (cve_id),
    date_added                 DATE NOT NULL,
    vendor_project              TEXT,
    product                     TEXT,
    vulnerability_name          TEXT,
    required_action             TEXT,
    due_date                    DATE,
    known_ransomware            BOOLEAN,
    first_seen_in_catalog_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kev_date_added ON canonical.kev (date_added);

CREATE TABLE IF NOT EXISTS canonical.exploitdb (
    exploit_id          INTEGER PRIMARY KEY,
    date_published        DATE,
    platform              TEXT,
    type                   TEXT,
    description            TEXT
);

CREATE TABLE IF NOT EXISTS canonical.exploitdb_cve_map (
    exploit_id          INTEGER NOT NULL REFERENCES canonical.exploitdb (exploit_id),
    cve_id                VARCHAR(20) NOT NULL REFERENCES canonical.cve (cve_id),
    match_method          TEXT NOT NULL CHECK (match_method IN ('source_code_field','fuzzy_description')),
    match_confidence      NUMERIC(4,3),
    is_fuzzy_matched      BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (exploit_id, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_edbmap_cve ON canonical.exploitdb_cve_map (cve_id);
CREATE INDEX IF NOT EXISTS idx_edbmap_fuzzy ON canonical.exploitdb_cve_map (is_fuzzy_matched);

-- =============================================================================
-- FEATURES
-- =============================================================================

CREATE TABLE IF NOT EXISTS features.static_features (
    cve_id                       VARCHAR(20) PRIMARY KEY REFERENCES canonical.cve (cve_id),
    cvss_base_score               NUMERIC(3,1),
    cvss_version                  TEXT,
    attack_vector                 TEXT,
    attack_complexity             TEXT,
    privileges_required            TEXT,
    user_interaction               TEXT,
    confidentiality_impact         TEXT,
    integrity_impact               TEXT,
    availability_impact            TEXT,
    vendor_normalized               TEXT,
    product_normalized              TEXT,
    primary_cwe_id                  VARCHAR(20),
    cwe_historical_base_rate        NUMERIC(6,5),
    n_affected_products             INTEGER,
    vendor_count                     INTEGER,
    cvss_missing                    BOOLEAN NOT NULL DEFAULT FALSE, -- carried from canonical.cve.cvss_missing; models consume this instead of imputing on a NULL cvss_base_score
    computed_at                     TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS features.temporal_features (
    cve_id                          VARCHAR(20) NOT NULL REFERENCES canonical.cve (cve_id),
    checkpoint_day                  INTEGER NOT NULL, -- landmark day (7/14/30); as_of_date = published_date + checkpoint_day
    as_of_date                      DATE NOT NULL,
    epss_score_at_checkpoint         NUMERIC(8,6),
    epss_percentile_at_checkpoint    NUMERIC(8,6),
    epss_slope_7d                    NUMERIC(12,8),
    epss_growth_rate_7d              NUMERIC(14,6),
    epss_volatility_7d               NUMERIC(12,8),
    epss_percentile_change           NUMERIC(8,6),
    days_until_poc                   INTEGER,
    poc_observed_by_checkpoint       BOOLEAN NOT NULL,
    days_until_kev                   INTEGER,
    kev_observed_by_checkpoint       BOOLEAN NOT NULL,
    related_vendor_kev_velocity      NUMERIC(12,6),
    related_cwe_kev_velocity         NUMERIC(12,6),
    -- landmark-design EPSS features (all forward-fill only, computed as of as_of_date) --
    epss_pct_now                     NUMERIC(8,6),
    epss_pct_7d_ago                  NUMERIC(8,6),
    epss_pct_7d_ago_missing          BOOLEAN NOT NULL DEFAULT FALSE,
    epss_pct_delta_7d                NUMERIC(9,6),
    epss_pct_first                   NUMERIC(8,6),
    epss_pct_max_to_date             NUMERIC(8,6),
    days_to_first_epss               INTEGER,
    epss_model_version_at_asof       TEXT,
    epss_score_at_asof_raw           NUMERIC(8,6), -- baseline / blind-spot use ONLY, never a model feature
    spans_version_transition         BOOLEAN NOT NULL DEFAULT FALSE, -- rows with TRUE are excluded from the default export; kept for sensitivity analysis
    cwe_kev_rate_expanding           NUMERIC(8,6), -- expanding-window target encoding, smoothed; see build_landmark_dataset.py
    vendor_kev_rate_expanding        NUMERIC(8,6),
    product_count                    INTEGER,
    exploit_published_by_asof        BOOLEAN NOT NULL DEFAULT FALSE,
    days_to_first_exploit            INTEGER,
    computed_at                      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cve_id, checkpoint_day)
);
CREATE INDEX IF NOT EXISTS idx_tempfeat_checkpoint ON features.temporal_features (checkpoint_day);

CREATE TABLE IF NOT EXISTS features.derived_features (
    cve_id                       VARCHAR(20) NOT NULL,
    checkpoint_day                INTEGER NOT NULL,
    composite_risk_index           NUMERIC(8,5),
    vendor_historical_kev_rate      NUMERIC(6,5),
    time_since_disclosure_days      INTEGER,
    rolling_epss_avg_7d             NUMERIC(8,6),
    rolling_epss_avg_30d            NUMERIC(8,6),
    epss_max_to_date                NUMERIC(8,6),
    computed_at                     TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cve_id, checkpoint_day),
    FOREIGN KEY (cve_id, checkpoint_day) REFERENCES features.temporal_features (cve_id, checkpoint_day)
);

-- =============================================================================
-- TRAINING
-- =============================================================================

CREATE TABLE IF NOT EXISTS training.survival_labels (
    cve_id                    VARCHAR(20) NOT NULL,
    checkpoint_day             INTEGER NOT NULL,
    event_time                 INTEGER,
    censor_flag                 BOOLEAN NOT NULL,
    composite_event              BOOLEAN NOT NULL,
    event_type                   TEXT CHECK (event_type IN ('kev','poc','epss_threshold','none')),
    observation_window_end       DATE NOT NULL,
    label_computed_at            TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cve_id, checkpoint_day)
);
CREATE INDEX IF NOT EXISTS idx_labels_checkpoint ON training.survival_labels (checkpoint_day);

CREATE TABLE IF NOT EXISTS training.training_dataset (
    cve_id                           VARCHAR(20) NOT NULL,
    checkpoint_day                    INTEGER NOT NULL,
    as_of_date                         DATE NOT NULL,
    cvss_base_score                    NUMERIC(3,1),
    cvss_version                       TEXT,
    attack_vector                      TEXT,
    attack_complexity                  TEXT,
    privileges_required                 TEXT,
    user_interaction                    TEXT,
    confidentiality_impact              TEXT,
    integrity_impact                    TEXT,
    availability_impact                 TEXT,
    vendor_normalized                    TEXT,
    product_normalized                   TEXT,
    primary_cwe_id                       VARCHAR(20),
    cwe_historical_base_rate             NUMERIC(6,5),
    n_affected_products                  INTEGER,
    vendor_count                          INTEGER,
    epss_score_at_checkpoint              NUMERIC(8,6),
    epss_percentile_at_checkpoint         NUMERIC(8,6),
    epss_slope_7d                         NUMERIC(12,8),
    epss_growth_rate_7d                   NUMERIC(14,6),
    epss_volatility_7d                    NUMERIC(12,8),
    epss_percentile_change                NUMERIC(8,6),
    days_until_poc                        INTEGER,
    poc_observed_by_checkpoint            BOOLEAN,
    days_until_kev                        INTEGER,
    kev_observed_by_checkpoint            BOOLEAN,
    related_vendor_kev_velocity           NUMERIC(12,6),
    related_cwe_kev_velocity              NUMERIC(12,6),
    composite_risk_index                  NUMERIC(8,5),
    vendor_historical_kev_rate             NUMERIC(6,5),
    time_since_disclosure_days             INTEGER,
    rolling_epss_avg_7d                    NUMERIC(8,6),
    rolling_epss_avg_30d                   NUMERIC(8,6),
    epss_max_to_date                       NUMERIC(8,6),
    epss_pct_now                          NUMERIC(8,6),
    epss_pct_7d_ago                       NUMERIC(8,6),
    epss_pct_7d_ago_missing               BOOLEAN NOT NULL DEFAULT FALSE,
    epss_pct_delta_7d                     NUMERIC(9,6),
    epss_pct_first                        NUMERIC(8,6),
    epss_pct_max_to_date                  NUMERIC(8,6),
    days_to_first_epss                    INTEGER,
    epss_model_version_at_asof            TEXT,
    epss_score_at_asof_raw                NUMERIC(8,6), -- baseline only, not a model feature
    spans_version_transition              BOOLEAN NOT NULL DEFAULT FALSE,
    cwe_kev_rate_expanding                NUMERIC(8,6),
    vendor_kev_rate_expanding             NUMERIC(8,6),
    product_count                         INTEGER,
    exploit_published_by_asof             BOOLEAN NOT NULL DEFAULT FALSE,
    days_to_first_exploit                 INTEGER,
    event_time                             INTEGER,
    censor_flag                             BOOLEAN NOT NULL,
    composite_event                         BOOLEAN NOT NULL,
    event_type                              TEXT,
    dataset_version                         TEXT NOT NULL,
    exported_at                             TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cve_id, checkpoint_day, dataset_version)
);
CREATE INDEX IF NOT EXISTS idx_training_checkpoint ON training.training_dataset (checkpoint_day);
CREATE INDEX IF NOT EXISTS idx_training_version ON training.training_dataset (dataset_version);

CREATE TABLE IF NOT EXISTS training.prediction (
    prediction_id                BIGSERIAL PRIMARY KEY,
    cve_id                         VARCHAR(20) NOT NULL,
    checkpoint_day                  INTEGER NOT NULL,
    model_name                      TEXT NOT NULL CHECK (model_name IN ('cox_ph','rsf','xgboost_aft','logreg')),
    model_version                    TEXT NOT NULL,
    predicted_risk_score             NUMERIC(8,6),
    predicted_survival_time          NUMERIC(10,3),
    predicted_at                      TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pred_cve ON training.prediction (cve_id);
CREATE INDEX IF NOT EXISTS idx_pred_model ON training.prediction (model_name, model_version);
