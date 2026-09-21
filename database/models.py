"""
SQLAlchemy 2.0 ORM models — mirrors database/schema.sql exactly.

Organized into the same four schemas: staging (append-only raw ingestion),
canonical (cleaned/deduped), features (engineered), training (labels +
export + prediction placeholder). See database/schema.sql for the
authoritative DDL and docs/database_schema.md for the normalization
rationale behind each table.
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    Numeric,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


# =============================================================================
# STAGING — append-only
# =============================================================================


class FileManifest(Base):
    __tablename__ = "file_manifest"
    __table_args__ = (
        UniqueConstraint("source", "file_path"),
        CheckConstraint("source IN ('nvd','epss','kev','exploitdb','cwe')"),
        CheckConstraint("status IN ('downloaded','verified','failed','parsed')"),
        {"schema": "staging"},
    )

    manifest_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    snapshot_date: Mapped[date | None] = mapped_column(Date)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    row_count: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    http_status: Mapped[int | None] = mapped_column(Integer)


class NvdCveRaw(Base):
    __tablename__ = "nvd_cve_raw"
    __table_args__ = {"schema": "staging"}

    staging_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_modified_src: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    manifest_id: Mapped[int | None] = mapped_column(ForeignKey("staging.file_manifest.manifest_id"))


class EpssScoresRaw(Base):
    __tablename__ = "epss_scores_raw"
    __table_args__ = (
        UniqueConstraint("cve_id", "snapshot_date"),
        CheckConstraint("epss_score >= 0 AND epss_score <= 1"),
        CheckConstraint("percentile >= 0 AND percentile <= 1"),
        {"schema": "staging"},
    )

    staging_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    epss_score: Mapped[float] = mapped_column(Numeric(8, 6), nullable=False)
    percentile: Mapped[float] = mapped_column(Numeric(8, 6), nullable=False)
    manifest_id: Mapped[int | None] = mapped_column(ForeignKey("staging.file_manifest.manifest_id"))


class KevRaw(Base):
    __tablename__ = "kev_raw"
    __table_args__ = {"schema": "staging"}

    staging_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    date_added_src: Mapped[date] = mapped_column(Date, nullable=False)
    vendor_project: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    vulnerability_name: Mapped[str | None] = mapped_column(Text)
    required_action: Mapped[str | None] = mapped_column(Text)
    due_date: Mapped[date | None] = mapped_column(Date)
    known_ransomware: Mapped[bool | None] = mapped_column(Boolean)
    manifest_id: Mapped[int | None] = mapped_column(ForeignKey("staging.file_manifest.manifest_id"))


class ExploitdbRaw(Base):
    __tablename__ = "exploitdb_raw"
    __table_args__ = {"schema": "staging"}

    staging_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    exploit_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    date_published_src: Mapped[date | None] = mapped_column(Date)
    author: Mapped[str | None] = mapped_column(Text)
    type: Mapped[str | None] = mapped_column(Text)
    platform: Mapped[str | None] = mapped_column(Text)
    codes_raw: Mapped[str | None] = mapped_column(Text)
    manifest_id: Mapped[int | None] = mapped_column(ForeignKey("staging.file_manifest.manifest_id"))


class CweRaw(Base):
    __tablename__ = "cwe_raw"
    __table_args__ = {"schema": "staging"}

    staging_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    cwe_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    name: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    raw_xml_fragment: Mapped[str | None] = mapped_column(Text)
    manifest_id: Mapped[int | None] = mapped_column(ForeignKey("staging.file_manifest.manifest_id"))


# =============================================================================
# CANONICAL — cleaned, deduped, normalized
# =============================================================================


class Cve(Base):
    __tablename__ = "cve"
    __table_args__ = {"schema": "canonical"}

    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    published_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    last_modified_date: Mapped[date] = mapped_column(Date, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    vuln_status: Mapped[str | None] = mapped_column(Text)
    source_last_fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    cvss_missing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)


class CvssMetric(Base):
    __tablename__ = "cvss_metric"
    __table_args__ = (
        UniqueConstraint("cve_id", "cvss_version", "source"),
        CheckConstraint("cvss_version IN ('2.0','3.0','3.1','4.0')"),
        CheckConstraint("base_score >= 0 AND base_score <= 10"),
        {"schema": "canonical"},
    )

    cvss_metric_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("canonical.cve.cve_id"), nullable=False, index=True)
    cvss_version: Mapped[str] = mapped_column(Text, nullable=False)
    vector_string: Mapped[str] = mapped_column(Text, nullable=False)
    base_score: Mapped[float] = mapped_column(Numeric(3, 1), nullable=False)
    base_severity: Mapped[str | None] = mapped_column(Text)
    attack_vector: Mapped[str | None] = mapped_column(Text)
    attack_complexity: Mapped[str | None] = mapped_column(Text)
    privileges_required: Mapped[str | None] = mapped_column(Text)
    user_interaction: Mapped[str | None] = mapped_column(Text)
    scope: Mapped[str | None] = mapped_column(Text)
    confidentiality_impact: Mapped[str | None] = mapped_column(Text)
    integrity_impact: Mapped[str | None] = mapped_column(Text)
    availability_impact: Mapped[str | None] = mapped_column(Text)
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    source: Mapped[str] = mapped_column(Text, nullable=False, default="nvd")


class Cwe(Base):
    __tablename__ = "cwe"
    __table_args__ = {"schema": "canonical"}

    cwe_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    abstraction: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str | None] = mapped_column(Text)


class CweRelationship(Base):
    __tablename__ = "cwe_relationship"
    __table_args__ = (
        UniqueConstraint("child_cwe_id", "parent_cwe_id", "relationship_type"),
        CheckConstraint(
            "relationship_type IN "
            "('ChildOf','ParentOf','PeerOf','CanFollow','CanPrecede','CanAlsoBe','Requires','StartsWith')"
        ),
        {"schema": "canonical"},
    )

    relationship_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    child_cwe_id: Mapped[str] = mapped_column(ForeignKey("canonical.cwe.cwe_id"), nullable=False, index=True)
    parent_cwe_id: Mapped[str] = mapped_column(ForeignKey("canonical.cwe.cwe_id"), nullable=False, index=True)
    relationship_type: Mapped[str] = mapped_column(Text, nullable=False)


class CveCweMap(Base):
    __tablename__ = "cve_cwe_map"
    __table_args__ = (
        PrimaryKeyConstraint("cve_id", "cwe_id", "source"),
        {"schema": "canonical"},
    )

    cve_id: Mapped[str] = mapped_column(ForeignKey("canonical.cve.cve_id"), nullable=False)
    cwe_id: Mapped[str] = mapped_column(ForeignKey("canonical.cwe.cwe_id"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(Text, nullable=False, default="nvd")


class CpeProduct(Base):
    __tablename__ = "cpe_product"
    __table_args__ = {"schema": "canonical"}

    cpe_product_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("canonical.cve.cve_id"), nullable=False, index=True)
    vendor_raw: Mapped[str | None] = mapped_column(Text)
    vendor_normalized: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    product_raw: Mapped[str | None] = mapped_column(Text)
    product_normalized: Mapped[str | None] = mapped_column(Text)
    cpe23_uri: Mapped[str | None] = mapped_column(Text)


class EpssTimeline(Base):
    __tablename__ = "epss_timeline"
    __table_args__ = (
        PrimaryKeyConstraint("cve_id", "snapshot_date"),
        CheckConstraint("epss_score >= 0 AND epss_score <= 1"),
        CheckConstraint("percentile >= 0 AND percentile <= 1"),
        CheckConstraint("fill_method IN ('observed','ffill')"),
        {"schema": "canonical"},
    )

    cve_id: Mapped[str] = mapped_column(ForeignKey("canonical.cve.cve_id"), nullable=False)
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    epss_score: Mapped[float] = mapped_column(Numeric(8, 6), nullable=False)
    percentile: Mapped[float] = mapped_column(Numeric(8, 6), nullable=False)
    is_observed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    fill_method: Mapped[str] = mapped_column(Text, nullable=False)


class Kev(Base):
    __tablename__ = "kev"
    __table_args__ = {"schema": "canonical"}

    cve_id: Mapped[str] = mapped_column(ForeignKey("canonical.cve.cve_id"), primary_key=True)
    date_added: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    vendor_project: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    vulnerability_name: Mapped[str | None] = mapped_column(Text)
    required_action: Mapped[str | None] = mapped_column(Text)
    due_date: Mapped[date | None] = mapped_column(Date)
    known_ransomware: Mapped[bool | None] = mapped_column(Boolean)
    first_seen_in_catalog_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Exploitdb(Base):
    __tablename__ = "exploitdb"
    __table_args__ = {"schema": "canonical"}

    exploit_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    date_published: Mapped[date | None] = mapped_column(Date)
    platform: Mapped[str | None] = mapped_column(Text)
    type: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)


class ExploitdbCveMap(Base):
    __tablename__ = "exploitdb_cve_map"
    __table_args__ = (
        PrimaryKeyConstraint("exploit_id", "cve_id"),
        CheckConstraint("match_method IN ('source_code_field','fuzzy_description')"),
        {"schema": "canonical"},
    )

    exploit_id: Mapped[int] = mapped_column(ForeignKey("canonical.exploitdb.exploit_id"), nullable=False)
    cve_id: Mapped[str] = mapped_column(ForeignKey("canonical.cve.cve_id"), nullable=False, index=True)
    match_method: Mapped[str] = mapped_column(Text, nullable=False)
    match_confidence: Mapped[float | None] = mapped_column(Numeric(4, 3))
    is_fuzzy_matched: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)


# =============================================================================
# FEATURES
# =============================================================================


class StaticFeatures(Base):
    __tablename__ = "static_features"
    __table_args__ = {"schema": "features"}

    cve_id: Mapped[str] = mapped_column(ForeignKey("canonical.cve.cve_id"), primary_key=True)
    cvss_base_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_version: Mapped[str | None] = mapped_column(Text)
    attack_vector: Mapped[str | None] = mapped_column(Text)
    attack_complexity: Mapped[str | None] = mapped_column(Text)
    privileges_required: Mapped[str | None] = mapped_column(Text)
    user_interaction: Mapped[str | None] = mapped_column(Text)
    confidentiality_impact: Mapped[str | None] = mapped_column(Text)
    integrity_impact: Mapped[str | None] = mapped_column(Text)
    availability_impact: Mapped[str | None] = mapped_column(Text)
    vendor_normalized: Mapped[str | None] = mapped_column(Text)
    product_normalized: Mapped[str | None] = mapped_column(Text)
    primary_cwe_id: Mapped[str | None] = mapped_column(String(20))
    cwe_historical_base_rate: Mapped[float | None] = mapped_column(Numeric(6, 5))
    n_affected_products: Mapped[int | None] = mapped_column(Integer)
    vendor_count: Mapped[int | None] = mapped_column(Integer)
    cvss_missing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TemporalFeatures(Base):
    __tablename__ = "temporal_features"
    __table_args__ = (
        PrimaryKeyConstraint("cve_id", "checkpoint_day"),
        {"schema": "features"},
    )

    cve_id: Mapped[str] = mapped_column(ForeignKey("canonical.cve.cve_id"), nullable=False)
    checkpoint_day: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    as_of_date: Mapped[date] = mapped_column(Date, nullable=False)
    epss_score_at_checkpoint: Mapped[float | None] = mapped_column(Numeric(8, 6))
    epss_percentile_at_checkpoint: Mapped[float | None] = mapped_column(Numeric(8, 6))
    epss_slope_7d: Mapped[float | None] = mapped_column(Numeric(12, 8))
    epss_growth_rate_7d: Mapped[float | None] = mapped_column(Numeric(14, 6))
    epss_volatility_7d: Mapped[float | None] = mapped_column(Numeric(12, 8))
    epss_percentile_change: Mapped[float | None] = mapped_column(Numeric(8, 6))
    days_until_poc: Mapped[int | None] = mapped_column(Integer)
    poc_observed_by_checkpoint: Mapped[bool] = mapped_column(Boolean, nullable=False)
    days_until_kev: Mapped[int | None] = mapped_column(Integer)
    kev_observed_by_checkpoint: Mapped[bool] = mapped_column(Boolean, nullable=False)
    related_vendor_kev_velocity: Mapped[float | None] = mapped_column(Numeric(12, 6))
    related_cwe_kev_velocity: Mapped[float | None] = mapped_column(Numeric(12, 6))
    # landmark-design EPSS features (forward-fill only, as of as_of_date)
    epss_pct_now: Mapped[float | None] = mapped_column(Numeric(8, 6))
    epss_pct_7d_ago: Mapped[float | None] = mapped_column(Numeric(8, 6))
    epss_pct_7d_ago_missing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    epss_pct_delta_7d: Mapped[float | None] = mapped_column(Numeric(9, 6))
    epss_pct_first: Mapped[float | None] = mapped_column(Numeric(8, 6))
    epss_pct_max_to_date: Mapped[float | None] = mapped_column(Numeric(8, 6))
    days_to_first_epss: Mapped[int | None] = mapped_column(Integer)
    epss_model_version_at_asof: Mapped[str | None] = mapped_column(Text)
    epss_score_at_asof_raw: Mapped[float | None] = mapped_column(Numeric(8, 6))
    spans_version_transition: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cwe_kev_rate_expanding: Mapped[float | None] = mapped_column(Numeric(8, 6))
    vendor_kev_rate_expanding: Mapped[float | None] = mapped_column(Numeric(8, 6))
    product_count: Mapped[int | None] = mapped_column(Integer)
    exploit_published_by_asof: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    days_to_first_exploit: Mapped[int | None] = mapped_column(Integer)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DerivedFeatures(Base):
    __tablename__ = "derived_features"
    __table_args__ = (
        PrimaryKeyConstraint("cve_id", "checkpoint_day"),
        ForeignKeyConstraint(
            ["cve_id", "checkpoint_day"],
            ["features.temporal_features.cve_id", "features.temporal_features.checkpoint_day"],
        ),
        {"schema": "features"},
    )

    cve_id: Mapped[str] = mapped_column(String(20), nullable=False)
    checkpoint_day: Mapped[int] = mapped_column(Integer, nullable=False)
    composite_risk_index: Mapped[float | None] = mapped_column(Numeric(8, 5))
    vendor_historical_kev_rate: Mapped[float | None] = mapped_column(Numeric(6, 5))
    time_since_disclosure_days: Mapped[int | None] = mapped_column(Integer)
    rolling_epss_avg_7d: Mapped[float | None] = mapped_column(Numeric(8, 6))
    rolling_epss_avg_30d: Mapped[float | None] = mapped_column(Numeric(8, 6))
    epss_max_to_date: Mapped[float | None] = mapped_column(Numeric(8, 6))
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


# =============================================================================
# TRAINING
# =============================================================================


class SurvivalLabels(Base):
    __tablename__ = "survival_labels"
    __table_args__ = (
        PrimaryKeyConstraint("cve_id", "checkpoint_day"),
        CheckConstraint("event_type IN ('kev','poc','epss_threshold','none')"),
        {"schema": "training"},
    )

    cve_id: Mapped[str] = mapped_column(String(20), nullable=False)
    checkpoint_day: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    event_time: Mapped[int | None] = mapped_column(Integer)
    censor_flag: Mapped[bool] = mapped_column(Boolean, nullable=False)
    composite_event: Mapped[bool] = mapped_column(Boolean, nullable=False)
    event_type: Mapped[str | None] = mapped_column(Text)
    observation_window_end: Mapped[date] = mapped_column(Date, nullable=False)
    label_computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TrainingDataset(Base):
    __tablename__ = "training_dataset"
    __table_args__ = (
        PrimaryKeyConstraint("cve_id", "checkpoint_day", "dataset_version"),
        {"schema": "training"},
    )

    cve_id: Mapped[str] = mapped_column(String(20), nullable=False)
    checkpoint_day: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    as_of_date: Mapped[date] = mapped_column(Date, nullable=False)
    cvss_base_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_version: Mapped[str | None] = mapped_column(Text)
    attack_vector: Mapped[str | None] = mapped_column(Text)
    attack_complexity: Mapped[str | None] = mapped_column(Text)
    privileges_required: Mapped[str | None] = mapped_column(Text)
    user_interaction: Mapped[str | None] = mapped_column(Text)
    confidentiality_impact: Mapped[str | None] = mapped_column(Text)
    integrity_impact: Mapped[str | None] = mapped_column(Text)
    availability_impact: Mapped[str | None] = mapped_column(Text)
    vendor_normalized: Mapped[str | None] = mapped_column(Text)
    product_normalized: Mapped[str | None] = mapped_column(Text)
    primary_cwe_id: Mapped[str | None] = mapped_column(String(20))
    cwe_historical_base_rate: Mapped[float | None] = mapped_column(Numeric(6, 5))
    n_affected_products: Mapped[int | None] = mapped_column(Integer)
    vendor_count: Mapped[int | None] = mapped_column(Integer)
    epss_score_at_checkpoint: Mapped[float | None] = mapped_column(Numeric(8, 6))
    epss_percentile_at_checkpoint: Mapped[float | None] = mapped_column(Numeric(8, 6))
    epss_slope_7d: Mapped[float | None] = mapped_column(Numeric(12, 8))
    epss_growth_rate_7d: Mapped[float | None] = mapped_column(Numeric(14, 6))
    epss_volatility_7d: Mapped[float | None] = mapped_column(Numeric(12, 8))
    epss_percentile_change: Mapped[float | None] = mapped_column(Numeric(8, 6))
    days_until_poc: Mapped[int | None] = mapped_column(Integer)
    poc_observed_by_checkpoint: Mapped[bool | None] = mapped_column(Boolean)
    days_until_kev: Mapped[int | None] = mapped_column(Integer)
    kev_observed_by_checkpoint: Mapped[bool | None] = mapped_column(Boolean)
    related_vendor_kev_velocity: Mapped[float | None] = mapped_column(Numeric(12, 6))
    related_cwe_kev_velocity: Mapped[float | None] = mapped_column(Numeric(12, 6))
    composite_risk_index: Mapped[float | None] = mapped_column(Numeric(8, 5))
    vendor_historical_kev_rate: Mapped[float | None] = mapped_column(Numeric(6, 5))
    time_since_disclosure_days: Mapped[int | None] = mapped_column(Integer)
    rolling_epss_avg_7d: Mapped[float | None] = mapped_column(Numeric(8, 6))
    rolling_epss_avg_30d: Mapped[float | None] = mapped_column(Numeric(8, 6))
    epss_max_to_date: Mapped[float | None] = mapped_column(Numeric(8, 6))
    epss_pct_now: Mapped[float | None] = mapped_column(Numeric(8, 6))
    epss_pct_7d_ago: Mapped[float | None] = mapped_column(Numeric(8, 6))
    epss_pct_7d_ago_missing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    epss_pct_delta_7d: Mapped[float | None] = mapped_column(Numeric(9, 6))
    epss_pct_first: Mapped[float | None] = mapped_column(Numeric(8, 6))
    epss_pct_max_to_date: Mapped[float | None] = mapped_column(Numeric(8, 6))
    days_to_first_epss: Mapped[int | None] = mapped_column(Integer)
    epss_model_version_at_asof: Mapped[str | None] = mapped_column(Text)
    epss_score_at_asof_raw: Mapped[float | None] = mapped_column(Numeric(8, 6))
    spans_version_transition: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cwe_kev_rate_expanding: Mapped[float | None] = mapped_column(Numeric(8, 6))
    vendor_kev_rate_expanding: Mapped[float | None] = mapped_column(Numeric(8, 6))
    product_count: Mapped[int | None] = mapped_column(Integer)
    exploit_published_by_asof: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    days_to_first_exploit: Mapped[int | None] = mapped_column(Integer)
    event_time: Mapped[int | None] = mapped_column(Integer)
    censor_flag: Mapped[bool] = mapped_column(Boolean, nullable=False)
    composite_event: Mapped[bool] = mapped_column(Boolean, nullable=False)
    event_type: Mapped[str | None] = mapped_column(Text)
    dataset_version: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    exported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Prediction(Base):
    __tablename__ = "prediction"
    __table_args__ = (
        CheckConstraint("model_name IN ('cox_ph','rsf','xgboost_aft','logreg')"),
        {"schema": "training"},
    )

    prediction_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    checkpoint_day: Mapped[int] = mapped_column(Integer, nullable=False)
    model_name: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    model_version: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    predicted_risk_score: Mapped[float | None] = mapped_column(Numeric(8, 6))
    predicted_survival_time: Mapped[float | None] = mapped_column(Numeric(10, 3))
    predicted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
