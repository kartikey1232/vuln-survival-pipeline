"""Pydantic response schemas."""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, Field


class FiredRule(BaseModel):
    id: str
    text: str
    consequent: str
    strength: float = Field(ge=0, le=1, description="Antecedent firing degree")
    affects_score: bool = Field(description="False for rules bounded by another rule with the same consequent "
                                            "(R02, R15, R16, R17): they explain but never move priority")


class FuzzyExplanation(BaseModel):
    priority: float = Field(ge=0, le=100)
    blindspot: float = Field(description="cox_risk_pct - epss_pct_now; 0 does NOT mean agreement "
                                         "(different reference populations)")
    rules_fired: list[FiredRule]


class SurvivalPoint(BaseModel):
    day: int = Field(description="Days after the landmark's as_of_date")
    survival_probability: float = Field(ge=0, le=1, description="P(not KEV-listed by then)")


class LandmarkPrediction(BaseModel):
    landmark_day: int
    as_of_date: date
    split: Literal["train", "test"]
    cox_partial_hazard: float
    cox_risk_pct: float = Field(ge=0, le=1, description="Percentile vs the training-period reference of this landmark")
    epss_pct_now: float
    cvss_base_score: float | None = Field(description="CNA-supplied score; null when the CNA gave none")
    survival_curve: list[SurvivalPoint]
    fuzzy: FuzzyExplanation


class LandmarkNotScored(BaseModel):
    landmark_day: int
    as_of_date: date
    reason: str


class CVSSMetric(BaseModel):
    cvss_version: str
    base_score: float
    base_severity: str | None
    vector_string: str
    source: str
    is_primary: bool


class CWE(BaseModel):
    cwe_id: str
    name: str | None
    source: str


class KEVEntry(BaseModel):
    date_added: date
    vendor_project: str | None
    product: str | None
    vulnerability_name: str | None
    known_ransomware: bool | None


class EPSSPoint(BaseModel):
    snapshot_date: date
    epss_score: float
    percentile: float
    is_observed: bool


class CVEResponse(BaseModel):
    cve_id: str
    published_date: date
    last_modified_date: date
    description: str | None
    vuln_status: str | None
    cna_source_identifier: str | None = Field(description="The CVE's own CNA (NVD sourceIdentifier); the model "
                                                          "only uses CVSS/CWE whose source equals it")
    cvss_metrics: list[CVSSMetric]
    cwes: list[CWE]
    kev: KEVEntry | None
    epss_history: list[EPSSPoint]
    landmarks: list[LandmarkPrediction]
    landmarks_not_scored: list[LandmarkNotScored]
    notes: list[str]


class WatchlistItem(BaseModel):
    rank: int = Field(description="1-based rank by Cox partial hazard within the pool")
    cve_id: str
    landmark_day: int
    as_of_date: date
    cox_partial_hazard: float
    cox_risk_pct: float
    epss_pct_now: float
    epss_ranks_low: bool = Field(description="Outside EPSS-alone's own top `budget` of the same pool "
                                             "(the blind-spot definition)")
    kev_date_added: date | None = Field(description="Retrospective: the pool is the historical test period")
    fuzzy: FuzzyExplanation


class WatchlistResponse(BaseModel):
    ranking: Literal["cox_partial_hazard"] = "cox_partial_hazard"
    explanation: Literal["fuzzy_rules"] = "fuzzy_rules"
    budget: float
    landmark_day: int | None
    pool: str
    pool_rows: int
    selected_rows: int
    selected_epss_ranks_low: int
    offset: int
    limit: int
    items: list[WatchlistItem]


class BacktestResponse(BaseModel):
    """Corrected-encoding test results (models/backtest_corrected_encoding.json)."""
    source: str
    test_rows: int
    test_cves: int
    test_events: int
    bootstrap: str
    models: dict
    paired_vs_epss: dict
    blind_spot_catch_rate_10pct: dict
    time_dependent_auc_pooled: dict
    fuzzy: dict
    recall_curve: dict


class ModelResponse(BaseModel):
    ranking_model: Literal["cox"] = "cox"
    explanation_layer: Literal["fuzzy"] = "fuzzy"
    cox: dict
    rsf: dict
    xgboost_aft: dict
    risk_percentile_reference: dict
    serving_preprocessing: dict
    fuzzy: dict
    known_issues: list[str]
