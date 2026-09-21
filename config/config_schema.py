"""
Loads, interpolates, and validates config/config.yaml.

This is the ONLY place that reads config.yaml or .env directly — every other
module in the project calls `get_config()` and works with typed, validated
Pydantic models. This is what makes "no hardcoded values" enforceable: a
script that needs a URL, threshold, or path has nowhere to hardcode it,
because everything it needs already has a typed home here.

Env-var interpolation supports `${VAR}` (required, raises if unset) and
`${VAR:-default}` (falls back to `default` if VAR is unset or empty).
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_YAML_PATH = PROJECT_ROOT / "config" / "config.yaml"
ENV_PATH = PROJECT_ROOT / ".env"

_INTERP_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}")


class ConfigError(RuntimeError):
    """Raised for missing/invalid config.yaml or .env values."""


def _interpolate_value(value: str) -> str:
    def _sub(match: re.Match[str]) -> str:
        var_name = match.group(1)
        has_default = match.group(2) is not None
        default = match.group(3)
        env_val = os.environ.get(var_name)
        if env_val:
            return env_val
        if has_default:
            return default or ""
        raise ConfigError(
            f"Required environment variable '{var_name}' is not set. "
            f"Copy .env.example to .env and fill it in, or export it directly."
        )

    return _INTERP_PATTERN.sub(_sub, value)


def _interpolate(node: Any) -> Any:
    if isinstance(node, str):
        return _interpolate_value(node)
    if isinstance(node, dict):
        return {k: _interpolate(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_interpolate(v) for v in node]
    return node


# ---------------------------------------------------------------------------
# Pydantic models — one per config.yaml section
# ---------------------------------------------------------------------------


class ProjectConfig(BaseModel):
    name: str
    version: str
    timezone: str = "UTC"


class PathsConfig(BaseModel):
    data_raw: Path
    data_processed: Path
    data_features: Path
    data_training: Path
    logs: Path

    def resolve_all(self, root: Path) -> "PathsConfig":
        return PathsConfig(
            **{field: (root / getattr(self, field)) for field in type(self).model_fields}
        )


class DatabaseConfig(BaseModel):
    host: str
    port: int
    name: str
    user: str
    password: str
    test_name: str
    schema_search_path: list[str]
    pool_size: int = 5
    echo_sql: bool = False

    def sqlalchemy_url(self, *, database: str | None = None) -> str:
        db = database or self.name
        return f"postgresql+psycopg://{self.user}:{self.password}@{self.host}:{self.port}/{db}"

    def test_sqlalchemy_url(self) -> str:
        return self.sqlalchemy_url(database=self.test_name)


class RetryConfig(BaseModel):
    max_attempts: int = 5
    backoff_base_seconds: float = 2
    backoff_max_seconds: float = 60


class NvdRateLimit(BaseModel):
    requests_no_key: int = 5
    requests_with_key: int = 50
    window_seconds: int = 30


class NvdScope(BaseModel):
    mode: Literal["bounded", "full_backfill"] = "bounded"
    bounded_lookback_days: int = 730
    full_backfill_start_date: str = "1999-01-01"


class NvdSourceConfig(BaseModel):
    base_url: str
    api_key: str = ""
    results_per_page: int = 2000
    max_date_window_days: int = 120
    rate_limit: NvdRateLimit
    scope: NvdScope
    retry: RetryConfig

    @property
    def effective_rate_limit(self) -> int:
        return self.rate_limit.requests_with_key if self.api_key else self.rate_limit.requests_no_key


class EpssScope(BaseModel):
    mode: Literal["bounded", "full_backfill"] = "bounded"
    bounded_lookback_days: int = 730


class EpssSourceConfig(BaseModel):
    daily_url_template: str
    current_url: str
    earliest_available_date: str
    scope: EpssScope
    concurrency: int = 8
    retry: RetryConfig


class KevSourceConfig(BaseModel):
    url: str
    retry: RetryConfig


class FuzzyMatchConfig(BaseModel):
    enabled: bool = True
    min_confidence: float = 0.75
    method: str = "rapidfuzz_token_sort_ratio"


class ExploitdbSourceConfig(BaseModel):
    mode: Literal["csv_index", "full_clone"] = "csv_index"
    files_exploits_url: str
    files_shellcodes_url: str
    full_clone_repo: str
    fuzzy_match: FuzzyMatchConfig
    retry: RetryConfig


class CweSourceConfig(BaseModel):
    url: str
    retry: RetryConfig


class SourcesConfig(BaseModel):
    nvd: NvdSourceConfig
    epss: EpssSourceConfig
    kev: KevSourceConfig
    exploitdb: ExploitdbSourceConfig
    cwe: CweSourceConfig


class CvssConfig(BaseModel):
    preference_order: list[str]


class CleaningConfig(BaseModel):
    vendor_alias_map_path: Path
    cve_id_regex: str


class CheckpointsConfig(BaseModel):
    days: list[int]

    @field_validator("days")
    @classmethod
    def _sorted_nonneg(cls, v: list[int]) -> list[int]:
        if any(d < 0 for d in v):
            raise ValueError("checkpoint days must be non-negative")
        return sorted(set(v))


class EpssThresholdConfig(BaseModel):
    enabled: bool = True
    threshold: float = 0.10


class CompositeEventConfig(BaseModel):
    kev_added: bool = True
    poc_appears: bool = True
    epss_threshold: EpssThresholdConfig


class SurvivalLabelsConfig(BaseModel):
    composite_event: CompositeEventConfig
    observation_window_end: str = "auto"
    pre_checkpoint_event_policy: Literal["exclude", "immediate_event"] = "exclude"
    event_priority: list[Literal["kev", "poc", "epss_threshold"]]


class EpssReconstructionConfig(BaseModel):
    fill_method: Literal["forward_fill"] = "forward_fill"
    pre_first_observation_policy: Literal["null_no_row"] = "null_no_row"
    max_ffill_gap_days: int | None = None


class CweBaseRateConfig(BaseModel):
    min_prior_observations: int = 10


class LeakageValidationConfig(BaseModel):
    tolerance: float = 1e-9
    enforce_as_of_query_only: bool = True


class FeatureEngineeringConfig(BaseModel):
    cwe_base_rate: CweBaseRateConfig
    rolling_windows_days: list[int]
    leakage_validation: LeakageValidationConfig


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: Literal["json", "text"] = "json"
    rotate_max_bytes: int = 10_485_760
    rotate_backup_count: int = 10


class ExportConfig(BaseModel):
    formats: list[Literal["csv", "parquet", "sql"]]
    dataset_version_strategy: Literal["date_stamp"] = "date_stamp"


class Config(BaseModel):
    project: ProjectConfig
    paths: PathsConfig
    database: DatabaseConfig
    sources: SourcesConfig
    cvss: CvssConfig
    cleaning: CleaningConfig
    checkpoints: CheckpointsConfig
    survival_labels: SurvivalLabelsConfig
    epss_reconstruction: EpssReconstructionConfig
    feature_engineering: FeatureEngineeringConfig
    logging: LoggingConfig
    export: ExportConfig

    project_root: Path = Field(default=PROJECT_ROOT, exclude=True)

    def model_post_init(self, __context: Any) -> None:
        self.paths = self.paths.resolve_all(self.project_root)
        self.cleaning = self.cleaning.model_copy(
            update={"vendor_alias_map_path": self.project_root / self.cleaning.vendor_alias_map_path}
        )


@lru_cache(maxsize=1)
def get_config() -> Config:
    """Load, interpolate, and validate config.yaml. Cached — call freely."""
    load_dotenv(ENV_PATH, override=False)

    if not CONFIG_YAML_PATH.exists():
        raise ConfigError(f"config.yaml not found at {CONFIG_YAML_PATH}")

    raw = yaml.safe_load(CONFIG_YAML_PATH.read_text())
    interpolated = _interpolate(raw)
    return Config.model_validate(interpolated)


def reload_config() -> Config:
    """Bypass the cache — used by tests that mutate env vars between cases."""
    get_config.cache_clear()
    return get_config()
