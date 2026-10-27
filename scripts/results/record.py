"""
Reads the corrected-labels record (results/corrected_labels/corrected.json,
written by scripts/evaluate/corrected_labels.py, the source of
docs/results_corrected_labels.md) into the small typed values the
presentation formats.

Reads one JSON file and nothing else: no database, no network, no config or
.env, and no pandas/numpy, so `vsp results` starts fast and has nothing to
fail on mid-demo but a missing or malformed record. No number lives here;
every value comes from the record.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RECORD_RELPATH = "results/corrected_labels/corrected.json"
RECORD_PATH = PROJECT_ROOT / RECORD_RELPATH
RECORD_DOC = "docs/results_corrected_labels.md"
BUDGETS = (1, 5, 10)  # recall / alert budgets, percent of rows


class RecordError(RuntimeError):
    pass


@dataclass(frozen=True)
class Estimate:
    """A bootstrap point estimate and its percentile interval."""
    point: float
    lo: float
    hi: float


@dataclass(frozen=True)
class Diff:
    """A paired difference. `significant` means the interval excludes zero
    strictly: a bound of exactly zero does not count."""
    point: float
    lo: float
    hi: float

    @property
    def significant(self) -> bool:
        return self.lo > 0 or self.hi < 0

    def verdict(self) -> str:
        """For a claim that the first ranking beats the second (Δ = first −
        second), what this interval says about it."""
        if not self.significant:
            return "not supported: interval spans zero"
        return "supported" if self.lo > 0 else "contradicted: significantly worse"


def load(path: Path = RECORD_PATH) -> dict:
    try:
        rec = json.loads(Path(path).read_text())
    except FileNotFoundError as exc:
        raise RecordError(f"record not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RecordError(f"record is not valid JSON: {path}: {exc}") from exc
    if rec.get("labels") != "corrected" or "provenance" not in rec:
        raise RecordError(f"{path} is not a corrected-labels record with provenance")
    return rec


def get(rec: dict, *path: str):
    node = rec
    for key in path:
        try:
            node = node[key]
        except (KeyError, TypeError) as exc:
            raise RecordError(f"record has no {'/'.join(path)}") from exc
    return node


def estimate(rec: dict, *path: str) -> Estimate:
    node = get(rec, *path)
    return Estimate(node["point"], node["ci_lower"], node["ci_upper"])


def diff(rec: dict, *path: str) -> Diff:
    node = get(rec, *path)
    return Diff(node["point_diff"], node["ci_lower"], node["ci_upper"])
