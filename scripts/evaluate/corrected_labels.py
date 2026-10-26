"""
Corrected-labels re-evaluation: every reported test-period metric
recomputed with the 18 test rows of 6 CVEs relabelled
(scripts/evaluate/label_corrections.py, tests/fixtures/kev_label_diffs_20261021.json),
and nothing else changed. Frozen models, frozen (stored) features, the same
seed and 200 whole-CVE resamples, through scripts/evaluate/common.py.
training.training_dataset is not written to: the relabel is in memory.
Refits happen only where the recorded analysis refit (the trajectory
ablations and the rolling-origin folds); their training labels are
unchanged, because all 6 listings fall after every training cutoff.

Two passes, each in its own process:

  run --labels stored     the same computations on the stored labels. Must
                          reproduce every recorded result file exactly;
                          `report` refuses to run otherwise.
  run --labels corrected  the new record.
  report                  checks the stored pass against the recorded
                          files, then writes the corrected-vs-recorded
                          comparison (every number, its difference, and
                          every significance-boundary crossing) to
                          results/corrected_labels/comparison.json and
                          docs/results_corrected_labels.md.

Not re-run: the RSF seed-variance study (RSF refits are not reproducible,
so a re-run would mix label effects with run-to-run noise) and the
original-encoding numbers (superseded).

Writes results/corrected_labels/{stored,corrected}.json, which are
committed: corrected.json is the record (`vsp results` reads it). Each
carries a provenance block naming the commit it was generated at, and `run`
refuses to start on a working tree with uncommitted changes to tracked
files, so that commit is the code that produced it. Checkpoints and logs go
to scratch/corrected_labels/. The corrected pass also writes
docs/figures/calibration_90d{,_calibrated}_corrected_labels.png and
scratch/corrected_labels/lead_time_per_cve_corrected.csv.

Usage: python -m scripts.evaluate.corrected_labels {run --labels stored|corrected | report}
"""

from __future__ import annotations

import json
import logging
import pickle
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from config.config_schema import get_config
from scripts.common.logging_utils import get_logger, log_with_fields
from scripts.evaluate import calibration
from scripts.evaluate.budget_equivalence import budget_results
from scripts.evaluate.common import CI_PERCENTILES, DEFAULT_SEED, fast_concordance_index, survival_array
from scripts.evaluate.corrected_encoding import METADATA_FILES, MODELS, headline_metrics, post_freeze
from scripts.evaluate.corrected_labels_report import render
from scripts.evaluate.cox_trajectory_ablation import cox_trajectory_ablation
from scripts.evaluate.data_splits import load_full_train_and_test
from scripts.evaluate.final_comparison import _prep
from scripts.evaluate.label_corrections import known_diffs, set_labels
from scripts.evaluate.lead_time import lead_time_results
from scripts.evaluate.post_freeze_metrics import load_frozen_predictions
from scripts.evaluate.rolling_origin import (
    _check_against_training_dataset,
    evaluate_folds,
    full_grid,
    headline_sanity,
)
from scripts.evaluate.sensitivity import evaluate_subsets, frozen_cox_scores, load_test_aug
from scripts.evaluate.stale_reruns import xgb_trajectory_ablation
from scripts.features.build_landmark_dataset import DATA_CUTOFF, STUDY_END, TRAIN_TEST_CUTOFF
from scripts.fuzzy.evaluate_fuzzy import frozen_config, test_results
from scripts.fuzzy.risk_percentile import OUTPUT_FILENAMES

logger = get_logger(__name__, category="evaluate")

OUT_SUBDIR = Path("scratch") / "corrected_labels"  # checkpoints, logs, per-CVE CSVs
RECORD_SUBDIR = Path("results") / "corrected_labels"  # committed outputs
N_RESAMPLES = 200  # every analysis here uses common.py's default


def relabel(df: pd.DataFrame, labels: str, *, expect: int | None = None) -> pd.DataFrame:
    """`set_labels`, refusing unless it found `expect` listed rows (all of
    them by default: every default-export test frame holds all 18)."""
    diffs = known_diffs()
    out, n = set_labels(df, labels, diffs=diffs)
    expect = len(diffs) if expect is None else expect
    if n != expect:
        raise RuntimeError(f"found {n} of the listed rows, expected {expect}")
    return out


def population(test_df: pd.DataFrame) -> dict:
    """Counts, plus the test set's definition: its publication window and
    the date labels are observed to (checked against the rows)."""
    ev = test_df["composite_event"].astype(bool)
    published = pd.to_datetime(test_df["as_of_date"]) - pd.to_timedelta(test_df["landmark_day"].astype(int), unit="D")
    if published.min().date() < TRAIN_TEST_CUTOFF or published.max().date() > STUDY_END:
        raise RuntimeError(f"test rows published {published.min().date()}..{published.max().date()}, "
                           f"outside {TRAIN_TEST_CUTOFF}..{STUDY_END}")
    observed_to = (pd.to_datetime(test_df["as_of_date"]) + pd.to_timedelta(test_df["event_time"], unit="D"))[~ev]
    if observed_to.max().date() != DATA_CUTOFF:
        raise RuntimeError(f"censored test rows end at {observed_to.max().date()}, not {DATA_CUTOFF}")
    return {
        "publication_window": [str(TRAIN_TEST_CUTOFF), str(STUDY_END)],
        "observation_cutoff": str(DATA_CUTOFF),
        "n_rows": len(test_df), "n_cves": int(test_df["cve_id"].nunique()), "n_events": int(ev.sum()),
        "n_event_cves": int(test_df.loc[ev, "cve_id"].nunique()),
        "n_events_within_90d": int((ev & (test_df["event_time"] <= 90)).sum()),
        "per_landmark": {str(lm): {"n_rows": int((test_df["landmark_day"] == lm).sum()),
                                   "n_events": int(ev[test_df["landmark_day"] == lm].sum())}
                         for lm in sorted(test_df["landmark_day"].unique(), key=int)},
    }


def _check_frozen_models(test_stored: pd.DataFrame, scores: dict, models_dir: Path) -> None:
    """Frozen models + stored features: each model's corrected-encoding
    C-index on the STORED labels must equal its recorded value."""
    duration = test_stored["event_time"].clip(lower=0.5).values
    event = test_stored["composite_event"].values.astype(int)
    for m in MODELS:
        recorded = json.loads((models_dir / METADATA_FILES[m]).read_text())[
            "test_metrics_corrected_encoding"]["test_cindex"]
        got = fast_concordance_index(duration, scores[m], event)
        if abs(got - recorded) > 1e-9:
            raise RuntimeError(f"{m}: frozen model gives {got} on stored labels, recorded {recorded}")


def provenance(root: Path, labels: str) -> dict:
    """The commit this pass runs at. Refuses uncommitted changes to tracked
    files (untracked/ignored files such as .env and data/ cannot change
    the code), so the commit is the code."""
    def git(*args):
        return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
    dirty = git("status", "--porcelain", "--untracked-files=no")
    if dirty:
        raise RuntimeError(f"uncommitted changes to tracked files; commit them first:\n{dirty}")
    lo, hi = CI_PERCENTILES
    return {"labels": labels, "git_commit": git("rev-parse", "HEAD"),
            "git_commit_date": git("show", "-s", "--format=%cI", "HEAD"),
            "generated_at_utc": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
            "seed": DEFAULT_SEED, "n_resamples": N_RESAMPLES, "ci_level": (hi - lo) / 100}


def run(labels: str) -> dict:
    """Stages are checkpointed to scratch/corrected_labels/<labels>.partial.json
    as they finish, so a re-run after a failure resumes at the failed stage
    (only at the same commit)."""
    cfg = get_config()
    root = cfg.project_root
    models_dir = root / "models"
    out_dir = root / OUT_SUBDIR
    out_dir.mkdir(parents=True, exist_ok=True)
    record_dir = root / RECORD_SUBDIR
    record_dir.mkdir(parents=True, exist_ok=True)
    fig_dir = root / "docs" / "figures" if labels == "corrected" else Path(tempfile.mkdtemp())
    partial = out_dir / f"{labels}.partial.json"
    prov = provenance(root, labels)

    train_df, test_stored = _prep()
    test_df = relabel(test_stored, labels)
    y_train = survival_array(train_df["event_time"].clip(lower=0.5).values, train_df["composite_event"].values)
    scores, cox_model, X_cox = load_frozen_predictions(test_stored, models_dir, encoding="corrected")
    _check_frozen_models(test_stored, scores, models_dir)
    cox = frozen_cox_scores(test_stored, models_dir)

    def headline():
        return {**headline_metrics(test_df, scores),
                **post_freeze(test_df, train_df, scores, cox_model, X_cox, y_train,
                              fig_dir / "calibration_90d_corrected_labels.png")}

    def fuzzy():
        inputs = pd.read_parquet(root / "data" / "training" / OUTPUT_FILENAMES["corrected"])
        fuzzy_test = relabel(inputs[inputs["split"] == "test"].reset_index(drop=True), labels)
        key = ["cve_id", "landmark_day"]
        cols = key + ["event_time", "composite_event"]
        m = fuzzy_test[cols].astype({"landmark_day": int}).merge(
            test_df[cols].astype({"landmark_day": int}), on=key, suffixes=("", "_td"), validate="one_to_one")
        if len(m) != len(test_df) or not ((m["event_time"] == m["event_time_td"]).all()
                                          and (m["composite_event"] == m["composite_event_td"]).all()):
            raise RuntimeError("fuzzy inputs' test labels do not match the test frame's")
        return test_results(fuzzy_test, frozen_config(cfg))[0]

    def sensitivity():
        test_aug, is_transition, cox_aug = load_test_aug(models_dir)
        return evaluate_subsets(relabel(test_aug, labels), is_transition, cox_aug)

    def lead_time():
        out, per_cve = lead_time_results(test_df, cox)
        per_cve.to_csv(out_dir / f"lead_time_per_cve_{labels}.csv", index=False)
        return out

    def rolling_origin():
        built = full_grid()  # current KEV catalog
        grid_stored = relabel(built, "stored")
        _check_against_training_dataset(grid_stored)
        headline_sanity(grid_stored, models_dir)
        grid = relabel(built, labels)
        _check_against_training_dataset(
            grid, relabel(pd.concat(load_full_train_and_test(), ignore_index=True), labels))
        return evaluate_folds(grid, models_dir)

    def display_calibration():
        with open(models_dir / "cox_final.pkl", "rb") as f:
            cox_pkl = pickle.load(f)
        return calibration.run(train_df, test_df, cox_pkl,
                               fig_dir / "calibration_90d_calibrated_corrected_labels.png")

    stages = {  # cheapest first; headline (time-dependent AUC bootstraps) is the slowest
        "population": lambda: population(test_df),
        "budget_equivalence": lambda: budget_results(test_df, cox),
        "lead_time": lead_time,
        "display_calibration": display_calibration,
        "fuzzy": fuzzy,
        "sensitivity": sensitivity,
        "rolling_origin": rolling_origin,
        "cox_trajectory_ablation": lambda: cox_trajectory_ablation(train_df, test_df),
        "xgb_trajectory_ablation": lambda: xgb_trajectory_ablation(train_df, test_df),
        "headline": headline,
    }
    out = json.loads(partial.read_text()) if partial.exists() else {"labels": labels, "provenance": prov}
    if out.get("provenance", {}).get("git_commit") != prov["git_commit"]:
        raise RuntimeError(f"{partial} was started at another commit; delete it to start over")
    for name, stage in stages.items():
        if name in out:
            log_with_fields(logger, logging.INFO, "stage already done", stage=name, labels=labels)
            continue
        log_with_fields(logger, logging.INFO, "stage", stage=name, labels=labels)
        out[name] = stage()
        partial.write_text(json.dumps(out, indent=2, default=str))

    out["provenance"]["completed_at_utc"] = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
    with open(record_dir / f"{labels}.json", "w") as f:
        json.dump(out, f, indent=2, default=str)
    partial.unlink()
    return out


# --- report -----------------------------------------------------------------

# analysis -> (recorded scratch file, key inside it, keys the pass does not produce)
RECORDED = {
    "headline": ("results_corrected_encoding.json", "corrected", ()),
    "cox_trajectory_ablation": ("cox_trajectory_ablation.json", None, ("encoding",)),
    "xgb_trajectory_ablation": ("stale_reruns.json", "xgb_trajectory_ablation",
                                ("frozen_model_cindex_corrected_encoding",)),
    "fuzzy": ("fuzzy_evaluation.json", None, ("encoding",)),
    "sensitivity": ("sensitivity.json", None, ()),
    "lead_time": ("lead_time.json", None, ()),
    "budget_equivalence": ("budget_equivalence.json", None, ()),
    "rolling_origin": ("rolling_origin.json", "folds", ()),
    "display_calibration": ("calibration_90d.json", None, ()),
}


def _norm(x):
    return json.loads(json.dumps(x, default=str))


def _mismatches(a, b, path=()):
    """Paths where a and b differ. Exact: floats must be identical (NaN
    equal to NaN)."""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                yield path + (k,), a.get(k, "<missing>"), b.get(k, "<missing>")
            else:
                yield from _mismatches(a[k], b[k], path + (k,))
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            yield from _mismatches(x, y, path + (i,))
    elif not (a == b or (isinstance(a, float) and isinstance(b, float) and a != a and b != b)):
        yield path, a, b


def recorded_results(root: Path) -> dict:
    out = {}
    for name, (fname, key, drop) in RECORDED.items():
        r = json.loads((root / "scratch" / fname).read_text())
        r = r[key] if key else r
        out[name] = {k: v for k, v in r.items() if k not in drop}
    return out


def _boundary(path: tuple) -> float:
    """The value a CI must exclude to count as significant."""
    last = str(path[-1]) if path else ""
    if "effort_ratio" in "/".join(map(str, path)):
        return 1.0
    return 0.0 if last != "cindex" else 0.5


def comparison_rows(recorded, corrected, path=()) -> list[dict]:
    """Every number in the recorded results beside its corrected value.
    Bootstrap estimates and paired differences carry their CIs and whether
    the CI excludes the null (0 for differences and most estimates, 1 for
    effort ratios, 0.5 for C-indexes)."""
    rows = []
    if isinstance(recorded, dict):
        kind = ("paired" if {"point_diff", "ci_lower", "ci_upper"} <= set(recorded)
                else "estimate" if {"point", "ci_lower", "ci_upper"} <= set(recorded) else None)
        if kind:
            p = "point_diff" if kind == "paired" else "point"
            null = 0.0 if kind == "paired" else _boundary(path)
            rec_sig = recorded["ci_lower"] > null or recorded["ci_upper"] < null
            cor_sig = corrected["ci_lower"] > null or corrected["ci_upper"] < null
            rows.append({"path": "/".join(map(str, path)), "kind": kind, "null": null,
                         "recorded": recorded[p], "recorded_ci": [recorded["ci_lower"], recorded["ci_upper"]],
                         "corrected": corrected[p], "corrected_ci": [corrected["ci_lower"], corrected["ci_upper"]],
                         "diff": corrected[p] - recorded[p],
                         "recorded_excludes_null": rec_sig, "corrected_excludes_null": cor_sig,
                         "crosses_boundary": rec_sig != cor_sig})
            return rows
        for k in recorded:
            rows += comparison_rows(recorded[k], corrected.get(k) if isinstance(corrected, dict) else None,
                                    path + (k,))
    elif isinstance(recorded, list) and isinstance(corrected, list) and len(recorded) == len(corrected):
        for i, (a, b) in enumerate(zip(recorded, corrected)):
            rows += comparison_rows(a, b, path + (i,))
    elif isinstance(recorded, (int, float)) and not isinstance(recorded, bool) and isinstance(corrected, (int, float)):
        rows.append({"path": "/".join(map(str, path)), "kind": "value", "recorded": recorded,
                     "corrected": corrected, "diff": corrected - recorded})
    return rows


def report() -> None:
    cfg = get_config()
    root = cfg.project_root
    out_dir = root / RECORD_SUBDIR
    recorded = _norm(recorded_results(root))
    stored = _norm(json.loads((out_dir / "stored.json").read_text()))
    corrected = _norm(json.loads((out_dir / "corrected.json").read_text()))
    if stored["provenance"]["git_commit"] != corrected["provenance"]["git_commit"]:
        raise RuntimeError("stored and corrected passes ran at different commits")

    reproduction = {}
    for name in RECORDED:
        bad = list(_mismatches(recorded[name], stored[name]))
        reproduction[name] = {"n_values": len(comparison_rows(recorded[name], stored[name])), "mismatches": len(bad)}
        for p, a, b in bad[:20]:
            log_with_fields(logger, logging.ERROR, "stored pass does not reproduce recorded value",
                            analysis=name, path="/".join(map(str, p)), recorded=a, stored=b)
    if any(r["mismatches"] for r in reproduction.values()):
        raise RuntimeError(f"stored-label pass does not reproduce the recorded results: {reproduction}")

    rows = {name: comparison_rows(recorded[name], corrected[name]) for name in RECORDED}
    rows["population"] = comparison_rows(stored["population"], corrected["population"])
    out = {"reproduction": reproduction, "rows": rows,
           "crossings": [{"analysis": n, **r} for n, rs in rows.items() for r in rs if r.get("crosses_boundary")]}
    with open(out_dir / "comparison.json", "w") as f:
        json.dump(out, f, indent=2, default=str)
    (root / "docs" / "results_corrected_labels.md").write_text(render(out, recorded, corrected, stored))
    log_with_fields(logger, logging.INFO, "corrected-labels report written",
                    crossings=len(out["crossings"]), **{k: v["n_values"] for k, v in reproduction.items()})


def main():
    import argparse

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run")
    p_run.add_argument("--labels", choices=["stored", "corrected"], required=True)
    sub.add_parser("report")
    args = parser.parse_args()
    if args.cmd == "run":
        run(args.labels)
    else:
        report()


if __name__ == "__main__":
    main()
