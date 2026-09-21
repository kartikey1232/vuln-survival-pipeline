"""
Root Typer CLI for the vulnerability survival-analysis pipeline.

Each subcommand is a thin wrapper around a plain `main(**kwargs)` function in
the corresponding script module — the CLI never contains logic of its own,
so every command is equally runnable as `python -m scripts.<pkg>.<module>`
for debugging. Commands are wired in as each phase of the build lands; see
docs/pipeline_stages.md for the phase plan.
"""

from __future__ import annotations

import typer

app = typer.Typer(
    name="vsp",
    help="Trajectory-Aware Survival Analysis pipeline — vulnerability data engineering CLI.",
    no_args_is_help=True,
)

download_app = typer.Typer(help="Download raw data from NVD, EPSS, KEV, ExploitDB, CWE.")
clean_app = typer.Typer(help="Clean/normalize raw data into the canonical schema.")
reconstruct_app = typer.Typer(help="Reconstruct derived timelines (EPSS).")
features_app = typer.Typer(help="Build static/temporal/derived features.")
labels_app = typer.Typer(help="Build survival-analysis labels.")
export_app = typer.Typer(help="Export the final training dataset.")
db_app = typer.Typer(help="Database schema management.")

app.add_typer(download_app, name="download")
app.add_typer(clean_app, name="clean")
app.add_typer(reconstruct_app, name="reconstruct")
app.add_typer(features_app, name="features")
app.add_typer(labels_app, name="labels")
app.add_typer(export_app, name="export")
app.add_typer(db_app, name="db")


def _not_yet_implemented(command: str, phase: str) -> None:
    typer.secho(
        f"'{command}' is not implemented yet (arrives in {phase} — see docs/pipeline_stages.md).",
        fg=typer.colors.YELLOW,
    )
    raise typer.Exit(code=1)


# --- download ---------------------------------------------------------------


@download_app.command("nvd")
def download_nvd(
    start_date: str = typer.Option(None, help="ISO date, overrides config scope"),
    end_date: str = typer.Option(None, help="ISO date, overrides config scope"),
    mode: str = typer.Option(None, help="bounded | full_backfill, overrides config"),
) -> None:
    from scripts.download.download_nvd import main

    main(start_date=start_date, end_date=end_date, mode=mode)


@download_app.command("epss")
def download_epss(
    start_date: str = typer.Option(None, help="ISO date, overrides config scope"),
    end_date: str = typer.Option(None, help="ISO date, overrides config scope"),
) -> None:
    from scripts.download.download_epss import main

    main(start_date=start_date, end_date=end_date)


@download_app.command("kev")
def download_kev() -> None:
    from scripts.download.download_kev import main

    main()


@download_app.command("exploitdb")
def download_exploitdb(
    full_clone: bool = typer.Option(False, help="Clone the full repo instead of just the CSV index"),
) -> None:
    from scripts.download.download_exploitdb import main

    main(full_clone=full_clone)


@download_app.command("cwe")
def download_cwe() -> None:
    from scripts.download.download_cwe import main

    main()


@download_app.command("all")
def download_all(
    sources: str = typer.Option("nvd,epss,kev,exploitdb,cwe", help="Comma-separated source list"),
    sequential: bool = typer.Option(False, help="Run sources one at a time instead of in parallel"),
    fail_fast: bool = typer.Option(False, help="Exit non-zero if any source fails (default: continue)"),
) -> None:
    from scripts.download.download_all import main

    main(sources=sources.split(","), sequential=sequential, fail_fast=fail_fast)


# --- clean -------------------------------------------------------------------


@clean_app.command("nvd")
def clean_nvd() -> None:
    from scripts.clean.clean_nvd import main

    main()


@clean_app.command("epss")
def clean_epss() -> None:
    from scripts.clean.clean_epss import main

    main()


@clean_app.command("kev")
def clean_kev() -> None:
    from scripts.clean.clean_kev import main

    main()


@clean_app.command("exploitdb")
def clean_exploitdb() -> None:
    from scripts.clean.clean_exploitdb import main

    main()


@clean_app.command("cwe")
def clean_cwe() -> None:
    from scripts.clean.clean_cwe import main

    main()


@clean_app.command("all")
def clean_all() -> None:
    from scripts.clean.clean_all import main

    main()


# --- reconstruct ---------------------------------------------------------------


@reconstruct_app.command("epss")
def reconstruct_epss(
    cve_id: str = typer.Option(None, help="Limit to a single CVE (debugging)"),
    batch_size: int = typer.Option(2000, help="CVE-ID chunk size for vectorized processing"),
) -> None:
    from scripts.epss_reconstruct.reconstruct_epss_timeline import main

    main(cve_id=cve_id, batch_size=batch_size)


# --- features ---------------------------------------------------------------


@features_app.command("static")
def features_static() -> None:
    from scripts.features.build_static_features import main

    main()


@features_app.command("temporal")
def features_temporal(
    checkpoint_day: int = typer.Option(..., help="Checkpoint day, must be in config.checkpoints.days"),
) -> None:
    from scripts.features.build_temporal_features import main

    main(checkpoint_day=checkpoint_day)


@features_app.command("derived")
def features_derived(
    checkpoint_day: int = typer.Option(..., help="Checkpoint day, must be in config.checkpoints.days"),
) -> None:
    from scripts.features.build_derived_features import main

    main(checkpoint_day=checkpoint_day)


@features_app.command("all")
def features_all(
    checkpoints: str = typer.Option(None, help="Comma-separated checkpoint days, default: all configured"),
) -> None:
    from scripts.features.build_all_features import main

    main(checkpoints=checkpoints.split(",") if checkpoints else None)


# --- labels ---------------------------------------------------------------


@labels_app.command("build")
def labels_build(
    checkpoints: str = typer.Option(None, help="Comma-separated checkpoint days, default: all configured"),
    observation_window_end: str = typer.Option(None, help="ISO date, overrides config"),
) -> None:
    from scripts.labels.build_survival_labels import main

    main(
        checkpoints=checkpoints.split(",") if checkpoints else None,
        observation_window_end=observation_window_end,
    )


# --- export ---------------------------------------------------------------


@export_app.command("training")
def export_training(
    formats: str = typer.Option(None, help="Comma-separated: csv,parquet,sql — default: all configured"),
    version_tag: str = typer.Option(None, help="Override the auto date-stamped dataset_version"),
) -> None:
    from scripts.export.export_training_dataset import main

    main(formats=formats.split(",") if formats else None, version_tag=version_tag)


# --- db ---------------------------------------------------------------


@db_app.command("init")
def db_init(
    drop_existing: bool = typer.Option(False, help="Drop and recreate schemas first (destructive)"),
) -> None:
    from database.init_db import main

    main(drop_existing=drop_existing)


@db_app.command("migrate")
def db_migrate(message: str = typer.Option(..., help="Alembic revision message")) -> None:
    """Generate an autogenerate migration from database/models.py against
    the live DB, then apply it. Use for incremental schema changes after the
    initial schema.sql-based revision."""
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from config.config_schema import PROJECT_ROOT

    alembic_cfg = AlembicConfig(str(PROJECT_ROOT / "alembic.ini"))
    command.revision(alembic_cfg, message=message, autogenerate=True)
    command.upgrade(alembic_cfg, "head")


# --- pipeline ---------------------------------------------------------------


@app.command("pipeline-run-all")
def pipeline_run_all(
    from_stage: str = typer.Option("download", help="download|clean|reconstruct|features|labels|export"),
    to_stage: str = typer.Option("export", help="download|clean|reconstruct|features|labels|export"),
) -> None:
    _not_yet_implemented("pipeline-run-all", "the phase after export lands (Phase 7+)")


if __name__ == "__main__":
    app()
