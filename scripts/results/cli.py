"""Entry point for `vsp results` (wired in scripts/cli.py)."""

from __future__ import annotations

import sys

from rich.console import Console

from scripts.results.record import RECORD_PATH, RECORD_RELPATH, RecordError, load
from scripts.results.render import SECTIONS, build, emit


def main(sections: list[str] | None = None, check: bool = False) -> None:
    unknown = [s for s in sections or [] if s not in SECTIONS]
    if unknown:
        sys.exit(f"unknown section(s): {', '.join(unknown)}. Choose from: {', '.join(SECTIONS)}")
    try:
        if check:
            from scripts.results.check import run_check

            problems = run_check(RECORD_PATH, sections)
            if problems:
                for p in problems:
                    print(f"MISMATCH {p}", file=sys.stderr)
                sys.exit(f"vsp results --check: {len(problems)} printed value(s) disagree with {RECORD_RELPATH}")
            print(f"vsp results --check: every printed value matches {RECORD_RELPATH}")
            return
        emit(Console(highlight=False, emoji=False), build(load(RECORD_PATH), sections))
    except RecordError as exc:
        sys.exit(f"vsp results: {exc}")
