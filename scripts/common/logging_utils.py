"""
Shared logging factory. Every script in the pipeline gets its logger from
`get_logger(__name__, category=...)` instead of configuring logging itself —
this is what guarantees consistent, timestamped, rotating logs across the
whole project without copy-pasted setup code.

Log files land under `logs/<category>/<category>_<YYYYMMDD>.log`, rotated by
size per `logging.rotate_max_bytes` / `rotate_backup_count` in config.yaml.
A console handler always mirrors output at the configured level.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from config.config_schema import get_config

_CONFIGURED_LOGGERS: set[str] = set()

Category = Literal["download", "clean", "features", "labels", "pipeline", "export", "db", "test", "evaluate"]


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        extra = getattr(record, "extra_fields", None)
        if extra:
            payload.update(extra)
        return json.dumps(payload, default=str)


class TextFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


def get_logger(name: str, category: Category = "pipeline") -> logging.Logger:
    """Return a configured logger. Safe to call repeatedly with the same name."""
    cfg = get_config()
    logger = logging.getLogger(name)

    if name in _CONFIGURED_LOGGERS:
        return logger

    logger.setLevel(cfg.logging.level)
    logger.propagate = False

    formatter: logging.Formatter = JsonFormatter() if cfg.logging.format == "json" else TextFormatter()

    log_dir: Path = cfg.paths.logs / category
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"{category}_{datetime.now(tz=timezone.utc):%Y%m%d}.log"

    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=cfg.logging.rotate_max_bytes,
        backupCount=cfg.logging.rotate_backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(TextFormatter())
    logger.addHandler(console_handler)

    _CONFIGURED_LOGGERS.add(name)
    return logger


def log_with_fields(logger: logging.Logger, level: int, message: str, **fields: object) -> None:
    """Log with structured extra fields (rendered into the JSON payload).

    Example: log_with_fields(logger, logging.INFO, "cleaning complete",
                              rows_before=1000, rows_after=950, rows_dropped=50)
    """
    logger.log(level, message, extra={"extra_fields": fields})
