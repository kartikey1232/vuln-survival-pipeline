"""Engine/session factory. Every script gets its DB access through here —
never constructs its own `create_engine()` call — so pool settings, echo
mode, and the target database (prod vs test) stay centralized.

IMPORTANT — this is a SYNCHRONOUS engine (create_engine, not
create_async_engine; psycopg used in its sync mode). Every call through
session_scope() blocks whatever thread calls it for the full DB round-trip.

If you call session_scope() (or anything that uses it) directly inside an
`async def`, that blocks the ONE asyncio event loop thread — not just the
calling task. Every other coroutine on that loop, including other tasks'
in-flight HTTP awaits, stalls until the DB call returns. Under
asyncio.gather/Semaphore-style concurrency this silently serializes
everything that looks concurrent, and gets worse as your tables grow (more
index maintenance per write). This is not hypothetical: it's exactly what
happened in scripts/download/download_epss.py — 8-way "concurrent"
downloads were fully serializing on every DB round-trip, degrading a job
from ~15 minutes to a 9-10 hour ETA, and it was invisible in
scripts/download/download_nvd.py only because that script has no
concurrency (a plain sequential for-loop) to expose the problem.

The fix, and the pattern to follow anywhere this engine is used from async
code: wrap the synchronous DB call in `await asyncio.to_thread(...)` (see
download_epss.py's `_check_already_downloaded` / `_write_manifest_and_rows`
for the pattern), and make sure `database.pool_size` in config.yaml is >=
the highest concurrency any caller will run with — a thread blocked
waiting for a pool checkout still stalls its own task for nothing if the
pool is smaller than the concurrency asking for connections."""

from __future__ import annotations

from contextlib import contextmanager
from functools import lru_cache
from typing import Iterator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from config.config_schema import get_config


@lru_cache(maxsize=2)
def get_engine(*, test: bool = False) -> Engine:
    cfg = get_config()
    url = cfg.database.test_sqlalchemy_url() if test else cfg.database.sqlalchemy_url()
    return create_engine(
        url,
        pool_size=cfg.database.pool_size,
        echo=cfg.database.echo_sql,
        future=True,
    )


def get_sessionmaker(*, test: bool = False) -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(test=test), expire_on_commit=False, future=True)


@contextmanager
def session_scope(*, test: bool = False) -> Iterator[Session]:
    """`with session_scope() as session: ...` — commits on success, rolls
    back and re-raises on exception."""
    session = get_sessionmaker(test=test)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
