"""
Read/write helpers for staging.file_manifest — the download bookkeeping
table every downloader consults before fetching anything (resumability) and
writes to after fetching (auditability).

A file is considered "already downloaded" if a manifest row exists for
(source, file_path) with status in ('verified', 'parsed') AND the sha256
recorded matches the sha256 of the file currently on disk (guards against a
manifest row surviving a partial/corrupted write).
"""

from __future__ import annotations

from datetime import date, datetime
from pathlib import Path

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from database.models import FileManifest
from scripts.common.checksums import sha256_file


def already_downloaded(session: Session, *, source: str, file_path: str) -> FileManifest | None:
    row = (
        session.query(FileManifest)
        .filter(
            FileManifest.source == source,
            FileManifest.file_path == file_path,
            FileManifest.status.in_(["verified", "parsed"]),
        )
        .one_or_none()
    )
    if row is None:
        return None
    local_path = Path(file_path)
    if not local_path.exists():
        return None
    if sha256_file(local_path) != row.sha256:
        return None
    return row


def upsert_manifest(
    session: Session,
    *,
    source: str,
    file_path: str,
    url: str,
    fetched_at: datetime,
    sha256: str,
    byte_size: int,
    status: str,
    snapshot_date: date | None = None,
    row_count: int | None = None,
    http_status: int | None = None,
) -> int:
    """INSERT ... ON CONFLICT (source, file_path) DO UPDATE. Returns manifest_id."""
    stmt = (
        pg_insert(FileManifest)
        .values(
            source=source,
            file_path=file_path,
            url=url,
            fetched_at=fetched_at,
            snapshot_date=snapshot_date,
            sha256=sha256,
            byte_size=byte_size,
            row_count=row_count,
            status=status,
            http_status=http_status,
        )
        .on_conflict_do_update(
            index_elements=["source", "file_path"],
            set_={
                "url": url,
                "fetched_at": fetched_at,
                "snapshot_date": snapshot_date,
                "sha256": sha256,
                "byte_size": byte_size,
                "row_count": row_count,
                "status": status,
                "http_status": http_status,
            },
        )
        .returning(FileManifest.manifest_id)
    )
    return session.execute(stmt).scalar_one()
