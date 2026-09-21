"""
Join-integrity tests for scripts/clean/*, against the real test Postgres
database (never mocked — this project doesn't use SQLite, see
tests/conftest.py). Each clean_*.py script upserts into a canonical table
with a foreign key back to canonical.cve; these tests assert that rows
whose cve_id isn't (yet) in canonical.cve are skipped rather than raising
an IntegrityError, that matching rows land correctly, and that re-running a
clean script is idempotent (no duplicate rows, no changed counts).
"""

from __future__ import annotations

from datetime import date, datetime, timezone

from sqlalchemy import select

from database.engine import session_scope
from database.models import (
    Cve,
    Exploitdb,
    ExploitdbCveMap,
    ExploitdbRaw,
    EpssScoresRaw,
    EpssTimeline,
    Kev,
    KevRaw,
    NvdCveRaw,
)
from scripts.clean import clean_epss, clean_exploitdb, clean_kev, clean_nvd

_NOW = datetime.now(tz=timezone.utc)


def _minimal_nvd_payload(cve_id: str, published: str, last_modified: str) -> dict:
    return {
        "id": cve_id,
        "published": published,
        "lastModified": last_modified,
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": f"Test description for {cve_id}"}],
        "metrics": {},
        "weaknesses": [],
        "configurations": [],
    }


def _insert_canonical_cve(cve_id: str, published: date = date(2026, 8, 1)) -> None:
    with session_scope(test=True) as session:
        session.add(
            Cve(
                cve_id=cve_id,
                published_date=published,
                last_modified_date=published,
                description="seed row",
                vuln_status="Analyzed",
                source_last_fetched_at=_NOW,
            )
        )


# --- clean_nvd ---------------------------------------------------------------


def test_clean_nvd_populates_cve_and_skips_malformed_cve_id() -> None:
    with session_scope(test=True) as session:
        session.add_all(
            [
                NvdCveRaw(
                    cve_id="CVE-2026-00001",
                    fetched_at=_NOW,
                    last_modified_src=_NOW,
                    payload=_minimal_nvd_payload(
                        "CVE-2026-00001", "2026-08-01T00:00:00.000", "2026-08-01T00:00:00.000"
                    ),
                ),
                # DB-level: staging.nvd_cve_raw has no CHECK on cve_id shape, so a
                # malformed value can land in staging — clean_nvd must filter it
                # out at the application layer rather than crash or clean it.
                NvdCveRaw(
                    cve_id="NOT-A-CVE",
                    fetched_at=_NOW,
                    last_modified_src=_NOW,
                    payload=_minimal_nvd_payload("NOT-A-CVE", "2026-08-01T00:00:00.000", "2026-08-01T00:00:00.000"),
                ),
            ]
        )

    clean_nvd.main(test=True)

    with session_scope(test=True) as session:
        cve_ids = set(session.execute(select(Cve.cve_id)).scalars().all())
    assert cve_ids == {"CVE-2026-00001"}


def test_clean_nvd_is_idempotent() -> None:
    with session_scope(test=True) as session:
        session.add(
            NvdCveRaw(
                cve_id="CVE-2026-00002",
                fetched_at=_NOW,
                last_modified_src=_NOW,
                payload=_minimal_nvd_payload(
                    "CVE-2026-00002", "2026-08-01T00:00:00.000", "2026-08-01T00:00:00.000"
                ),
            )
        )

    clean_nvd.main(test=True)
    clean_nvd.main(test=True)

    with session_scope(test=True) as session:
        count = session.execute(select(Cve)).scalars().all()
    assert len(count) == 1


# --- clean_kev -----------------------------------------------------------


def test_clean_kev_skips_cve_not_in_canonical_without_raising() -> None:
    _insert_canonical_cve("CVE-2026-00010")

    with session_scope(test=True) as session:
        session.add_all(
            [
                KevRaw(cve_id="CVE-2026-00010", fetched_at=_NOW, date_added_src=date(2026, 8, 3)),
                # not in canonical.cve — must be skipped, not raise IntegrityError
                KevRaw(cve_id="CVE-2019-99999", fetched_at=_NOW, date_added_src=date(2026, 8, 3)),
            ]
        )

    clean_kev.main(test=True)  # would raise on FK violation if unfiltered

    with session_scope(test=True) as session:
        kev_cve_ids = set(session.execute(select(Kev.cve_id)).scalars().all())
    assert kev_cve_ids == {"CVE-2026-00010"}


def test_clean_kev_first_seen_in_catalog_is_earliest_snapshot() -> None:
    _insert_canonical_cve("CVE-2026-00011")
    earlier = datetime(2026, 8, 1, tzinfo=timezone.utc)
    later = datetime(2026, 8, 5, tzinfo=timezone.utc)

    with session_scope(test=True) as session:
        session.add_all(
            [
                KevRaw(cve_id="CVE-2026-00011", fetched_at=earlier, date_added_src=date(2026, 8, 1)),
                KevRaw(cve_id="CVE-2026-00011", fetched_at=later, date_added_src=date(2026, 8, 1)),
            ]
        )

    clean_kev.main(test=True)

    with session_scope(test=True) as session:
        row = session.execute(select(Kev).where(Kev.cve_id == "CVE-2026-00011")).scalar_one()
        assert row.first_seen_in_catalog_at == earlier


# --- clean_epss ------------------------------------------------------------


def test_clean_epss_only_inserts_rows_for_known_cves() -> None:
    _insert_canonical_cve("CVE-2026-00020")

    with session_scope(test=True) as session:
        session.add_all(
            [
                EpssScoresRaw(
                    cve_id="CVE-2026-00020", snapshot_date=date(2026, 8, 1),
                    epss_score=0.5, percentile=0.9,
                ),
                EpssScoresRaw(
                    cve_id="CVE-1999-88888", snapshot_date=date(2026, 8, 1),
                    epss_score=0.1, percentile=0.2,
                ),
            ]
        )

    clean_epss.main(test=True)

    with session_scope(test=True) as session:
        timeline_cve_ids = set(session.execute(select(EpssTimeline.cve_id)).scalars().all())
    assert timeline_cve_ids == {"CVE-2026-00020"}


# --- clean_exploitdb -------------------------------------------------------


def test_clean_exploitdb_maps_only_known_cve_but_stores_every_exploit() -> None:
    _insert_canonical_cve("CVE-2026-00030")

    with session_scope(test=True) as session:
        session.add_all(
            [
                ExploitdbRaw(
                    exploit_id=1, fetched_at=_NOW, description="matches a known CVE",
                    codes_raw="CVE-2026-00030;OSVDB-1",
                ),
                ExploitdbRaw(
                    exploit_id=2, fetched_at=_NOW, description="matches no known CVE",
                    codes_raw="CVE-2010-00099",
                ),
                ExploitdbRaw(
                    exploit_id=3, fetched_at=_NOW, description="no CVE code at all",
                    codes_raw="OSVDB-2",
                ),
            ]
        )

    clean_exploitdb.main(test=True)

    with session_scope(test=True) as session:
        exploit_ids = set(session.execute(select(Exploitdb.exploit_id)).scalars().all())
        mapped = session.execute(select(ExploitdbCveMap)).scalars().all()

    # every exploit is stored regardless of CVE match (exploitdb has no FK to cve)
    assert exploit_ids == {1, 2, 3}
    # only the exploit referencing a CVE already in canonical.cve gets mapped
    assert len(mapped) == 1
    assert mapped[0].exploit_id == 1
    assert mapped[0].cve_id == "CVE-2026-00030"
    assert mapped[0].match_method == "source_code_field"
