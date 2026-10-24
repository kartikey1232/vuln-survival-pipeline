# Database backups

Full-database dumps live in `data/backups/` and are never committed
(`.gitignore`). This file records each dump and how it was verified.
**The sha256 is the authoritative identifier** of a dump. Sizes are given
in bytes because "MB" has been quoted inconsistently: 463,612,521 bytes is
463.6 MB (decimal) and 442.1 MiB (binary). A figure of 449 MB was quoted
for this dump elsewhere and matches neither unit. The checksum is what
identifies the file, not the size.

## `vuln_survival_pre_refresh_20261022.dump`

Taken before the October 2026 refresh (`scripts/download/refresh.py`)
modified any table.

| | |
|---|---|
| Path | `data/backups/vuln_survival_pre_refresh_20261022.dump` |
| sha256 | `1d83088cb05eb1e35a29701deecac0eef49cc568565de36a0082cc02775cf753` |
| Size | 463,612,521 bytes |
| Archive created | 2026-10-22 17:42:06 IST (`pg_restore --list` header) |
| Format | `pg_dump -Fc` (custom, gzip), PostgreSQL 16.14, database `vuln_survival` |
| Contents | 166 TOC entries, 23 tables with data |

### Verification

**The first verification (2026-10-22) was not recorded.** It was a
row-count comparison against the live database, run in an earlier session
just after the dump was taken. Its result was never written down and is
not recoverable. The verification below was re-run on **2026-10-24** and
is the one on record.

1. **Archive integrity.** `pg_restore -a -f -` streamed every table's data
   out of the archive, so every compressed data block was read and
   decompressed. It finished without error.
2. **Row counts, dump vs live** (per table: lines between each `COPY` header
   and its `\.` terminator, against `SELECT count(*)` on the live database).
   **Every table the refresh does not write to matches exactly.** Every
   table that differs is one the refresh appends to, and in each the live
   count is the higher one.

   | Table | Dump | Live (2026-10-24) | |
   |---|---|---|---|
   | training.training_dataset | 895,400 | 895,400 | same |
   | training.survival_labels | 462,049 | 462,049 | same |
   | training.prediction | 0 | 0 | same |
   | features.temporal_features | 462,049 | 462,049 | same |
   | features.static_features | 155,808 | 155,808 | same |
   | features.derived_features | 0 | 0 | same |
   | canonical.cwe | 969 | 969 | same |
   | canonical.cwe_relationship | 1,444 | 1,444 | same |
   | staging.cwe_raw | 969 | 969 | same |
   | public.alembic_version | 1 | 1 | same |
   | canonical.cve | 222,452 | 239,679 | refresh (NVD) |
   | canonical.cvss_metric | 352,155 | 373,658 | refresh (NVD) |
   | canonical.cve_cwe_map | 257,247 | 275,446 | refresh (NVD) |
   | canonical.cpe_product | 1,240,730 | 1,279,885 | refresh (NVD) |
   | staging.nvd_cve_raw | 224,161 | 297,152 | refresh (NVD) |
   | canonical.epss_timeline | 17,528,877 | 18,701,346 | refresh (EPSS) |
   | staging.epss_scores_raw | 17,528,877 | 18,701,346 | refresh (EPSS) |
   | canonical.kev | 787 | 873 | refresh (KEV) |
   | staging.kev_raw | 1,661 | 3,415 | refresh (KEV) |
   | canonical.exploitdb | 46,636 | 46,709 | refresh (ExploitDB) |
   | canonical.exploitdb_cve_map | 991 | 1,036 | refresh (ExploitDB) |
   | staging.exploitdb_raw | 47,108 | 94,289 | refresh (ExploitDB) |
   | staging.file_manifest | 1,905 | 2,089 | refresh (all sources) |

3. **`training.training_dataset` content, dump vs live.** Both COPY
   streams were sorted and hashed, which makes the comparison independent
   of row order. Dump (`pg_restore -a -n training -t training_dataset`) and
   live (`COPY training.training_dataset TO STDOUT`) give the **same
   sha256: `d13ece2ae3327b3244bdf27b3f282c587ca0d2176bfc18de89957a5f610e5ac2`**,
   over all 895,400 rows. The table the frozen models were fit on has not
   been written to since the backup. That includes the corrected-labels
   re-evaluation, which relabels in memory only (`docs/STATUS.md`).

An earlier check already used this dump as the reference for the EPSS
history-immutability check (`docs/STATUS.md`, the refresh's EPSS step):
15,229,696 `canonical.epss_timeline` rows dated on or before 2026-06-22
matched exactly.
