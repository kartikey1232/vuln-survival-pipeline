"""refresh.label_affecting_listings: a KEV completion record must never
overstate label impact. Train rows censor at TRAIN_TEST_CUTOFF, so a new
listing after it cannot change a stored train label."""

import pandas as pd

from scripts.download.refresh import label_affecting_listings


def _stored(cve_id, published, n_rows):
    return [{"cve_id": cve_id, "as_of_date": pd.Timestamp(published) + pd.Timedelta(days=7 * i),
             "published_date": published} for i in range(n_rows)]


def test_train_listing_after_train_cutoff_does_not_affect_labels():
    stored = pd.DataFrame(_stored("CVE-2022-0001", "2022-03-25", 3) + _stored("CVE-2025-0001", "2025-09-05", 3))
    new = pd.DataFrame({"cve_id": ["CVE-2022-0001", "CVE-2025-0001"], "date_added": ["2026-08-26", "2026-09-18"]})
    affecting, other = label_affecting_listings(new, stored)
    assert affecting["cve_id"].tolist() == ["CVE-2025-0001"]
    assert affecting["rows"].tolist() == [3]
    assert other["cve_id"].tolist() == ["CVE-2022-0001"]
    assert other["split"].tolist() == ["train"]


def test_test_listing_after_data_cutoff_does_not_affect_labels():
    stored = pd.DataFrame(_stored("CVE-2025-0002", "2025-10-01", 2))
    new = pd.DataFrame({"cve_id": ["CVE-2025-0002"], "date_added": ["2026-09-21"]})
    affecting, other = label_affecting_listings(new, stored)
    assert affecting.empty and other["cve_id"].tolist() == ["CVE-2025-0002"]


def test_train_listing_before_train_cutoff_affects_labels():
    stored = pd.DataFrame(_stored("CVE-2024-0001", "2024-06-01", 2))
    new = pd.DataFrame({"cve_id": ["CVE-2024-0001"], "date_added": ["2024-12-31"]})
    affecting, _ = label_affecting_listings(new, stored)
    assert affecting["cve_id"].tolist() == ["CVE-2024-0001"] and affecting["split"].tolist() == ["train"]


def test_listings_without_stored_rows_are_ignored():
    stored = pd.DataFrame(_stored("CVE-2025-0003", "2025-10-01", 1))
    new = pd.DataFrame({"cve_id": ["CVE-2026-9999"], "date_added": ["2026-09-01"]})
    affecting, other = label_affecting_listings(new, stored)
    assert affecting.empty and other.empty
