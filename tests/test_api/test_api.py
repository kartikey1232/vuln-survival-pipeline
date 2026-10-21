"""
API tests against the real test database (vuln_survival_test) and the real
frozen artifacts in models/. The app's engine dependency is pointed at the
test database; nothing is mocked.
"""

from __future__ import annotations

import pickle
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from api import main, scoring
from api.artifacts import get_artifacts
from database.engine import get_engine
from scripts.evaluate.data_splits import DATASET_VERSION

MODELS = Path(__file__).resolve().parents[2] / "models"
NOW = datetime(2026, 9, 20, tzinfo=timezone.utc)
KEV_CVE = "CVE-2025-10001"  # listed 20 days after publication: landmarks 7 and 14 only


def _landmark_row(cve_id, published, landmark, rng, **overrides):
    epss = float(rng.uniform(0.01, 0.95))
    row = {
        "cve_id": cve_id, "checkpoint_day": landmark, "as_of_date": published + timedelta(days=landmark),
        "epss_pct_now": epss, "epss_pct_7d_ago": epss * 0.9, "epss_pct_7d_ago_missing": False,
        "epss_pct_delta_7d": epss * 0.1, "epss_pct_first": epss * 0.8, "epss_pct_max_to_date": epss,
        "days_to_first_epss": 1, "epss_model_version_at_asof": "v2025.03.14",
        "cvss_base_score": float(rng.choice([5.3, 7.5, 9.8])), "attack_vector": "NETWORK",
        "attack_complexity": "LOW", "privileges_required": "NONE", "user_interaction": "NONE",
        "confidentiality_impact": "HIGH", "integrity_impact": "HIGH", "availability_impact": "HIGH",
        "cvss_version": "3.1", "cvss_cna_missing": False,
        "cwe_kev_rate_expanding": float(rng.uniform(0, 0.02)), "cna_kev_rate_expanding": float(rng.uniform(0, 0.01)),
        "exploit_published_by_asof": bool(rng.random() < 0.2), "days_to_first_exploit": None,
        "epss_score_at_asof_raw": epss / 10, "event_time": 100, "censor_flag": True, "composite_event": False,
        "dataset_version": DATASET_VERSION, "exported_at": NOW,
    }
    row.update(overrides)
    return row


@pytest.fixture()
def client():
    rng = np.random.default_rng(0)
    engine = get_engine(test=True)
    cves, rows = [], []
    for i in range(40):
        cve_id = f"CVE-2025-{20000 + i}"
        published = date(2025, 3, 1) + timedelta(days=i)
        cves.append({"cve_id": cve_id, "published_date": published})
        missing = i % 3 == 0
        for lm in (7, 14, 30):
            rows.append(_landmark_row(cve_id, published, lm, rng, landmark_day=None,
                                      cvss_cna_missing=missing,
                                      cvss_base_score=None if missing else float(rng.choice([5.3, 7.5, 9.8])),
                                      cvss_version=None if missing else ("3.0" if i % 5 == 0 else "3.1")))
    kev_published = date(2025, 6, 1)
    cves.append({"cve_id": KEV_CVE, "published_date": kev_published})
    for lm in (7, 14):
        rows.append(_landmark_row(KEV_CVE, kev_published, lm, rng, event_time=20 - lm, composite_event=True,
                                  censor_flag=False))
    train_published = date(2024, 3, 1)  # train-period row: in /cve, not in the watchlist pool
    cves.append({"cve_id": "CVE-2024-30000", "published_date": train_published})
    rows.append(_landmark_row("CVE-2024-30000", train_published, 7, rng))

    with engine.begin() as conn:
        conn.execute(text("INSERT INTO canonical.cve (cve_id, published_date, last_modified_date, description, "
                          "vuln_status, source_last_fetched_at) VALUES (:cve_id, :published_date, :published_date, "
                          "'test', 'Analyzed', :now)"), [{**c, "now": NOW} for c in cves])
        cols = [k for k in rows[0] if k != "landmark_day"]
        conn.execute(text(f"INSERT INTO training.training_dataset ({', '.join(cols)}) "
                          f"VALUES ({', '.join(':' + c for c in cols)})"),
                     [{c: r[c] for c in cols} for r in rows])
        conn.execute(text("INSERT INTO canonical.kev (cve_id, date_added, vendor_project, first_seen_in_catalog_at) "
                          "VALUES (:c, :d, 'Acme', :now)"), {"c": KEV_CVE, "d": kev_published + timedelta(days=20), "now": NOW})
        conn.execute(text("INSERT INTO staging.nvd_cve_raw (cve_id, fetched_at, last_modified_src, payload) "
                          "VALUES (:c, :now, :now, CAST(:p AS jsonb))"),
                     {"c": KEV_CVE, "now": NOW, "p": '{"id": "%s", "sourceIdentifier": "cna@acme"}' % KEV_CVE})
        conn.execute(text("INSERT INTO canonical.cvss_metric (cve_id, cvss_version, vector_string, base_score, source) "
                          "VALUES (:c, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'cna@acme')"),
                     {"c": KEV_CVE})
        conn.execute(text("INSERT INTO canonical.epss_timeline (cve_id, snapshot_date, epss_score, percentile, "
                          "is_observed, fill_method) VALUES (:c, :d, :s, :p, true, 'observed')"),
                     [{"c": KEV_CVE, "d": kev_published + timedelta(days=k), "s": 0.01 * (k + 1), "p": 0.05 * (k + 1)}
                      for k in range(10)])

    main._pool_cache.clear()
    main.app.dependency_overrides[main.get_db] = lambda: engine
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()
    main._pool_cache.clear()


def test_model_reports_frozen_metadata_and_ranking_role(client):
    body = client.get("/model").json()
    with open(MODELS / "cox_final_metadata.json") as f:
        import json
        recorded = json.load(f)
    assert body["ranking_model"] == "cox" and body["explanation_layer"] == "fuzzy"
    assert body["cox"]["test_metrics"] == recorded["test_metrics"]
    assert body["fuzzy"]["monotonicity_check"]["worst_step"] >= 0
    assert any("encoding" in issue for issue in body["known_issues"])


def test_cve_not_found_and_malformed(client):
    assert client.get("/cve/CVE-1999-0001").status_code == 404
    assert client.get("/cve/CVE-25-1").status_code == 422


def test_cve_scores_each_landmark_and_explains_missing_ones(client):
    body = client.get(f"/cve/{KEV_CVE}").json()
    art = get_artifacts()
    assert [lm["landmark_day"] for lm in body["landmarks"]] == [7, 14]
    assert body["landmarks_not_scored"] == [
        {"landmark_day": 30, "as_of_date": "2025-07-01", "reason": "already KEV-listed on or before this landmark"}]
    assert body["kev"]["date_added"] == "2025-06-21"
    assert [p["snapshot_date"] for p in body["epss_history"]] == sorted(p["snapshot_date"] for p in body["epss_history"])
    assert len(body["epss_history"]) == 10 and body["cvss_metrics"][0]["base_score"] == 9.8
    assert body["cna_source_identifier"] == "cna@acme"
    assert client.get("/cve/CVE-2025-20000").json()["cna_source_identifier"] is None

    for lm in body["landmarks"]:
        assert lm["split"] == "test"
        assert lm["cox_risk_pct"] == pytest.approx(
            art.reference.percentile([lm["cox_partial_hazard"]], [lm["landmark_day"]])[0])
        surv = [p["survival_probability"] for p in lm["survival_curve"]]
        assert all(0 <= s <= 1 for s in surv) and all(b <= a + 1e-12 for a, b in zip(surv, surv[1:]))
        fuzzy = lm["fuzzy"]
        assert 0 <= fuzzy["priority"] <= 100 and fuzzy["rules_fired"]
        strengths = [r["strength"] for r in fuzzy["rules_fired"]]
        assert strengths == sorted(strengths, reverse=True) and all(0 < s <= 1 for s in strengths)
    assert client.get("/cve/CVE-2024-30000").json()["landmarks"][0]["split"] == "train"


def test_watchlist_ranks_by_cox_and_flags_epss_blind_spots(client):
    body = client.get("/watchlist?budget=0.25&limit=1000").json()
    pool = main._scored_pool(get_engine(test=True), get_artifacts())
    assert body["pool_rows"] == len(pool) == 40 * 3 + 2  # test-period rows only
    n_top = int(np.ceil(len(pool) * 0.25))
    assert body["selected_rows"] == len(body["items"]) == n_top

    expected = np.argsort(-pool["cox_partial_hazard"].to_numpy())[:n_top]
    assert [(i["cve_id"], i["landmark_day"]) for i in body["items"]] == list(
        zip(pool["cve_id"].iloc[expected], pool["landmark_day"].iloc[expected]))
    hazards = [i["cox_partial_hazard"] for i in body["items"]]
    assert hazards == sorted(hazards, reverse=True)

    epss_top = set(np.argsort(-pool["epss_pct_now"].to_numpy())[:n_top])
    assert [i["epss_ranks_low"] for i in body["items"]] == [idx not in epss_top for idx in expected]
    assert body["selected_epss_ranks_low"] == sum(i["epss_ranks_low"] for i in body["items"])
    assert all(i["fuzzy"]["rules_fired"] for i in body["items"])


def test_watchlist_pagination_and_landmark_filter(client):
    full = client.get("/watchlist?budget=0.5&limit=1000").json()["items"]
    page = client.get("/watchlist?budget=0.5&limit=5&offset=5").json()["items"]
    assert [i["rank"] for i in page] == [6, 7, 8, 9, 10]
    assert [i["cve_id"] for i in page] == [i["cve_id"] for i in full[5:10]]
    only_30 = client.get("/watchlist?budget=1.0&landmark_day=30&limit=1000").json()
    assert only_30["pool_rows"] == 40 and {i["landmark_day"] for i in only_30["items"]} == {30}


@pytest.mark.parametrize("query", ["budget=0", "budget=1.5", "landmark_day=5", "limit=0"])
def test_watchlist_rejects_bad_parameters(client, query):
    assert client.get(f"/watchlist?{query}").status_code == 422


def test_single_row_scoring_equals_batch_scoring(client):
    """encode_for_model keeps a lone row's category (one_hot's drop_first
    would drop it)."""
    pool = main._scored_pool(get_engine(test=True), get_artifacts()).reset_index(drop=True)
    art = get_artifacts()
    alone = np.array([scoring.cox_scores(pool.iloc[[i]], art)[0] for i in range(len(pool))])
    np.testing.assert_allclose(alone, pool["cox_partial_hazard"].to_numpy(), rtol=1e-12)
    assert pool["cvss_version"].nunique() > 1  # the batch mixes categories


def test_requests_never_refit_the_model(client):
    with open(MODELS / "cox_final.pkl", "rb") as f:
        frozen = pickle.load(f)["model"].params_
    for path in ("/model", f"/cve/{KEV_CVE}", "/watchlist?budget=0.5"):
        assert client.get(path).status_code == 200
    assert get_artifacts().cox.params_.equals(frozen)


def test_backtest_serves_the_corrected_record(client):
    import json
    body = client.get("/backtest").json()
    with open(MODELS / "cox_final_metadata.json") as f:
        corrected = json.load(f)["test_metrics_corrected_encoding"]
    assert body["models"]["Cox"]["cindex"]["point"] == pytest.approx(corrected["test_cindex"])
    curve = body["recall_curve"]
    i = curve["budgets"].index(0.1)
    assert curve["recall"]["Cox"][i] == pytest.approx(corrected["test_recall_10pct"])
    assert all(np.all(np.diff(r) >= 0) for r in curve["recall"].values())  # recall never falls as budget grows
    assert body["paired_vs_epss"]["XGBoost-AFT"]["cindex"]["excludes_zero"] is False
