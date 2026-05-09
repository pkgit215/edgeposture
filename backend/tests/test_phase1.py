"""Phase 1 tests — audit lifecycle, scoring, persistence.

Mongo is replaced with mongomock; OpenAI pipeline is replaced with the same
deterministic fake used by Phase 0.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import mongomock
import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["RULEIQ_TESTING"] = "1"

from services import ai_pipeline  # noqa: E402
from services import audit as audit_mod  # noqa: E402
from services import db as db_mod  # noqa: E402
from services import scoring  # noqa: E402
from services import seed as seed_mod  # noqa: E402
import main  # noqa: E402

FIXTURE_PATH = BACKEND_DIR / "fixtures" / "waf_rules.json"


def _load_fixtures() -> List[Dict[str, Any]]:
    with FIXTURE_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _fake_explanation(rule: Dict[str, Any]) -> Dict[str, Any]:
    if rule.get("fms_managed") and (rule.get("hit_count") or 0) == 0:
        return {"explanation": "fms zero", "working": False, "concerns": "fms"}
    if (rule.get("hit_count") or 0) == 0:
        return {"explanation": "dead", "working": False, "concerns": "zero"}
    if rule.get("hit_count") == 1:
        return {"explanation": "low", "working": False, "concerns": "bypass"}
    return {"explanation": "ok", "working": True, "concerns": None}


def _fake_findings(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    by_name = {r["rule_name"]: r for r in rules}

    dead_customer = [
        r["rule_name"]
        for r in rules
        if (r.get("hit_count") or 0) == 0 and not r.get("fms_managed")
    ]
    if dead_customer:
        findings.append(
            {
                "type": "dead_rule",
                "severity": "medium",
                "affected_rules": dead_customer,
                "title": "Dead customer-owned rules detected",
                "description": "zero hits 30d",
                "recommendation": "remove",
                "confidence": 0.9,
            }
        )

    bypass = [
        r["rule_name"]
        for r in rules
        if r.get("hit_count") == 1
        and "Sqli" in json.dumps(r.get("statement_json", {}))
    ]
    if bypass:
        findings.append(
            {
                "type": "bypass_candidate",
                "severity": "high",
                "affected_rules": bypass,
                "title": "Possible SQLi bypass",
                "description": "low",
                "recommendation": "tighten",
                "confidence": 0.7,
            }
        )

    if "AllowOfficeIPRange" in by_name and "BlockOfficeIPRangeOnAdmin" in by_name:
        findings.append(
            {
                "type": "conflict",
                "severity": "medium",
                "affected_rules": [
                    "AllowOfficeIPRange",
                    "BlockOfficeIPRangeOnAdmin",
                ],
                "title": "overlap",
                "description": "two rules",
                "recommendation": "consolidate",
                "confidence": 0.8,
            }
        )

    if "BlockMaliciousIPsDuplicate" in by_name:
        findings.append(
            {
                "type": "quick_win",
                "severity": "low",
                "affected_rules": ["BlockMaliciousIPsDuplicate"],
                "title": "duplicate",
                "description": "subset",
                "recommendation": "remove",
                "confidence": 0.95,
            }
        )

    for r in rules:
        if r.get("fms_managed") and (
            (r.get("hit_count") or 0) == 0 or r.get("override_action")
        ):
            findings.append(
                {
                    "type": "fms_review",
                    "severity": "low",
                    "affected_rules": [r["rule_name"]],
                    "title": f"Review FMS-managed rule {r['rule_name']}",
                    "description": "fms",
                    "recommendation": "escalate",
                    "confidence": 0.6,
                }
            )

    return findings


def _fake_run_pipeline(rules):
    enriched = [{**r, "ai_explanation": _fake_explanation(r)} for r in rules]
    return {"rules": enriched, "findings": _fake_findings(enriched)}


@pytest.fixture(autouse=True)
def _patch_pipeline_and_db(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(ai_pipeline, "explain_rule", _fake_explanation)
    monkeypatch.setattr(
        ai_pipeline, "generate_findings", lambda rs: _fake_findings(rs)
    )
    monkeypatch.setattr(ai_pipeline, "run_pipeline", _fake_run_pipeline)
    monkeypatch.setattr(main, "run_pipeline", _fake_run_pipeline)

    mock_client = mongomock.MongoClient()
    mock_db = mock_client["ruleiq_test"]
    db_mod.set_test_db(mock_db)
    yield mock_db
    db_mod.clear_test_db()


@pytest.fixture()
def client() -> TestClient:
    return TestClient(main.app)


# ---------- Endpoint shape ----------------------------------------------------


def test_post_audits_returns_202_pending(client: TestClient) -> None:
    resp = client.post(
        "/api/audits",
        json={
            "account_id": "111122223333",
            "role_arn": None,
            "region": "us-east-1",
            "log_window_days": 30,
        },
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "pending"
    assert body["audit_run_id"]


def test_audit_progresses_to_complete(client: TestClient, _patch_pipeline_and_db) -> None:
    db = _patch_pipeline_and_db
    audit_id = audit_mod.create_audit_run(
        db=db,
        account_id="111122223333",
        role_arn=None,
        region="us-east-1",
        log_window_days=30,
    )
    audit_mod.run_audit_pipeline(audit_id, db)

    run = db["audit_runs"].find_one({"_id": audit_id})
    assert run["status"] == "complete"
    assert run["rule_count"] > 0
    assert run["estimated_waste_usd"] is not None
    assert db["rules"].count_documents({"audit_run_id": audit_id}) == run["rule_count"]
    assert db["findings"].count_documents({"audit_run_id": audit_id}) > 0


def test_audits_list_newest_first(client: TestClient, _patch_pipeline_and_db) -> None:
    db = _patch_pipeline_and_db
    a1 = audit_mod.create_audit_run(db, "111122223333", None, "us-east-1", 30)
    a2 = audit_mod.create_audit_run(db, "111122223333", None, "us-east-1", 30)
    a3 = audit_mod.create_audit_run(db, "111122223333", None, "us-east-1", 30)
    resp = client.get("/api/audits")
    assert resp.status_code == 200
    ids = [r["id"] for r in resp.json()]
    assert ids[:3] == [a3, a2, a1]


def test_findings_sorted_by_severity_score(client: TestClient, _patch_pipeline_and_db) -> None:
    db = _patch_pipeline_and_db
    audit_id = audit_mod.create_audit_run(db, "111122223333", None, "us-east-1", 30)
    audit_mod.run_audit_pipeline(audit_id, db)
    resp = client.get(f"/api/audits/{audit_id}/findings")
    assert resp.status_code == 200
    findings = resp.json()
    assert findings, "expected at least one finding"
    scores = [f["severity_score"] for f in findings]
    assert scores == sorted(scores, reverse=True)


# ---------- Scoring -----------------------------------------------------------


def test_severity_score_in_range_0_100() -> None:
    cases = [
        ("high", 1.0, ["a"], 10),
        ("medium", 0.5, ["a", "b"], 5),
        ("low", 0.1, [], 1),
        ("high", 0.0, ["a"], 1),
        ("low", 1.0, ["a", "b", "c"], 1),
    ]
    for sev, conf, ar, total in cases:
        score = scoring.severity_score(sev, conf, ar, total)
        assert 0 <= score <= 100, (sev, conf, ar, total, score)


def test_estimated_waste_usd_excludes_fms_dead_rules() -> None:
    rules = [
        {"rule_name": "deadCustomer1", "hit_count": 0, "fms_managed": False},
        {"rule_name": "deadCustomer2", "hit_count": 0, "fms_managed": False},
        {"rule_name": "deadFms", "hit_count": 0, "fms_managed": True},
        {"rule_name": "alive", "hit_count": 100, "fms_managed": False},
    ]
    waste = scoring.estimated_waste_usd(rules)
    assert waste == 2.00  # only the two non-FMS dead rules count


# ---------- Seed --------------------------------------------------------------


def test_seed_is_idempotent(_patch_pipeline_and_db) -> None:
    db = _patch_pipeline_and_db
    first = seed_mod.ensure_demo_seed(db)
    second = seed_mod.ensure_demo_seed(db)
    assert first == second
    assert (
        db["audit_runs"].count_documents(
            {"seed": True, "account_id": seed_mod.DEMO_ACCOUNT_ID}
        )
        == 1
    )


def test_seed_persists_rules_and_findings(_patch_pipeline_and_db) -> None:
    db = _patch_pipeline_and_db
    audit_id = seed_mod.ensure_demo_seed(db)
    assert audit_id
    run = db["audit_runs"].find_one({"_id": audit_id})
    assert run["status"] == "complete"
    assert run["rule_count"] == len(_load_fixtures())
    fms_names = {r["rule_name"] for r in _load_fixtures() if r.get("fms_managed")}
    for f in db["findings"].find({"audit_run_id": audit_id}):
        if f["type"] in ("dead_rule", "quick_win"):
            assert not fms_names.intersection(f.get("affected_rules", []))


# ---------- Health -------------------------------------------------------------


def test_health_includes_mongo_field(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "phase" in body  # phase number bumps every release; just confirm presence
    assert body["mongo"] in ("ok", "unreachable")
