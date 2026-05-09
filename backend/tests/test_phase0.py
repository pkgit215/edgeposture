"""Phase 0 tests for RuleIQ.

OpenAI is fully mocked. Tests verify endpoint shape, finding-type coverage,
and FMS suppression rules.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

import sys

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from services import ai_pipeline, secrets  # noqa: E402
import main  # noqa: E402


FIXTURE_PATH = BACKEND_DIR / "fixtures" / "waf_rules.json"


def _load_fixtures() -> List[Dict[str, Any]]:
    with FIXTURE_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _fake_explanation(rule: Dict[str, Any]) -> Dict[str, Any]:
    working = (rule.get("hit_count") or 0) > 0 and not rule.get("fms_managed", False) is None
    if rule.get("fms_managed") and (rule.get("hit_count") or 0) == 0:
        return {
            "explanation": (
                f"FMS-managed rule {rule['rule_name']} has zero hits over 30 days; "
                "since it is controlled by the delegated admin account, the local "
                "team cannot tune it."
            ),
            "working": False,
            "concerns": "FMS-managed and silent — flag for central security review.",
        }
    if (rule.get("hit_count") or 0) == 0:
        return {
            "explanation": (
                f"Rule {rule['rule_name']} blocks legacy traffic patterns and has "
                "produced zero hits in the trailing 30 days."
            ),
            "working": False,
            "concerns": "Zero hits — likely dead and removable.",
        }
    if rule.get("hit_count") == 1:
        return {
            "explanation": (
                f"Rule {rule['rule_name']} targets SQL injection on the query string; "
                "hit volume is far below the typical baseline."
            ),
            "working": False,
            "concerns": "Hit count suspiciously low for a SQLi defense — possible bypass.",
        }
    return {
        "explanation": (
            f"Rule {rule['rule_name']} is firing as expected against current traffic."
        ),
        "working": True,
        "concerns": None,
    }


def _fake_findings(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deterministic Pass-2 fake honoring the FMS suppression contract."""
    findings: List[Dict[str, Any]] = []

    by_name = {r["rule_name"]: r for r in rules}

    # dead_rule — only customer-owned zero-hit rules
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
                "description": "These customer-owned rules have zero hits in the last 30 days.",
                "recommendation": "Validate intent and remove or migrate.",
                "confidence": 0.9,
            }
        )

    # bypass_candidate — SQLi-type rule with 1 hit
    bypass = [
        r["rule_name"]
        for r in rules
        if r.get("hit_count") == 1 and "Sqli" in json.dumps(r.get("statement_json", {}))
    ]
    if bypass:
        findings.append(
            {
                "type": "bypass_candidate",
                "severity": "high",
                "affected_rules": bypass,
                "title": "Possible SQLi bypass",
                "description": "SQLi rule has only 1 hit in 30 days; likely being evaded.",
                "recommendation": "Review false-negative samples and tighten match criteria.",
                "confidence": 0.7,
            }
        )

    # conflict — Allow + Block on the same office IP set
    if "AllowOfficeIPRange" in by_name and "BlockOfficeIPRangeOnAdmin" in by_name:
        findings.append(
            {
                "type": "conflict",
                "severity": "medium",
                "affected_rules": ["AllowOfficeIPRange", "BlockOfficeIPRangeOnAdmin"],
                "title": "Allow and Block overlap on office IP set",
                "description": "Two rules touch the same IP set with contradicting actions on /admin paths.",
                "recommendation": "Consolidate into a single intent-clear rule.",
                "confidence": 0.8,
            }
        )

    # quick_win — duplicate IP-set rule
    if "BlockMaliciousIPsDuplicate" in by_name and "BlockKnownMaliciousIPs" in by_name:
        findings.append(
            {
                "type": "quick_win",
                "severity": "low",
                "affected_rules": ["BlockMaliciousIPsDuplicate"],
                "title": "Redundant duplicate of BlockKnownMaliciousIPs",
                "description": "Same IP set, same action, lower priority — strict subset.",
                "recommendation": "Remove BlockMaliciousIPsDuplicate.",
                "confidence": 0.95,
            }
        )

    # fms_review — every FMS-managed rule with zero hits or override locked
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
                    "description": (
                        "This rule is controlled by a delegated admin account "
                        "(AWS Firewall Manager) and the local team cannot modify it."
                    ),
                    "recommendation": (
                        "Flag for review with the central security team owning the "
                        "delegated admin account."
                    ),
                    "confidence": 0.6,
                }
            )

    return findings


@pytest.fixture(autouse=True)
def _patch_openai(monkeypatch: pytest.MonkeyPatch):
    """Replace the two pipeline helpers with deterministic fakes.

    The pipeline is fully short-circuited so no real OpenAI client is ever
    constructed; therefore secrets.get_openai_key is intentionally NOT patched
    here, leaving test_secrets_env_var_precedence free to assert against it.
    """
    monkeypatch.setattr(ai_pipeline, "explain_rule", _fake_explanation)
    monkeypatch.setattr(
        ai_pipeline,
        "generate_findings",
        lambda enriched: _fake_findings(enriched),
    )

    # run_pipeline imports its dependencies by name from the same module —
    # rebind via the module reference so the patch is picked up.
    def fake_run(rules):
        enriched = [{**r, "ai_explanation": _fake_explanation(r)} for r in rules]
        return {"rules": enriched, "findings": _fake_findings(enriched)}

    monkeypatch.setattr(ai_pipeline, "run_pipeline", fake_run)
    monkeypatch.setattr(main, "run_pipeline", fake_run)


@pytest.fixture()
def client() -> TestClient:
    return TestClient(main.app)


def test_health_ok(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    # Phase 1 enriched the contract with `mongo` and bumped `phase` to "1".
    # Keep this test loose so it survives subsequent phase bumps too — it is a
    # smoke test, not a contract test.
    assert body["status"] == "ok"
    assert "phase" in body


def test_openapi_reachable(client: TestClient) -> None:
    resp = client.get("/api/openapi.json")
    assert resp.status_code == 200
    body = resp.json()
    assert "paths" in body
    assert "/api/health" in body["paths"]
    assert "/api/poc/analyze" in body["paths"]


def test_analyze_returns_valid_shape(client: TestClient) -> None:
    resp = client.post("/api/poc/analyze")
    assert resp.status_code == 200
    body = resp.json()
    assert "rules" in body and isinstance(body["rules"], list)
    assert "findings" in body and isinstance(body["findings"], list)
    assert len(body["rules"]) == len(_load_fixtures())
    for r in body["rules"]:
        assert "ai_explanation" in r
        ai = r["ai_explanation"]
        assert set(["explanation", "working", "concerns"]).issubset(ai.keys())
    for f in body["findings"]:
        for key in (
            "type",
            "severity",
            "affected_rules",
            "title",
            "description",
            "recommendation",
            "confidence",
        ):
            assert key in f, f"missing {key} in finding {f}"


def test_every_finding_type_present(client: TestClient) -> None:
    resp = client.post("/api/poc/analyze")
    body = resp.json()
    types = {f["type"] for f in body["findings"]}
    expected = {"dead_rule", "bypass_candidate", "conflict", "quick_win", "fms_review"}
    missing = expected - types
    assert not missing, f"missing finding types: {missing}"


def test_no_fms_rule_in_removal_findings(client: TestClient) -> None:
    fixtures = _load_fixtures()
    fms_names = {r["rule_name"] for r in fixtures if r.get("fms_managed")}

    resp = client.post("/api/poc/analyze")
    body = resp.json()

    for f in body["findings"]:
        if f["type"] in ("dead_rule", "quick_win"):
            overlap = fms_names.intersection(set(f.get("affected_rules", [])))
            assert not overlap, (
                f"FMS-managed rule(s) {overlap} appeared in removal-class finding "
                f"of type {f['type']}: {f}"
            )


def test_fms_review_exists_for_fms_zero_hit(client: TestClient) -> None:
    fixtures = _load_fixtures()
    fms_zero = [
        r["rule_name"]
        for r in fixtures
        if r.get("fms_managed") and (r.get("hit_count") or 0) == 0
    ]
    assert fms_zero, "fixture must contain at least one FMS-managed zero-hit rule"

    resp = client.post("/api/poc/analyze")
    body = resp.json()

    fms_review_findings = [f for f in body["findings"] if f["type"] == "fms_review"]
    assert fms_review_findings, "no fms_review finding produced"

    matched = False
    for f in fms_review_findings:
        if any(name in f.get("affected_rules", []) for name in fms_zero):
            matched = True
            break
    assert matched, (
        f"no fms_review finding mentioned an FMS zero-hit rule {fms_zero}"
    )


def test_secrets_env_var_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_mongo_uri / get_openai_key must prefer the env var over Secrets Manager."""
    secrets._reset_cache_for_tests()
    monkeypatch.setenv("OPENAI_API_KEY", "env-openai")
    monkeypatch.setenv("MONGODB_URI", "mongodb+srv://env/mongo")
    assert secrets.get_openai_key() == "env-openai"
    assert secrets.get_mongo_uri() == "mongodb+srv://env/mongo"
    secrets._reset_cache_for_tests()
