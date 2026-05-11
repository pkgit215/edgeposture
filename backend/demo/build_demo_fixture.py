"""Build the committed demo audit fixture used by `/api/demo/audit`.

Runs the audit pipeline in DEMO_MODE (bundled fixtures — they were
designed for exactly this case: realistic shellshock / sqli / fms /
dead-rule rules with hits) and dumps the result to JSON + PDF, scrubbing
any real-account substrings.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
ROOT = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["DEMO_MODE"] = "true"
os.environ["RULEIQ_TESTING"] = "1"
os.environ.setdefault("EXTERNAL_ID_SECRET", "a" * 64)

import mongomock

from services import audit as audit_mod
from services import db as db_mod
from services import pdf_report

DUMMY_ACCOUNT_ID = "123456789012"
DUMMY_ROLE_ARN = f"arn:aws:iam::{DUMMY_ACCOUNT_ID}:role/RuleIQAuditRole"
REAL_ACCOUNT_IDS = ("371126261144",)  # scrub list
OUT_JSON = BACKEND_DIR / "demo" / "demo_audit.json"
OUT_PDF = BACKEND_DIR / "demo" / "demo_audit.pdf"


def _no_ai(rules, suspicious_requests=None, web_acl_names=None):
    """Replace ai_pipeline.run_pipeline with a deterministic findings
    set so the fixture is offline-reproducible (no OpenAI call)."""
    enriched = [
        {**r, "ai_explanation": {
            "explanation": (
                f"{r['rule_name']}: " + (
                    "blocks shellshock attempts in the User-Agent header."
                    if "Shellshock" in r["rule_name"]
                    else "blocks `/wp-admin` paths."
                    if "AdminPath" in r["rule_name"]
                    else "legacy rule with no recent matches — review with owning team."
                    if "Legacy" in r["rule_name"] or "Old" in r["rule_name"]
                    else "blocks generic SQL-injection patterns."
                    if "SQL" in r["rule_name"] or "Sqli" in r["rule_name"]
                    else "AWS managed common rule set — broad XSS/SQLi/path-traversal coverage."
                )),
            "working": "Legacy" not in r["rule_name"] and "Old" not in r["rule_name"],
            "concerns": None}}
        for r in rules
    ]
    findings = []
    rule_names = {r["rule_name"] for r in rules}

    # Dead rules — Legacy/Old prefixes in fixture indicate zero-hit cruft.
    for n in sorted(n for n in rule_names if "Legacy" in n or "Old" in n):
        findings.append({
            "type": "dead_rule", "severity": "medium",
            "affected_rules": [n],
            "title": f"Dead rule: {n}",
            "description": f"Rule '{n}' matched zero requests in the last 30 days.",
            "recommendation": "Verify with the original author whether this protection is still required.",
            "confidence": 0.9,
        })

    # FMS — managed zero-hit rule surfaces as fms_review.
    managed = next((r["rule_name"] for r in rules
                    if r.get("fms_managed") and r.get("hit_count", 0) == 0), None)
    if managed:
        findings.append({
            "type": "fms_review", "severity": "low",
            "affected_rules": [managed],
            "title": f"FMS-managed rule: {managed}",
            "description": "Controlled by your central security admin via Firewall Manager.",
            "recommendation": "Escalate to the central security team or accept as out-of-scope.",
            "confidence": 0.85,
        })

    # Bypass — attack-shaped request reached origin (synthetic suspicious req).
    if suspicious_requests:
        acl_names = sorted({r.get("_web_acl_name") for r in suspicious_requests
                            if r.get("_web_acl_name")}) or (web_acl_names or [])
        findings.append({
            "type": "bypass_candidate", "severity": "high",
            "affected_rules": list(acl_names) or ["ruleiq-prod-acl"],
            "title": "Possible WAF bypass: SQL-injection reached origin",
            "description": ("HTTP request containing SQL-injection payload in the "
                            "query string was answered 200 OK by origin. "
                            "Example URI: /search?q=1%27%20OR%201%3D1--."),
            "recommendation": "Enable AWSManagedRulesSQLiRuleSet on the affected ACL.",
            "confidence": 0.95, "evidence": "log-sample",
        })

    # Quick-win duplicate — BlockMaliciousIPsDuplicate is clearly redundant.
    if {"BlockKnownMaliciousIPs", "BlockMaliciousIPsDuplicate"} <= rule_names:
        findings.append({
            "type": "quick_win", "severity": "low",
            "affected_rules": ["BlockKnownMaliciousIPs", "BlockMaliciousIPsDuplicate"],
            "title": "Duplicate rule: BlockMaliciousIPsDuplicate",
            "description": ("Rule 'BlockMaliciousIPsDuplicate' references the same "
                            "IP set as 'BlockKnownMaliciousIPs' with no additional scope."),
            "recommendation": "Delete BlockMaliciousIPsDuplicate after confirming hit counts.",
            "confidence": 0.9,
        })

    # Conflict — Allow rule overlaps Block rule on the same path.
    if {"AllowOfficeIPRange", "BlockOfficeIPRangeOnAdmin"} <= rule_names:
        findings.append({
            "type": "conflict", "severity": "medium",
            "affected_rules": ["AllowOfficeIPRange", "BlockOfficeIPRangeOnAdmin"],
            "title": "Contradicting rules on /admin",
            "description": ("Rule 'AllowOfficeIPRange' permits the office IP range "
                            "while 'BlockOfficeIPRangeOnAdmin' blocks the same range "
                            "on /admin. Rule priority will silently determine the outcome."),
            "recommendation": ("Confirm desired behaviour with the security owner and "
                               "consolidate into a single explicit rule with the correct "
                               "priority."),
            "confidence": 0.8,
        })

    return {"rules": enriched, "findings": findings}


def _serialize(doc, drop_id=True):
    out = {}
    for k, v in doc.items():
        if drop_id and k == "_id":
            continue
        if isinstance(v, _dt.datetime):
            v = v.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")
        out[k] = v
    if not drop_id and "_id" in doc:
        out["id"] = str(doc["_id"])
    return out


def _scrub(obj):
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(x) for x in obj]
    if isinstance(obj, str):
        s = obj
        for real in REAL_ACCOUNT_IDS:
            s = s.replace(real, DUMMY_ACCOUNT_ID)
        return s
    return obj


def main():
    db = mongomock.MongoClient()["ruleiq_demo_fixture"]
    db_mod.set_test_db(db)

    # Inject deterministic findings instead of calling OpenAI.
    audit_mod.ai_pipeline.run_pipeline = _no_ai

    # Wrap the fixture loader to attach a synthetic suspicious request so
    # the demo includes a `bypass_candidate` finding (otherwise the meta
    # ships with `suspicious_requests=[]`).
    _orig_loader = audit_mod._load_rules_from_fixtures

    def _loader_with_suspicious():
        rules, meta = _orig_loader()
        meta = {**meta, "suspicious_requests": [{
            "httpRequest": {
                "uri": "/search",
                "args": "q=1%27%20OR%201%3D1--",
                "headers": [{"name": "User-Agent",
                             "value": "sqlmap/1.5"}],
            },
            "action": "ALLOW",
            "_web_acl_name": "ruleiq-prod-acl",
        }]}
        return rules, meta

    audit_mod._load_rules_from_fixtures = _loader_with_suspicious

    audit_id = audit_mod.create_audit_run(
        db=db, account_id=DUMMY_ACCOUNT_ID, role_arn=None,
        region="us-east-1", log_window_days=30, external_id=None,
    )
    audit_mod.run_audit_pipeline(audit_id, db)

    run = db["audit_runs"].find_one({"_id": audit_id})
    assert run is not None, "audit run was not persisted"
    rules = list(db["rules"].find({"audit_run_id": audit_id}))
    findings = list(db["findings"].find({"audit_run_id": audit_id}).sort(
        "severity_score", -1))

    payload = {
        "audit": _scrub({**_serialize(run, drop_id=True),
                         "id": str(run["_id"])}),
        "rules": _scrub([_serialize(r) for r in rules]),
        "findings": _scrub([_serialize(f) for f in findings]),
    }

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(payload, indent=2))
    print(f"wrote {OUT_JSON} ({OUT_JSON.stat().st_size:,} bytes)")

    pdf_bytes = pdf_report.render_audit_pdf(run, rules, findings)
    OUT_PDF.write_bytes(pdf_bytes)
    print(f"wrote {OUT_PDF} ({OUT_PDF.stat().st_size:,} bytes)")

    blob = OUT_JSON.read_bytes() + OUT_PDF.read_bytes()
    for real in REAL_ACCOUNT_IDS:
        assert real.encode() not in blob, (
            f"real account id {real} leaked into demo fixture"
        )
    print("OK — no real account-id substring in fixture.")
    print(f"  audit: rules={len(rules)} findings={len(findings)} "
          f"web_acls={[w['name'] for w in (run.get('web_acls') or [])]}")
    print(f"  finding types: {sorted({f['type'] for f in findings})}")


if __name__ == "__main__":
    main()
