"""Real AWS WAFv2 + CloudWatch Logs + FMS reads for RuleIQ Phase 2.

All access is via STS-assumed temporary credentials sourced from a customer
role created by `cloudformation/customer-role.yaml`. The functions here are
deliberately thin wrappers — orchestration lives in services/audit.py.

Sampling policy for get_rule_stats:
    Most-recent 50,000 events per rule, sorted desc by timestamp, 30-day
    window. If the rule has more than 50k hits in 30d, sample_uris and
    count_mode_hits reflect only the most recent slice — the hit_count is
    also capped at 50k. This is a known sampling limitation; bump
    max_events or move to Athena over S3 for high-traffic accounts.
"""
from __future__ import annotations

import base64
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

logger = logging.getLogger(__name__)

DEFAULT_REGION = "us-east-1"
LOG_EVENT_PAGE_SIZE = 10_000
DEFAULT_MAX_EVENTS = 50_000
DEFAULT_WINDOW_DAYS = 30


# ---------- JSON normalization (boto3 → JSON-safe) ---------------------------


def _normalize_for_json(obj: Any) -> Any:
    """Recursively convert boto3 response values into JSON-safe primitives.

    boto3's WAFv2 model returns several fields as Python `bytes` (notably
    `ByteMatchStatement.SearchString` and any `IPSetForwardedIPConfig.Data`).
    Those values can't be json-dumped for Mongo persistence or for the AI
    prompt payload. This helper walks dicts/lists and:

      - bytes  → utf-8 decoded string when valid; else base64-encoded ascii
      - datetime → isoformat string
      - everything else passed through

    Apply at the boundary where boto3 dicts are first captured, so the rest
    of the codebase only ever sees JSON-safe data.
    """
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return base64.b64encode(obj).decode("ascii")
    if isinstance(obj, dict):
        return {k: _normalize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize_for_json(v) for v in obj]
    if isinstance(obj, tuple):
        return [_normalize_for_json(v) for v in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


# ---------- STS ---------------------------------------------------------------


def assume_role(role_arn: str, external_id: Optional[str] = None) -> boto3.Session:
    """Assume the customer role and return a boto3.Session built from the temps."""
    sts = boto3.client("sts")
    kwargs: Dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": f"ruleiq-audit-{int(time.time())}",
        "DurationSeconds": 3600,
    }
    if external_id:
        kwargs["ExternalId"] = external_id
    resp = sts.assume_role(**kwargs)
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


# ---------- WAFv2 -------------------------------------------------------------


def _wafv2(session: boto3.Session, region: str, scope: str):
    """WAFv2 client. CLOUDFRONT scope must be hit in us-east-1."""
    if scope == "CLOUDFRONT":
        return session.client("wafv2", region_name="us-east-1")
    return session.client("wafv2", region_name=region)


def list_web_acls(session: boto3.Session, region: str) -> List[Dict[str, Any]]:
    """List Web ACLs in both REGIONAL (`region`) and CLOUDFRONT scopes."""
    out: List[Dict[str, Any]] = []
    for scope in ("REGIONAL", "CLOUDFRONT"):
        client = _wafv2(session, region, scope)
        next_marker: Optional[str] = None
        while True:
            kwargs: Dict[str, Any] = {"Scope": scope, "Limit": 100}
            if next_marker:
                kwargs["NextMarker"] = next_marker
            try:
                resp = client.list_web_acls(**kwargs)
            except ClientError as exc:
                logger.warning("list_web_acls %s failed: %s", scope, exc)
                break
            for acl in resp.get("WebACLs", []):
                out.append({**_normalize_for_json(acl), "Scope": scope})
            next_marker = resp.get("NextMarker")
            if not next_marker:
                break
    return out


def get_web_acl_rules(
    session: boto3.Session, web_acl: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Fetch a Web ACL and project its rules into RuleIQ rule dicts.

    boto3 returns ByteMatchStatement.SearchString (and a few IPSet/Forwarded
    fields) as raw bytes. We normalize the entire Statement subtree to JSON
    primitives here so downstream code never sees bytes.
    """
    scope = web_acl.get("Scope", "REGIONAL")
    region = "us-east-1" if scope == "CLOUDFRONT" else web_acl.get("Region", DEFAULT_REGION)
    client = session.client("wafv2", region_name=region)
    resp = client.get_web_acl(
        Name=web_acl["Name"], Scope=scope, Id=web_acl["Id"]
    )
    acl = resp["WebACL"]
    rules: List[Dict[str, Any]] = []
    for r in acl.get("Rules", []):
        action = _derive_action(r)
        override_action = None
        ovr = r.get("OverrideAction") or {}
        if "None" in ovr:
            override_action = "None"
        elif "Count" in ovr:
            override_action = "Count"
        rules.append(
            {
                "rule_name": r["Name"],
                "priority": r.get("Priority", 0),
                "action": action,
                "statement_json": _normalize_for_json(r.get("Statement", {})),
                "override_action": override_action,
                "fms_managed": bool(r.get("ManagedByFirewallManager", False)),
            }
        )
    return rules


def _derive_action(rule: Dict[str, Any]) -> str:
    action = rule.get("Action") or {}
    for key in ("Allow", "Block", "Count", "Captcha", "Challenge"):
        if key in action:
            return key.upper()
    # Managed/override-only rule
    ovr = rule.get("OverrideAction") or {}
    if "Count" in ovr:
        return "COUNT"
    return "ALLOW"


# ---------- FMS (best-effort) -------------------------------------------------


def enrich_fms(
    session: boto3.Session, account_id: str, region: str
) -> Dict[str, Any]:
    """Optional FMS context. Failures degrade silently to {available: false}."""
    try:
        client = session.client("fms", region_name="us-east-1")
        policies: List[Dict[str, Any]] = []
        next_token: Optional[str] = None
        while True:
            kwargs: Dict[str, Any] = {"MaxResults": 50}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = client.list_policies(**kwargs)
            for p in resp.get("PolicyList", []):
                policies.append(
                    _normalize_for_json(
                        {
                            "PolicyId": p.get("PolicyId"),
                            "PolicyName": p.get("PolicyName"),
                            "ResourceType": p.get("ResourceType"),
                            "SecurityServiceType": p.get("SecurityServiceType"),
                        }
                    )
                )
            next_token = resp.get("NextToken")
            if not next_token:
                break
        return {"available": True, "policies": policies}
    except (ClientError, EndpointConnectionError) as exc:
        code = getattr(getattr(exc, "response", {}), "get", lambda *_: {})(
            "Error", {}
        ).get("Code") if hasattr(exc, "response") else None
        logger.info("FMS unavailable (%s): %s", code, exc)
        return {"available": False}


# ---------- WAF logging discovery --------------------------------------------


def discover_logging(
    session: boto3.Session, web_acl_arn: str
) -> Optional[str]:
    """Return the first CloudWatch log group ARN configured on the Web ACL.

    Returns None if logging is disabled or the destination is S3/Firehose.
    """
    region = _region_from_arn(web_acl_arn) or DEFAULT_REGION
    client = session.client("wafv2", region_name=region)
    try:
        resp = client.get_logging_configuration(ResourceArn=web_acl_arn)
    except client.exceptions.WAFNonexistentItemException:
        return None
    except ClientError as exc:
        logger.info("get_logging_configuration failed for %s: %s", web_acl_arn, exc)
        return None
    cfg = resp.get("LoggingConfiguration") or {}
    for dest in cfg.get("LogDestinationConfigs", []) or []:
        if ":logs:" in dest:
            return dest
    return None


def _region_from_arn(arn: str) -> Optional[str]:
    parts = arn.split(":")
    return parts[3] if len(parts) > 3 and parts[3] else None


# ---------- CloudWatch Logs (rule stats) -------------------------------------


def _filter_pattern(rule_name: str) -> str:
    return (
        '{ ($.terminatingRuleId = "'
        + rule_name
        + '") || ($.ruleGroupList[0].terminatingRule.ruleId = "'
        + rule_name
        + '") }'
    )


def _log_group_name_from_arn(arn_or_name: str) -> str:
    """Return the bare log group name. WAF stores destinations as full ARNs.

    Example ARN: arn:aws:logs:us-east-1:123:log-group:aws-waf-logs-foo:*
    """
    if arn_or_name.startswith("arn:"):
        parts = arn_or_name.split(":")
        # Drop trailing :* if present
        name = parts[6] if len(parts) > 6 else arn_or_name
        return name.rstrip(":*")
    return arn_or_name


def _ms(epoch_seconds: float) -> int:
    return int(epoch_seconds * 1000)


def get_rule_stats(
    session: boto3.Session,
    log_group_arn: str,
    rule_name: str,
    web_acl_name: str,
    days: int = DEFAULT_WINDOW_DAYS,
    max_events: int = DEFAULT_MAX_EVENTS,
    *,
    logs_client: Any = None,
) -> Dict[str, Any]:
    """Aggregate CloudWatch Logs hits for a single WAF rule.

    Most-recent 50,000 events per rule, sorted desc by timestamp, 30-day
    window. If the rule has more than 50k hits in 30d, sample_uris and
    count_mode_hits reflect only the most recent slice — the hit_count is
    also capped at 50k. This is a known sampling limitation; bump
    max_events or move to Athena over S3 for high-traffic accounts.
    """
    region = _region_from_arn(log_group_arn) or DEFAULT_REGION
    if logs_client is None:
        logs_client = session.client("logs", region_name=region)

    log_group_name = _log_group_name_from_arn(log_group_arn)
    now = time.time()
    start_ms = _ms(now - days * 86400)
    end_ms = _ms(now)
    pattern = _filter_pattern(rule_name)

    collected: List[Dict[str, Any]] = []
    next_token: Optional[str] = None
    while len(collected) < max_events:
        kwargs: Dict[str, Any] = {
            "logGroupName": log_group_name,
            "startTime": start_ms,
            "endTime": end_ms,
            "filterPattern": pattern,
            "limit": LOG_EVENT_PAGE_SIZE,
        }
        if next_token:
            kwargs["nextToken"] = next_token
        try:
            resp = logs_client.filter_log_events(**kwargs)
        except ClientError as exc:
            logger.info(
                "filter_log_events failed for %s/%s: %s",
                log_group_name,
                rule_name,
                exc,
            )
            break
        events = resp.get("events", []) or []
        for ev in events:
            collected.append(ev)
            if len(collected) >= max_events:
                break
        next_token = resp.get("nextToken")
        if not next_token:
            break

    collected.sort(key=lambda e: e.get("timestamp", 0), reverse=True)
    hit_count = len(collected)
    last_fired: Optional[str] = None
    if collected:
        last_fired = (
            datetime.fromtimestamp(collected[0]["timestamp"] / 1000, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

    count_mode_hits = 0
    sample_uris: List[str] = []
    seen: set = set()
    for ev in collected:
        try:
            parsed = json.loads(ev.get("message", "{}"))
        except json.JSONDecodeError:
            continue
        if parsed.get("action") == "COUNT":
            count_mode_hits += 1
        uri = (parsed.get("httpRequest") or {}).get("uri")
        if uri and uri not in seen:
            seen.add(uri)
            if len(sample_uris) < 10:
                sample_uris.append(uri)

    return {
        "hit_count": hit_count,
        "last_fired": last_fired,
        "count_mode_hits": count_mode_hits,
        "sample_uris": sample_uris,
    }
