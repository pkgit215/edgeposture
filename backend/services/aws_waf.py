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
import heapq
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
        statement = _normalize_for_json(r.get("Statement", {}))
        kind = classify_rule_kind(statement)
        mode = derive_mode(r, kind)
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
                "action": mode,  # Phase 5: now uses derive_mode() — "Block (group)" etc.
                "rule_kind": kind,
                "statement_json": statement,
                "override_action": override_action,
                "fms_managed": bool(r.get("ManagedByFirewallManager", False)),
            }
        )
    return rules


def classify_rule_kind(statement: Dict[str, Any]) -> str:
    """Phase 5: 'managed' vs 'rate_based' vs 'custom'."""
    if not isinstance(statement, dict):
        return "custom"
    if "ManagedRuleGroupStatement" in statement:
        return "managed"
    if "RateBasedStatement" in statement:
        return "rate_based"
    # Walk one level into AndStatement/OrStatement/NotStatement
    for combinator in ("AndStatement", "OrStatement", "NotStatement"):
        inner = statement.get(combinator) or {}
        stmts = inner.get("Statements") or ([inner.get("Statement")] if inner.get("Statement") else [])
        for s in stmts:
            if isinstance(s, dict) and "ManagedRuleGroupStatement" in s:
                return "managed"
            if isinstance(s, dict) and "RateBasedStatement" in s:
                return "rate_based"
    return "custom"


def derive_mode(rule: Dict[str, Any], kind: str) -> str:
    """Phase 5: human-readable rule action, fixing the OverrideAction misread.

    For managed rule groups:
      OverrideAction.None  → 'Block (group)'      (group's own per-sub-rule actions apply)
      OverrideAction.Count → 'Count (override)'   (operator override — observe only)
      (missing)            → 'Block (group)'      (group default)

    For custom rules:
      Action.Block/Allow/Count/Captcha/Challenge → upper-case label
    """
    if kind == "managed":
        ovr = rule.get("OverrideAction") or {}
        if "Count" in ovr:
            return "Count (override)"
        return "Block (group)"
    action = rule.get("Action") or {}
    for key in ("Block", "Allow", "Count", "Captcha", "Challenge"):
        if key in action:
            return key.upper()
    return "ALLOW"


# Compatibility shim — old callers (tests) used _derive_action(rule).
def _derive_action(rule: Dict[str, Any]) -> str:
    kind = classify_rule_kind(rule.get("Statement") or {})
    return derive_mode(rule, kind)


def list_resources_for_web_acl(
    session: boto3.Session, web_acl: Dict[str, Any]
) -> List[str]:
    """Phase 5: Return all resource ARNs (ALB, API Gateway, AppSync, etc.) the
    Web ACL is associated with. For CLOUDFRONT scope, returns distribution
    IDs (which AWS treats as resources here). Empty list = orphaned ACL.

    All boto3/moto errors degrade gracefully to an empty list rather than
    failing the audit — older test rigs (moto) don't implement this API.
    """
    scope = web_acl.get("Scope", "REGIONAL")
    arns: List[str] = []
    region = "us-east-1" if scope == "CLOUDFRONT" else web_acl.get("Region", DEFAULT_REGION)
    client = session.client("wafv2", region_name=region)
    if scope == "CLOUDFRONT":
        try:
            resp = client.list_resources_for_web_acl(WebACLArn=web_acl["ARN"])
            for r in resp.get("ResourceArns", []) or []:
                arns.append(r)
        except (ClientError, NotImplementedError, Exception) as exc:  # noqa: BLE001
            logger.warning("list_resources_for_web_acl CLOUDFRONT failed: %s", exc)
        return arns

    # REGIONAL — iterate the documented resource types.
    for rt in (
        "APPLICATION_LOAD_BALANCER",
        "API_GATEWAY",
        "APPSYNC",
        "COGNITO_USER_POOL",
        "APP_RUNNER_SERVICE",
        "VERIFIED_ACCESS_INSTANCE",
    ):
        try:
            resp = client.list_resources_for_web_acl(
                WebACLArn=web_acl["ARN"], ResourceType=rt
            )
            for r in resp.get("ResourceArns", []) or []:
                arns.append(r)
        except (ClientError, NotImplementedError, Exception) as exc:  # noqa: BLE001
            # Older SDKs / unsupported resource types / moto stubs.
            logger.debug("list_resources_for_web_acl %s skipped: %s", rt, exc)
    return arns


# Phase 5.5 — bypass-detection scoring + sampler ----------------------------
#
# Scoring is additive across signature families. Threshold of 4 means at
# least one "scanner / admin path" hit, and we keep top-K (default 50)
# across the whole audit. Values come straight from the Phase 5 spec —
# don't lower them without also updating the threshold in the sampler.

_SHELLSHOCK_TOKENS = ("() { :;}", "() {:;}")
_LOG4SHELL_TOKENS = ("${jndi:",)
_SQLI_TOKENS = (
    "union+select", "union select", "' or '1'='1", "' or 1=1",
    "'; drop table", "; drop table", "/*!50000",
)
_XSS_TOKENS = (
    "<script", "javascript:", "onerror=", "onload=", "onfocus=",
)
_LFI_TOKENS = ("../", "..\\", "/etc/passwd", "/proc/self", "\\..\\")
_CMD_INJECTION_TOKENS = (
    "wget ", "curl ", "bash -c", "eval(", "system(", "$(", "`whoami",
)
_ADMIN_PATH_TOKENS = (
    "/admin", "/.git", "/.env", "/wp-admin", "/cgi-bin/", "/phpmyadmin",
    "/server-status", "/.well-known/cgi-bin",
)
_SCANNER_UA_TOKENS = (
    "sqlmap", "nikto", "nmap", "acunetix", "burp", "wpscan",
    "masscan", "gobuster", "dirbuster",
)

# Score increments (per spec).
_S_SHELLSHOCK = 10
_S_LOG4SHELL = 10
_S_SQLI = 8
_S_XSS = 6
_S_LFI = 6
_S_CMD = 6
_S_ADMIN = 4
_S_SCANNER_UA = 4

# Minimum score for an event to be considered a "candidate" worth sampling.
SUSPICION_THRESHOLD = 4


def score_request_suspicion(req: Dict[str, Any]) -> int:
    """Return an additive 0..N 'attack-shapedness' score for one parsed
    WAFv2 log event.

    Signatures (see spec § Phase 5.5):
      * Shellshock in any header value:                +10
      * ${jndi: anywhere in headers/uri/args:          +10
      * SQLi tokens in uri or args:                    +8
      * XSS tokens in uri or args:                     +6
      * Path-traversal / LFI tokens in uri:            +6  (also +6 if /etc/passwd etc)
      * Command-injection tokens in uri or args:       +6
      * Admin / sensitive-path prefix on uri:          +4
      * Known scanner User-Agent:                      +4

    No upper cap — multi-signature attacks naturally accumulate higher.
    A score >= SUSPICION_THRESHOLD (4) marks the request as a candidate
    for inclusion in the Pass-3 bypass sample.
    """
    score = 0
    http = req.get("httpRequest") or {}
    uri = (http.get("uri") or "").lower()
    args = (http.get("args") or "").lower()
    headers = http.get("headers") or []

    # Flatten headers once.
    header_values = []
    ua = ""
    for h in headers:
        v = (h.get("value") or "").lower()
        header_values.append(v)
        if (h.get("name") or "").lower() == "user-agent":
            ua = v

    # Shellshock — header-only signature, signature itself is unambiguous.
    for hv in header_values:
        if any(tok in hv for tok in _SHELLSHOCK_TOKENS):
            score += _S_SHELLSHOCK
            break

    # Log4Shell / JNDI — header, uri, or args.
    haystack_for_jndi = " ".join([uri, args, *header_values])
    if any(tok in haystack_for_jndi for tok in _LOG4SHELL_TOKENS):
        score += _S_LOG4SHELL

    # SQLi.
    haystack_for_payload = uri + " " + args
    if any(tok in haystack_for_payload for tok in _SQLI_TOKENS):
        score += _S_SQLI

    # XSS.
    if any(tok in haystack_for_payload for tok in _XSS_TOKENS):
        score += _S_XSS

    # LFI / path traversal — primarily uri.
    if any(tok in uri for tok in _LFI_TOKENS):
        score += _S_LFI

    # Command injection.
    if any(tok in haystack_for_payload for tok in _CMD_INJECTION_TOKENS):
        score += _S_CMD

    # Admin / sensitive paths — uri prefix only.
    if any(uri.startswith(p) for p in _ADMIN_PATH_TOKENS):
        score += _S_ADMIN

    # Scanner UA.
    if ua and any(tok in ua for tok in _SCANNER_UA_TOKENS):
        score += _S_SCANNER_UA

    return score


def sample_suspicious_allowed_requests(
    session: boto3.Session,
    log_group_arn: str,
    days: int = DEFAULT_WINDOW_DAYS,
    top_k: int = 50,
    *,
    logs_client: Any = None,
    max_events_scanned: int = 200_000,
) -> List[Dict[str, Any]]:
    """Phase 5.5 — page CloudWatch Logs for ALLOW events on this Web ACL's
    log group and return the global top-K by `score_request_suspicion`.

    Only events with `action == "ALLOW"` are considered — these are the
    requests that REACHED the origin. BLOCK/COUNT events are excluded
    because they were already handled by a WAF rule (the spec wants
    coverage gaps, not rule hits).

    Returns a list of parsed-JSON log events sorted by score desc, each
    annotated with an internal `_suspicion_score` field. Empty input
    (no logs, or no events scoring above SUSPICION_THRESHOLD) ⇒ [].
    """
    region = _region_from_arn(log_group_arn) or DEFAULT_REGION
    if logs_client is None:
        logs_client = session.client("logs", region_name=region)

    log_group_name = _log_group_name_from_arn(log_group_arn)
    now = time.time()
    start_ms = _ms(now - days * 86400)
    end_ms = _ms(now)
    # CloudWatch Logs JSON filter — server-side narrowing to ALLOW so we
    # don't drag back gigabytes of irrelevant BLOCK events.
    pattern = '{ $.action = "ALLOW" }'

    heap: List[Any] = []  # (score, tie-breaker, parsed_event)
    next_token: Optional[str] = None
    scanned = 0
    tie = 0

    while scanned < max_events_scanned:
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
                "filter_log_events ALLOW sample failed for %s: %s",
                log_group_name, exc,
            )
            break
        events = resp.get("events", []) or []
        for ev in events:
            scanned += 1
            try:
                parsed = json.loads(ev.get("message", "{}"))
            except json.JSONDecodeError:
                continue
            if parsed.get("action") != "ALLOW":
                continue  # defence-in-depth — server filter SHOULD have caught
            score = score_request_suspicion(parsed)
            if score < SUSPICION_THRESHOLD:
                continue
            tie += 1
            parsed["_suspicion_score"] = score
            if len(heap) < top_k:
                heapq.heappush(heap, (score, tie, parsed))
            elif score > heap[0][0]:
                heapq.heappushpop(heap, (score, tie, parsed))
        next_token = resp.get("nextToken")
        if not next_token:
            break

    return [p for _s, _t, p in sorted(heap, key=lambda x: (-x[0], x[1]))]


def merge_suspicious_samples(
    samples: List[List[Dict[str, Any]]], top_k: int = 50
) -> List[Dict[str, Any]]:
    """Merge per-ACL suspicious-request samples into one global top-K
    ranked by `_suspicion_score`. Stable across input order."""
    flat: List[Dict[str, Any]] = []
    for s in samples:
        if s:
            flat.extend(s)
    flat.sort(key=lambda e: -int(e.get("_suspicion_score") or 0))
    return flat[:top_k]


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
