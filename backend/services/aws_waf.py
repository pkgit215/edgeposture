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

    Phase 5 production fix: also iterate
    `PreProcessFirewallManagerRuleGroups` and
    `PostProcessFirewallManagerRuleGroups` — FMS-deployed managed rule
    groups live there, NOT in `acl["Rules"]`, and were being dropped by
    Phase 5's first pass causing the "Mode: ALLOW" misread on the PDF.
    """
    scope = web_acl.get("Scope", "REGIONAL")
    region = "us-east-1" if scope == "CLOUDFRONT" else web_acl.get("Region", DEFAULT_REGION)
    client = session.client("wafv2", region_name=region)
    resp = client.get_web_acl(
        Name=web_acl["Name"], Scope=scope, Id=web_acl["Id"]
    )
    acl = resp["WebACL"]

    raw_rules: List[Dict[str, Any]] = []
    raw_rules.extend(acl.get("Rules", []) or [])
    # FMS pre/post-process rule groups also need to surface to the audit.
    # boto3 returns them as wrappers with a synthetic `FirewallManagerStatement`;
    # we synthesise rule entries so they appear in the inventory with kind=managed.
    for prefix, source in (
        ("FMSPreProcess-", acl.get("PreProcessFirewallManagerRuleGroups", []) or []),
        ("FMSPostProcess-", acl.get("PostProcessFirewallManagerRuleGroups", []) or []),
    ):
        for grp in source:
            raw_rules.append({
                "Name": prefix + (grp.get("Name") or "unknown"),
                "Priority": grp.get("Priority", 0),
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": (grp.get("FirewallManagerStatement") or {})
                            .get("ManagedRuleGroupStatement", {})
                            .get("VendorName", "AWS"),
                        "Name": (grp.get("FirewallManagerStatement") or {})
                            .get("ManagedRuleGroupStatement", {})
                            .get("Name", grp.get("Name", "unknown")),
                    }
                },
                "OverrideAction": grp.get("OverrideAction") or {"None": {}},
                "ManagedByFirewallManager": True,
            })

    rules: List[Dict[str, Any]] = []
    for r in raw_rules:
        statement = _normalize_for_json(r.get("Statement", {}))
        kind = classify_rule_kind(statement)
        # Phase 5 production fix: presence of OverrideAction always means
        # managed-style (the rule references a rule group, AWS-managed or
        # customer-managed). Trust the field, not just the Statement shape.
        if "OverrideAction" in r and r.get("OverrideAction"):
            kind = "managed"
        mode = derive_mode(r, kind)
        override_action = None
        ovr = r.get("OverrideAction") or {}
        if "None" in ovr:
            override_action = "None"
        elif "Count" in ovr:
            override_action = "Count"
        # Phase 5.3.3 — extract sub-rule action overrides inside a
        # managed rule group (e.g. SizeRestrictions_BODY → Count).
        sub_overrides: List[Dict[str, str]] = []
        if isinstance(statement, dict):
            mrg = statement.get("ManagedRuleGroupStatement")
            if isinstance(mrg, dict):
                for o in (mrg.get("RuleActionOverrides") or []):
                    if not isinstance(o, dict):
                        continue
                    name = o.get("Name") or ""
                    action_to_use = o.get("ActionToUse") or {}
                    if isinstance(action_to_use, dict) and action_to_use:
                        # ActionToUse is shaped like {"Count": {}} / {"Block": {}} / etc.
                        action_label = next(iter(action_to_use.keys()), "")
                        if name and action_label:
                            sub_overrides.append({"name": name, "action": action_label})
        rules.append(
            {
                "rule_name": r["Name"],
                "priority": r.get("Priority", 0),
                "action": mode,  # Phase 5: now uses derive_mode() — "Block (group)" etc.
                "rule_kind": kind,
                "statement_json": statement,
                "override_action": override_action,
                "managed_rule_overrides": sub_overrides,
                "fms_managed": bool(r.get("ManagedByFirewallManager", False)),
            }
        )
    return rules


def classify_rule_kind(statement: Dict[str, Any]) -> str:
    """Phase 5: 'managed' vs 'rate_based' vs 'custom'.

    Production fix: also treat `RuleGroupReferenceStatement` (customer-
    owned rule groups) as managed-style so its mode renders correctly.
    """
    if not isinstance(statement, dict):
        return "custom"
    if "ManagedRuleGroupStatement" in statement:
        return "managed"
    if "RuleGroupReferenceStatement" in statement:
        return "managed"
    if "RateBasedStatement" in statement:
        return "rate_based"
    # Walk one level into AndStatement/OrStatement/NotStatement
    for combinator in ("AndStatement", "OrStatement", "NotStatement"):
        inner = statement.get(combinator) or {}
        stmts = inner.get("Statements") or ([inner.get("Statement")] if inner.get("Statement") else [])
        for s in stmts:
            if isinstance(s, dict) and (
                "ManagedRuleGroupStatement" in s
                or "RuleGroupReferenceStatement" in s
            ):
                return "managed"
            if isinstance(s, dict) and "RateBasedStatement" in s:
                return "rate_based"
    return "custom"


def _classify_resource_arn(arn: str) -> str:
    """Map an AWS ARN string to a short resource-type label."""
    if not arn:
        return "UNKNOWN"
    if ":cloudfront:" in arn or ":cloudfront::" in arn:
        return "CLOUDFRONT"
    if ":elasticloadbalancing:" in arn and ":loadbalancer/app/" in arn:
        return "ALB"
    if ":apigateway:" in arn or ":execute-api:" in arn:
        return "API_GW"
    if ":appsync:" in arn:
        return "APPSYNC"
    if ":cognito-idp:" in arn:
        return "COGNITO"
    if ":apprunner:" in arn:
        return "APPRUNNER"
    return "UNKNOWN"


def _resource_id_from_arn(arn: str) -> str:
    """Best-effort id extraction — last `/` or `:` segment of the ARN."""
    if not arn:
        return ""
    last_slash = arn.rsplit("/", 1)
    if len(last_slash) == 2 and last_slash[1]:
        return last_slash[1]
    return arn.rsplit(":", 1)[-1]


def enrich_resource_friendly_names(
    session: boto3.Session,
    resource_arns: List[str],
    *,
    cf_distros: Optional[List[Dict[str, str]]] = None,
) -> List[Dict[str, Optional[str]]]:
    """Phase 5.2.2 — turn a list of ARN strings into a list of
    `{arn, type, id, friendly}` dicts. Best-effort: failures don't break
    the audit; `friendly` is left as None for that resource.

    `cf_distros` lets the caller pass distributions already enumerated by
    `list_cloudfront_distributions_for_web_acl` (which carries DomainName);
    we look up Aliases via a per-distribution `cloudfront:get-distribution`
    call only when an alias would meaningfully beat the cloudfront.net
    name. Other resource types are looked up via their type-specific API.
    """
    out: List[Dict[str, Optional[str]]] = []
    cf_by_arn = {d.get("arn"): d for d in (cf_distros or []) if d.get("arn")}

    # Cache per-type clients lazily.
    elbv2_client = None
    cf_client = None
    apigw_client = None
    apigwv2_client = None

    for arn in resource_arns:
        rtype = _classify_resource_arn(arn)
        rid = _resource_id_from_arn(arn)
        friendly: Optional[str] = None
        try:
            if rtype == "CLOUDFRONT":
                hint = cf_by_arn.get(arn) or {}
                friendly = hint.get("domain_name") or None
                # Upgrade to a custom alias when available.
                try:
                    if cf_client is None:
                        cf_client = session.client("cloudfront", region_name="us-east-1")
                    if rid:
                        resp = cf_client.get_distribution(Id=rid)
                        aliases = ((resp.get("Distribution") or {}).get("DistributionConfig") or {}).get("Aliases") or {}
                        items = aliases.get("Items") or []
                        if items:
                            friendly = items[0]
                except ClientError as exc:
                    if not _is_access_denied(exc):
                        logger.debug("get_distribution failed for %s: %s", rid, exc)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("get_distribution failed for %s: %s", rid, exc)
            elif rtype == "ALB":
                try:
                    region = arn.split(":")[3] or DEFAULT_REGION
                    if elbv2_client is None:
                        elbv2_client = session.client("elbv2", region_name=region)
                    resp = elbv2_client.describe_load_balancers(LoadBalancerArns=[arn])
                    lbs = resp.get("LoadBalancers") or []
                    if lbs:
                        friendly = lbs[0].get("DNSName") or lbs[0].get("LoadBalancerName")
                except ClientError as exc:
                    if not _is_access_denied(exc):
                        logger.debug("describe_load_balancers failed: %s", exc)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("describe_load_balancers failed: %s", exc)
            elif rtype == "API_GW":
                # APIGatewayv2 or REST API — try both lazily.
                try:
                    region = arn.split(":")[3] or DEFAULT_REGION
                    if apigwv2_client is None:
                        apigwv2_client = session.client("apigatewayv2", region_name=region)
                    resp = apigwv2_client.get_api(ApiId=rid)
                    friendly = resp.get("Name") or rid
                except Exception:  # noqa: BLE001
                    try:
                        if apigw_client is None:
                            apigw_client = session.client("apigateway", region_name=region)
                        resp = apigw_client.get_rest_api(restApiId=rid)
                        friendly = resp.get("name") or rid
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("apigw friendly name lookup failed: %s", exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "attachment_lookup arn=%s type=%s method=friendly_name "
                "result=unexpected_error error=%r",
                arn, rtype, exc,
            )
        logger.info(
            "attachment_lookup arn=%s type=%s method=friendly_name "
            "result=%s id=%s friendly=%r",
            arn, rtype, "success" if friendly else "no_friendly", rid, friendly,
        )
        out.append({"arn": arn, "type": rtype, "id": rid, "friendly": friendly})
    return out


def derive_mode(rule: Dict[str, Any], kind: str) -> str:
    """Phase 5: human-readable rule action, fixing the OverrideAction misread.

    Production fix: presence of `OverrideAction` ALWAYS forces managed
    branch — this is the field AWS uses to signal "this rule is a group
    reference". Don't rely on the kind classifier alone (it can miss
    edge cases like custom rule groups or FMS pre/post rules).

    For managed rule groups:
      OverrideAction.None  → 'Block (group)'      (group's own per-sub-rule actions apply)
      OverrideAction.Count → 'Count (override)'   (operator override — observe only)
      (missing)            → 'Block (group)'      (group default)

    For custom rules:
      Action.Block/Allow/Count/Captcha/Challenge → upper-case label
    """
    # Phase 5 production fix: OverrideAction presence is the canonical
    # signal of a managed/group-reference rule.
    has_override = bool(rule.get("OverrideAction"))
    if kind == "managed" or has_override:
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


def _is_access_denied(exc: Exception) -> bool:
    """Robustly detect IAM/auth denials across all boto3 exception shapes."""
    try:
        resp = getattr(exc, "response", None) or {}
        code = (resp.get("Error") or {}).get("Code") or ""
    except Exception:  # noqa: BLE001
        code = ""
    if code in ("AccessDeniedException", "AccessDenied", "UnauthorizedOperation"):
        return True
    # botocore may not populate response.Error for some exception classes;
    # fall back to checking class name.
    cls = type(exc).__name__
    return cls in ("AccessDeniedException", "AccessDenied", "UnauthorizedOperation")


def list_cloudfront_distributions_for_web_acl(
    session: boto3.Session, web_acl_arn: str
) -> Optional[List[Dict[str, str]]]:
    """Phase 5.2 — REAL CloudFront attachment detection.

    `wafv2:list-resources-for-web-acl` is unreliable for CLOUDFRONT scope
    (the API often returns [] even for attached ACLs). The canonical way
    to find which CloudFront distributions reference a Web ACL is to
    page `cloudfront:list-distributions` and filter by `WebACLId == arn`.

    Returns a list of `{"arn": ..., "id": ..., "domain_name": ...}` or
    None if AccessDenied / API unreachable (treated as Unknown by caller).
    """
    # Phase 5.2.1 — CloudFront is global but the SDK still binds the
    # endpoint via region_name. Pin to us-east-1 explicitly so an
    # un-configured session region doesn't trip the client builder.
    try:
        cf = session.client("cloudfront", region_name="us-east-1")
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "attachment_lookup acl_arn=%s scope=CLOUDFRONT method=cloudfront:ListDistributions "
            "result=client_construction_failed error=%r",
            web_acl_arn, exc,
        )
        return None
    try:
        paginator = cf.get_paginator("list_distributions")
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "attachment_lookup acl_arn=%s scope=CLOUDFRONT method=cloudfront:ListDistributions "
            "result=paginator_unavailable error=%r",
            web_acl_arn, exc,
        )
        return None
    matching: List[Dict[str, str]] = []
    scanned = 0
    try:
        for page in paginator.paginate():
            dist_list = (page.get("DistributionList") or {})
            items = dist_list.get("Items", []) or []
            scanned += len(items)
            for d in items:
                if d.get("WebACLId") == web_acl_arn:
                    matching.append({
                        "arn": d.get("ARN") or "",
                        "id": d.get("Id") or "",
                        "domain_name": d.get("DomainName") or "",
                    })
    except ClientError as exc:
        if _is_access_denied(exc):
            logger.warning(
                "attachment_lookup acl_arn=%s scope=CLOUDFRONT method=cloudfront:ListDistributions "
                "result=access_denied — IAM role missing cloudfront:ListDistributions.",
                web_acl_arn,
            )
            return None
        logger.warning(
            "attachment_lookup acl_arn=%s scope=CLOUDFRONT method=cloudfront:ListDistributions "
            "result=client_error error=%r",
            web_acl_arn, exc,
        )
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "attachment_lookup acl_arn=%s scope=CLOUDFRONT method=cloudfront:ListDistributions "
            "result=unexpected_error error=%r",
            web_acl_arn, exc,
        )
        return None
    logger.info(
        "attachment_lookup acl_arn=%s scope=CLOUDFRONT method=cloudfront:ListDistributions "
        "result=success scanned=%d matches=%d match_ids=%s",
        web_acl_arn, scanned, len(matching),
        [m["id"] for m in matching],
    )
    return matching


def list_resources_for_web_acl(
    session: boto3.Session, web_acl: Dict[str, Any]
) -> Optional[List[str]]:
    """Phase 5: Return all resource ARNs the Web ACL is associated with.

    Return semantics:
      * `[]`   → ACL is genuinely orphaned (API succeeded, no associations)
      * `None` → attachment status UNKNOWN (AccessDenied / API unreachable)
      * `[...]`→ attached to the listed resources.

    Phase 5.2 fixes:
      * Don't abort the regional loop on FIRST AccessDenied — retry the
        denied resource types once after a 2-second backoff (handles IAM
        propagation lag), then keep going. The function only returns None
        if EVERY resource type call failed (no partial-success window).
      * CloudFront scope now uses `list_cloudfront_distributions_for_web_acl`
        (cloudfront:ListDistributions) which IS reliable — wafv2's
        list_resources_for_web_acl is the broken API for CF.
    """
    scope = web_acl.get("Scope", "REGIONAL")
    region = "us-east-1" if scope == "CLOUDFRONT" else web_acl.get("Region", DEFAULT_REGION)

    if scope == "CLOUDFRONT":
        dists = list_cloudfront_distributions_for_web_acl(session, web_acl["ARN"])
        if dists is None:
            return None
        return [d["arn"] for d in dists if d.get("arn")]

    client = session.client("wafv2", region_name=region)
    arns: List[str] = []
    saw_success = False
    denied_rts: List[str] = []
    other_failure_rts: List[str] = []
    resource_types = (
        "APPLICATION_LOAD_BALANCER",
        "API_GATEWAY",
        "APPSYNC",
        "COGNITO_USER_POOL",
        "APP_RUNNER_SERVICE",
        "VERIFIED_ACCESS_INSTANCE",
    )
    for rt in resource_types:
        try:
            resp = client.list_resources_for_web_acl(
                WebACLArn=web_acl["ARN"], ResourceType=rt
            )
            saw_success = True
            for r in resp.get("ResourceArns", []) or []:
                arns.append(r)
        except ClientError as exc:
            if _is_access_denied(exc):
                denied_rts.append(rt)
            else:
                other_failure_rts.append(rt)
                logger.debug(
                    "list_resources_for_web_acl %s on %s skipped: %s",
                    rt, web_acl.get("Name"), exc,
                )
        except Exception as exc:  # noqa: BLE001
            other_failure_rts.append(rt)
            logger.debug("list_resources_for_web_acl %s skipped: %s", rt, exc)

    # Phase 5.2 fix: retry denied resource types once after a short wait
    # (IAM propagation can take 5-15 seconds, well within retry budget).
    if denied_rts and not saw_success:
        logger.info(
            "list_resources_for_web_acl: %d resource types denied on %s. "
            "Sleeping 2s and retrying (IAM propagation hedge).",
            len(denied_rts), web_acl.get("Name"),
        )
        time.sleep(2)
        for rt in denied_rts:
            try:
                resp = client.list_resources_for_web_acl(
                    WebACLArn=web_acl["ARN"], ResourceType=rt
                )
                saw_success = True
                for r in resp.get("ResourceArns", []) or []:
                    arns.append(r)
            except ClientError as exc:
                if _is_access_denied(exc):
                    continue  # still denied
                logger.debug(
                    "list_resources_for_web_acl retry %s skipped: %s", rt, exc
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("list_resources_for_web_acl retry %s skipped: %s", rt, exc)

    if not saw_success:
        # EVERY call failed → genuinely Unknown (no permission, or API down).
        if denied_rts:
            logger.warning(
                "attachment_lookup acl_name=%s scope=REGIONAL "
                "method=wafv2:ListResourcesForWebACL result=all_denied "
                "denied_resource_types=%s — IAM role missing wafv2:ListResourcesForWebACL.",
                web_acl.get("Name"), denied_rts,
            )
        else:
            logger.warning(
                "attachment_lookup acl_name=%s scope=REGIONAL "
                "method=wafv2:ListResourcesForWebACL result=all_failed "
                "other_failures=%s",
                web_acl.get("Name"), other_failure_rts,
            )
        return None
    # At least one resource type returned successfully — the empty/non-empty
    # `arns` list is now a real signal: empty means truly orphan.
    logger.info(
        "attachment_lookup acl_name=%s scope=REGIONAL "
        "method=wafv2:ListResourcesForWebACL result=success "
        "resources=%d denied=%s other_failures=%s",
        web_acl.get("Name"), len(arns), denied_rts, other_failure_rts,
    )
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

    Production fix: URL-decode `uri` and `args` before pattern matching.
    Real WAF logs preserve URL-encoding (`%3Cscript%3E`, `%27+OR+%271%27%3D%271`),
    which would never match the literal `<script` / `' or '1'='1` tokens.
    Scoring takes the MAX of raw-form and decoded-form matches per family
    so deliberately encoded attacks aren't lost either.

    Signatures (see spec § Phase 5.5):
      * Shellshock in any header value:                +10
      * ${jndi: anywhere in headers/uri/args:          +10
      * SQLi tokens in uri or args:                    +8
      * XSS tokens in uri or args:                     +6
      * Path-traversal / LFI tokens in uri:            +6
      * Command-injection tokens in uri or args:       +6
      * Admin / sensitive-path prefix on uri:          +4
      * Known scanner User-Agent:                      +4
    """
    from urllib.parse import unquote_plus

    score = 0
    http = req.get("httpRequest") or {}
    uri_raw = (http.get("uri") or "").lower()
    args_raw = (http.get("args") or "").lower()
    try:
        uri_dec = unquote_plus(uri_raw, errors="replace")
        args_dec = unquote_plus(args_raw, errors="replace")
    except Exception:  # noqa: BLE001
        uri_dec, args_dec = uri_raw, args_raw

    headers = http.get("headers") or []
    # Headers are a list of {name, value} dicts. AWS CF-source uses
    # lowercase names; ALB-source uses Title-Case. Normalise name lookup.
    header_values: List[str] = []
    ua = ""
    for h in headers:
        v_raw = (h.get("value") or "").lower()
        try:
            v_dec = unquote_plus(v_raw, errors="replace")
        except Exception:  # noqa: BLE001
            v_dec = v_raw
        # Score on both forms — store decoded so signature checks succeed.
        header_values.append(v_dec if v_dec != v_raw else v_raw)
        if v_dec != v_raw:
            header_values.append(v_raw)
        if (h.get("name") or "").lower() == "user-agent":
            ua = v_dec or v_raw

    def _hit(tokens, *haystacks):
        for hay in haystacks:
            if any(tok in hay for tok in tokens):
                return True
        return False

    # Shellshock — header-only signature.
    if _hit(_SHELLSHOCK_TOKENS, *header_values):
        score += _S_SHELLSHOCK

    # Log4Shell / JNDI — header, uri, or args (raw OR decoded).
    jndi_hay = " ".join([uri_raw, args_raw, uri_dec, args_dec, *header_values])
    if _hit(_LOG4SHELL_TOKENS, jndi_hay):
        score += _S_LOG4SHELL

    # SQLi.
    if _hit(_SQLI_TOKENS, uri_raw + " " + args_raw, uri_dec + " " + args_dec):
        score += _S_SQLI

    # XSS.
    if _hit(_XSS_TOKENS, uri_raw + " " + args_raw, uri_dec + " " + args_dec):
        score += _S_XSS

    # LFI / path traversal — uri only.
    if _hit(_LFI_TOKENS, uri_raw, uri_dec):
        score += _S_LFI

    # Command injection.
    if _hit(_CMD_INJECTION_TOKENS, uri_raw + " " + args_raw, uri_dec + " " + args_dec):
        score += _S_CMD

    # Admin / sensitive paths — uri prefix only (decoded form to match
    # `%2Fadmin` -> `/admin`).
    if any(uri_dec.startswith(p) or uri_raw.startswith(p) for p in _ADMIN_PATH_TOKENS):
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
    debug_capture: Optional[List[Dict[str, Any]]] = None,
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

    Phase 5 production fix:
      * `debug_capture` if provided is filled with up to 5 RAW parsed
        events (the first 5 actually fetched) for post-hoc diagnosis of
        WAF-log-shape surprises in production. Audit pipeline persists
        these onto `audit_runs.debug_log_sample`.
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
    debug_captured = 0

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
            # Phase 5 production debug — capture first 5 RAW events (before
            # action-filter / scoring) so the caller can diagnose log shape.
            if debug_capture is not None and debug_captured < 5:
                debug_capture.append(parsed)
                debug_captured += 1
            if parsed.get("action") != "ALLOW":
                continue  # defence-in-depth — server filter SHOULD have caught
            score = score_request_suspicion(parsed)
            if score < SUSPICION_THRESHOLD:
                continue
            tie += 1
            parsed["_suspicion_score"] = score
            # Issue #4 — tag each persisted event with the set of
            # signature classes it matched, so the audit pipeline can
            # cross-reference dead-rule intent against observed traffic.
            try:
                from .signature_class import classify_request_pattern
                http_obj = parsed.get("httpRequest") or {}
                _ua = ""
                for _h in (http_obj.get("headers") or []):
                    if (_h.get("name") or "").lower() == "user-agent":
                        _ua = _h.get("value") or ""
                        break
                parsed["_signature_classes"] = sorted(classify_request_pattern(
                    uri=(http_obj.get("uri") or "")
                        + ("?" + http_obj.get("args") if http_obj.get("args") else ""),
                    headers=http_obj.get("headers") or [],
                    ua=_ua,
                ))
            except Exception:  # noqa: BLE001
                parsed["_signature_classes"] = []
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
