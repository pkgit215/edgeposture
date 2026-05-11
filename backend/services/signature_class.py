"""Phase post-5.3.2 — Issue #4 signature-class taxonomy.

Two responsibilities:

  * `classify_rule_intent(statement_json, rule_name)` — what attack class
    a WAF rule is *designed to block*.
  * `classify_request_pattern(uri, headers, ua, body_sample)` — what attack
    classes a real request *matches*.

Both functions key off the same lookup table so the audit pipeline can
detect coverage gaps:  "rule X was supposed to block shellshock; that
shellshock-shaped request reached origin → escalate the finding".

Out of scope:
  * AI fallback for ambiguous statements (tracked as a follow-up).
  * Body inspection beyond the first 4 KB.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import unquote_plus


# --- Class table ------------------------------------------------------------

# Each entry: (substring tokens, rule-name keyword tokens).
# `tokens` match decoded `uri + " " + args + " " + headers` (case-insensitive).
# `name_keywords` match the rule name itself (case-insensitive substring).
_TABLE: Dict[str, Dict[str, List[str]]] = {
    "shellshock": {
        "tokens": ["() { :", "() {:", "$(", "shellshock"],
        "name_keywords": ["shellshock", "bash_env", "bashbug"],
    },
    "log4shell": {
        "tokens": ["${jndi:", "${lower:j}ndi:", "${${"],
        "name_keywords": ["log4shell", "log4j", "jndi"],
    },
    "sqli": {
        "tokens": [
            "' or '1'='1", "1=1--", "union select", "select * from",
            "/**/and/**/", " or 1=1", "%27+or+", "drop table",
        ],
        "name_keywords": ["sqli", "sql_injection", "sqlinjection"],
    },
    "xss": {
        "tokens": [
            "<script", "<svg", "<img onerror", "javascript:", "onerror=",
            "<iframe", "alert(", "document.cookie",
        ],
        "name_keywords": ["xss", "cross_site", "crosssite"],
    },
    "unix_cve": {
        "tokens": [
            "/etc/passwd", "/etc/shadow", "/proc/self/", "wget ",
            "curl -o", "nc -e", "/dev/tcp/",
        ],
        "name_keywords": ["unix_cve", "cve_", "rce"],
    },
    "rate_limit": {
        "tokens": [],
        "name_keywords": ["rate_limit", "ratelimit", "throttle"],
    },
    "curl_ua": {
        "tokens": [],
        "name_keywords": [
            "curl", "scanner", "blockoldcurl", "old_curl", "useragent_block",
        ],
    },
    "bad_ip": {
        "tokens": [],
        "name_keywords": ["bad_ip", "blocklist", "ip_block", "ipdeny"],
    },
    "admin_path": {
        "tokens": [
            "/wp-admin", "/wp-login", "/phpmyadmin", "/.env",
            "/.git", "/admin/", "/manager/html", "/server-status",
        ],
        "name_keywords": ["admin_path", "blockadmin", "wpblock"],
    },
    "bot": {
        "tokens": [],
        "name_keywords": ["bot", "crawler", "spider", "ms-bot", "aws-bot"],
    },
}

_RULE_KIND_FROM_STATEMENT_REGEX = re.compile(r"[A-Za-z]+")


def _lc(s: Any) -> str:
    return str(s or "").lower()


def _classify_from_name(rule_name: str) -> Optional[str]:
    name = _lc(rule_name)
    if not name:
        return None
    for cls, entry in _TABLE.items():
        for kw in entry["name_keywords"]:
            if kw in name:
                return cls
    return None


def _statement_search_strings(node: Any) -> List[str]:
    """Walk a statement JSON node and return every `SearchString` and
    `RegexString` we encounter. Recursive; bounded to dict/list shapes."""
    out: List[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("SearchString", "RegexString") and isinstance(v, str):
                out.append(v)
            else:
                out.extend(_statement_search_strings(v))
    elif isinstance(node, list):
        for x in node:
            out.extend(_statement_search_strings(x))
    return out


def _classify_from_statement(statement_json: Any) -> Optional[str]:
    if not isinstance(statement_json, (dict, list)):
        return None
    needles = [_lc(s) for s in _statement_search_strings(statement_json)]
    if not needles:
        return None
    joined = " ".join(needles)
    for cls, entry in _TABLE.items():
        for tok in entry["tokens"]:
            if tok in joined:
                return cls
    return None


def classify_rule_intent(
    statement_json: Any,
    rule_name: str,
) -> Optional[str]:
    """Return the attack class this rule is designed to block, or `None`.

    Resolution order:
      1. Rule name keyword match (most reliable — humans pick descriptive names).
      2. Statement `SearchString` / `RegexString` token match.
      3. Otherwise None.
    """
    cls = _classify_from_name(rule_name)
    if cls:
        return cls
    return _classify_from_statement(statement_json)


def classify_request_pattern(
    uri: str = "",
    headers: Optional[List[Dict[str, str]]] = None,
    ua: str = "",
    body_sample: str = "",
) -> Set[str]:
    """Return the set of attack classes this request matches.

    Headers shape mirrors AWS WAFv2 logs:
        `[{"name": "user-agent", "value": "() { :; };"}, ...]`

    `uri` may be URL-encoded; we decode once before token matching so
    requests like `/%3Cscript%3Ealert(1)%3C/script%3E` correctly classify
    as `xss`.
    """
    headers = headers or []
    out: Set[str] = set()
    try:
        uri_dec = unquote_plus(_lc(uri), errors="replace")
    except Exception:  # noqa: BLE001
        uri_dec = _lc(uri)
    header_values: List[str] = []
    for h in headers:
        v_raw = _lc((h or {}).get("value"))
        try:
            v_dec = unquote_plus(v_raw, errors="replace")
        except Exception:  # noqa: BLE001
            v_dec = v_raw
        header_values.append(v_dec)
        if v_dec != v_raw:
            header_values.append(v_raw)
    ua_dec = _lc(ua)
    try:
        ua_dec = unquote_plus(ua_dec, errors="replace")
    except Exception:  # noqa: BLE001
        pass
    body_dec = _lc(body_sample)
    haystack = " ".join([uri_dec, *header_values, ua_dec, body_dec])

    for cls, entry in _TABLE.items():
        for tok in entry["tokens"]:
            if tok in haystack:
                out.add(cls)
                break
    return out
