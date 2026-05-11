"""Phase 4 — PDF audit report renderer.

Generates a clean, executive-grade PDF summarizing a completed audit run.
Layout: cover → executive summary → findings detail (grouped) → rule
inventory table. Footer on every page. Helvetica throughout.

Inputs are the already-loaded Mongo documents (audit_run, rules, findings).
The renderer never touches the database — it is pure data → bytes.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Sequence

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

# ---- Visual tokens -----------------------------------------------------------

INK = colors.HexColor("#0f172a")        # slate-900
INK_SOFT = colors.HexColor("#334155")   # slate-700
MUTED = colors.HexColor("#64748b")      # slate-500
HAIRLINE = colors.HexColor("#e2e8f0")   # slate-200
ROW_ALT = colors.HexColor("#f8fafc")    # slate-50
ACCENT = colors.HexColor("#1d4ed8")     # blue-700

SEV_HIGH = colors.HexColor("#dc2626")   # red-600
SEV_MED = colors.HexColor("#d97706")    # amber-600
SEV_LOW = colors.HexColor("#6b7280")    # gray-500

SEV_COLOR = {"high": SEV_HIGH, "medium": SEV_MED, "low": SEV_LOW}

TYPE_ORDER = ["dead_rule", "bypass_candidate", "conflict", "quick_win", "fms_review", "orphaned_web_acl"]
TYPE_LABEL = {
    "dead_rule": "Dead rules",
    "bypass_candidate": "Bypass candidates",
    "conflict": "Rule conflicts",
    "quick_win": "Quick wins",
    "fms_review": "FMS-managed review items",
    "orphaned_web_acl": "Orphaned Web ACLs",
}


# ---- Helpers -----------------------------------------------------------------


def _fmt_date(d: Any) -> str:
    if not d:
        return "—"
    if isinstance(d, datetime):
        return d.strftime("%Y-%m-%d %H:%M UTC")
    return str(d)


def _fmt_int(n: int) -> str:
    return f"{n:,}"


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()["Normal"]
    base.fontName = "Helvetica"
    base.fontSize = 9.5
    base.textColor = INK_SOFT
    base.leading = 13
    return {
        "h1": ParagraphStyle(
            "h1", parent=base, fontName="Helvetica-Bold", fontSize=24,
            textColor=INK, leading=28, spaceAfter=2,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base, fontName="Helvetica-Bold", fontSize=15,
            textColor=INK, leading=20, spaceBefore=10, spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "h3", parent=base, fontName="Helvetica-Bold", fontSize=11,
            textColor=INK, leading=15, spaceBefore=6, spaceAfter=2,
        ),
        "muted": ParagraphStyle(
            "muted", parent=base, fontSize=9, textColor=MUTED, leading=12,
        ),
        "body": base,
        "body_small": ParagraphStyle(
            "body_small", parent=base, fontSize=8.5, leading=11,
        ),
        "tag": ParagraphStyle(
            "tag", parent=base, fontName="Helvetica-Bold", fontSize=8,
            textColor=colors.white, leading=10,
        ),
    }


# ---- Custom flowables --------------------------------------------------------


class _SeverityBar(Flowable):
    """A short colored vertical bar — used in finding cards."""

    def __init__(self, severity: str, height: float = 36) -> None:
        super().__init__()
        self.color = SEV_COLOR.get(severity, SEV_LOW)
        self.height = height
        self.width = 4

    def draw(self) -> None:
        c = self.canv
        c.setFillColor(self.color)
        c.rect(0, 0, self.width, self.height, stroke=0, fill=1)


# ---- Page footer / numbering -------------------------------------------------


def _make_footer(generated_at: str):
    def _draw(canvas, doc) -> None:
        canvas.saveState()
        canvas.setStrokeColor(HAIRLINE)
        canvas.setLineWidth(0.5)
        canvas.line(
            doc.leftMargin,
            doc.bottomMargin - 12,
            LETTER[0] - doc.rightMargin,
            doc.bottomMargin - 12,
        )
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(
            doc.leftMargin,
            doc.bottomMargin - 24,
            f"RuleIQ Audit Report  ·  {generated_at}",
        )
        canvas.drawRightString(
            LETTER[0] - doc.rightMargin,
            doc.bottomMargin - 24,
            f"page {canvas.getPageNumber()}",
        )
        canvas.restoreState()

    return _draw


# ---- Section builders --------------------------------------------------------


def _summary_stats(audit_run: Dict[str, Any], rules: Sequence[Dict[str, Any]],
                   findings: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    sev = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        s = (f.get("severity") or "low").lower()
        if s in sev:
            sev[s] += 1
    zero_hit = sum(1 for r in rules if int(r.get("hit_count") or 0) == 0)
    waste = audit_run.get("estimated_waste_usd")
    if waste is None:
        waste = 0
    return {
        "rules_analyzed": len(rules),
        "findings_total": len(findings),
        "sev_high": sev["high"],
        "sev_medium": sev["medium"],
        "sev_low": sev["low"],
        "zero_hit": zero_hit,
        "waste_usd": waste,
    }


def _build_cover(audit_run: Dict[str, Any], stats: Dict[str, Any],
                 generated_at: str, S: Dict[str, ParagraphStyle]) -> List[Flowable]:
    out: List[Flowable] = []
    out.append(Paragraph("RuleIQ", S["muted"]))
    out.append(Paragraph("AWS WAF Audit Report", S["h1"]))
    out.append(Spacer(1, 18))

    data_source = (audit_run.get("data_source") or "fixture").lower()
    badge_label = "Real AWS data" if data_source == "aws" else "Demo / fixture data"
    badge_color = ACCENT if data_source == "aws" else MUTED

    facts = [
        ["Account ID", str(audit_run.get("account_id") or "—")],
        ["Region", str(audit_run.get("region") or "—")],
        ["Audit started", _fmt_date(audit_run.get("started_at") or audit_run.get("created_at"))],
        ["Audit completed", _fmt_date(audit_run.get("completed_at"))],
        ["Data source", badge_label],
        ["Report ID", str(audit_run.get("_id") or audit_run.get("id") or "—")],
    ]
    t = Table(facts, colWidths=[1.6 * inch, 4.6 * inch])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), MUTED),
        ("TEXTCOLOR", (1, 0), (1, -1), INK),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, HAIRLINE),
        ("TEXTCOLOR", (1, 4), (1, 4), badge_color),
        ("FONTNAME", (1, 4), (1, 4), "Helvetica-Bold"),
    ]))
    out.append(t)
    out.append(Spacer(1, 24))

    out.append(Paragraph("Summary", S["h2"]))
    sev_line = (
        f"<b>{stats['findings_total']}</b> findings   ·   "
        f"<font color='{SEV_HIGH.hexval()}'><b>{stats['sev_high']}</b> high</font>   ·   "
        f"<font color='{SEV_MED.hexval()}'><b>{stats['sev_medium']}</b> medium</font>   ·   "
        f"<font color='{SEV_LOW.hexval()}'><b>{stats['sev_low']}</b> low</font>"
    )
    sev_line_para = Paragraph(sev_line, S["body"])
    cards = [
        ["Rules analyzed", _fmt_int(stats["rules_analyzed"])],
        ["Findings", sev_line_para],
        ["Rules with zero hits (30 d)", _fmt_int(stats["zero_hit"])],
        ["Estimated monthly waste", f"${int(stats['waste_usd']):,} / month"],
    ]
    ct = Table(cards, colWidths=[2.4 * inch, 3.8 * inch])
    ct.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica"),
        ("TEXTCOLOR", (0, 0), (0, -1), MUTED),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (-1, -1), ROW_ALT),
        ("BOX", (0, 0), (-1, -1), 0.4, HAIRLINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, HAIRLINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (1, 0), (1, -1), INK),
    ]))
    out.append(ct)
    out.append(Spacer(1, 16))
    out.append(_what_was_tested(audit_run, S))
    out.append(PageBreak())
    return out


def _what_was_tested(audit_run: Dict[str, Any],
                     S: Dict[str, ParagraphStyle]) -> Flowable:
    """Cover-page provenance callout — answers the security reader's first
    question ("how was this generated") before they read any findings."""
    log_window = audit_run.get("log_window_days") or 30
    log_source = audit_run.get("log_source") or "CloudWatch Logs"
    web_acl_count = audit_run.get("web_acl_count") or 0
    rule_count = audit_run.get("rule_count") or 0
    # Phase 5.2 — display BOTH scopes when both were scanned.
    scopes = audit_run.get("scopes") or []
    if scopes:
        scope = " + ".join(sorted(set(scopes)))
    else:
        scope = audit_run.get("scope") or "REGIONAL"

    header = Paragraph(
        "<font color='%s'><b>What was tested</b></font>" % MUTED.hexval(),
        S["body_small"],
    )
    pairs = [
        ["Log window",      f"{log_window} days"],
        ["Log source",      str(log_source)],
        ["Web ACLs scanned", _fmt_int(int(web_acl_count))],
        ["Rules analyzed",  _fmt_int(int(rule_count))],
        ["Scope",           str(scope)],
    ]
    inner = Table(pairs, colWidths=[1.6 * inch, 4.6 * inch])
    inner.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), MUTED),
        ("TEXTCOLOR", (1, 0), (1, -1), INK),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))

    wrapper = Table(
        [[header], [inner]],
        colWidths=[6.2 * inch],
    )
    wrapper.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), ROW_ALT),
        ("LINEABOVE", (0, 0), (-1, 0), 1.2, INK),
        ("LINEBELOW", (0, -1), (-1, -1), 0.4, HAIRLINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (0, 0), 8),
        ("BOTTOMPADDING", (0, 0), (0, 0), 4),
        ("TOPPADDING", (0, 1), (0, 1), 0),
        ("BOTTOMPADDING", (0, 1), (0, 1), 8),
    ]))
    return wrapper


def _rank_findings(findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def sev_score(f: Dict[str, Any]) -> int:
        try:
            return int(f.get("severity_score") or 0)
        except (TypeError, ValueError):
            return 0

    def conf(f: Dict[str, Any]) -> float:
        try:
            return float(f.get("confidence") or 0)
        except (TypeError, ValueError):
            return 0.0

    return sorted(findings, key=lambda f: (sev_score(f), conf(f)), reverse=True)


def _build_executive_summary(audit_run: Dict[str, Any],
                              findings: Sequence[Dict[str, Any]],
                              stats: Dict[str, Any],
                              S: Dict[str, ParagraphStyle]) -> List[Flowable]:
    out: List[Flowable] = []
    out.append(Paragraph("Executive Summary", S["h2"]))
    out.append(Paragraph(
        "Top findings ranked by severity and confidence. Full detail in the "
        "next section.",
        S["muted"],
    ))
    out.append(Spacer(1, 8))

    top = _rank_findings(findings)[:5]
    if not top:
        out.append(Paragraph(
            "No findings produced for this audit. The Web ACL is in a clean state.",
            S["body"],
        ))
    for i, f in enumerate(top, start=1):
        sev = (f.get("severity") or "low").lower()
        title = f.get("title") or "(untitled finding)"
        desc = f.get("description") or ""
        rec = f.get("recommendation") or ""
        block = [
            Paragraph(f"<b>{i}.  {title}</b>", S["h3"]),
            Paragraph(
                f"<font color='{SEV_COLOR.get(sev, SEV_LOW).hexval()}'>"
                f"<b>{sev.upper()}</b></font> &nbsp; "
                f"<font color='{MUTED.hexval()}'>"
                f"score {f.get('severity_score', 0)}  ·  confidence "
                f"{int(round(float(f.get('confidence') or 0) * 100))}%</font>",
                S["body_small"],
            ),
            Paragraph(desc, S["body"]),
            Paragraph(f"<b>Recommendation.</b> {rec}", S["body"]),
            Spacer(1, 8),
        ]
        out.append(KeepTogether(block))

    out.append(PageBreak())
    return out


def _build_findings_detail(rules: Sequence[Dict[str, Any]],
                           findings: Sequence[Dict[str, Any]],
                           S: Dict[str, ParagraphStyle]) -> List[Flowable]:
    out: List[Flowable] = []
    out.append(Paragraph("Findings Detail", S["h2"]))

    fms_set = {r.get("rule_name") for r in rules if r.get("fms_managed")}
    grouped: Dict[str, List[Dict[str, Any]]] = {t: [] for t in TYPE_ORDER}
    for f in findings:
        t = f.get("type") or "quick_win"
        grouped.setdefault(t, []).append(f)

    any_emitted = False
    for ftype in TYPE_ORDER:
        bucket = grouped.get(ftype) or []
        if not bucket:
            continue
        any_emitted = True
        out.append(Paragraph(f"{TYPE_LABEL[ftype]} ({len(bucket)})", S["h3"]))
        for f in _rank_findings(bucket):
            out.append(_render_finding(f, fms_set, S))
            out.append(Spacer(1, 6))
        out.append(Spacer(1, 4))

    if not any_emitted:
        out.append(Paragraph("No findings produced for this audit.", S["body"]))
    out.append(PageBreak())
    return out


def _render_finding(f: Dict[str, Any], fms_set: set,
                    S: Dict[str, ParagraphStyle]) -> Flowable:
    sev = (f.get("severity") or "low").lower()
    title = f.get("title") or "(untitled finding)"
    desc = f.get("description") or ""
    rec = f.get("recommendation") or ""
    affected = f.get("affected_rules") or []

    chips: List[str] = []
    for name in affected:
        safe = str(name)
        if safe in fms_set:
            chips.append(
                f"<b>{safe}</b> "
                f"<font color='{ACCENT.hexval()}' size=7>"
                "[FMS-managed — review only, do not auto-remove]</font>"
            )
        else:
            chips.append(f"<b>{safe}</b>")
    affected_html = ", ".join(chips) if chips else "—"

    sev_score = f.get("severity_score", 0)
    conf_pct = int(round(float(f.get("confidence") or 0) * 100))

    inner = [
        Paragraph(f"<b>{title}</b>", S["body"]),
        Paragraph(
            f"<font color='{SEV_COLOR.get(sev, SEV_LOW).hexval()}'>"
            f"<b>{sev.upper()}</b></font>"
            f" &nbsp; <font color='{MUTED.hexval()}'>"
            f"score {sev_score}  ·  confidence {conf_pct}%</font>",
            S["body_small"],
        ),
        Paragraph(desc, S["body_small"]),
        Paragraph(f"<b>Recommendation.</b> {rec}", S["body_small"]),
        Paragraph(
            f"<font color='{MUTED.hexval()}'>Affected:</font> {affected_html}",
            S["body_small"],
        ),
    ]
    bar = _SeverityBar(sev, height=12 * len(inner))
    row = Table(
        [[bar, inner]],
        colWidths=[0.12 * inch, 6.0 * inch],
    )
    row.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (1, 0), (1, 0), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("BACKGROUND", (0, 0), (-1, -1), ROW_ALT),
        ("BOX", (0, 0), (-1, -1), 0.4, HAIRLINE),
    ]))
    return KeepTogether(row)


def _rule_status(rule: Dict[str, Any]) -> str:
    if rule.get("fms_managed"):
        return "FMS-managed"
    if int(rule.get("hit_count") or 0) > 0:
        return "Active"
    return "Dead"


def _fmt_last_fired(value: Any) -> str:
    """Stable ISO short form: 2025-01-15 14:32 UTC. No relative times."""
    if not value:
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    s = str(value).strip()
    if not s:
        return ""
    # Normalize ISO Zulu strings → "YYYY-MM-DD HH:MM UTC"
    try:
        # Accept "2026-04-30T14:23:11Z" / with offsets / with microseconds.
        normalized = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return s


def _build_web_acl_section(audit_run: Dict[str, Any],
                           S: Dict[str, ParagraphStyle]) -> List[Flowable]:
    """Phase 5 — render the Web ACL attachment table.

    Empty / missing `web_acls` ⇒ nothing emitted (e.g. older audit runs).
    """
    web_acls = audit_run.get("web_acls") or []
    if not web_acls:
        return []
    out: List[Flowable] = []
    out.append(Paragraph("Web ACL Attachment", S["h2"]))
    out.append(Paragraph(
        "Web ACLs scanned in this audit. Orphaned ACLs (no attached "
        "resources) protect nothing and incur the fixed monthly fee.",
        S["muted"],
    ))
    out.append(Spacer(1, 6))

    cell = ParagraphStyle(
        "wacl_cell", parent=S["body_small"], fontSize=9, leading=11,
        textColor=INK_SOFT, fontName="Helvetica",
    )
    cell_bold = ParagraphStyle(
        "wacl_cell_b", parent=cell, fontName="Helvetica-Bold", textColor=INK,
    )
    cell_orphan = ParagraphStyle(
        "wacl_cell_o", parent=cell_bold, textColor=SEV_HIGH,
    )
    header_style = ParagraphStyle(
        "wacl_header", parent=cell, fontName="Helvetica-Bold",
        textColor=colors.white, fontSize=9,
    )

    rows: List[List[Any]] = [[
        Paragraph("Web ACL", header_style),
        Paragraph("Scope", header_style),
        Paragraph("Attached Resources", header_style),
        Paragraph("Status", header_style),
    ]]
    orphan_idx: List[int] = []
    for i, acl in enumerate(web_acls, start=1):
        attached = acl.get("attached")
        resources = acl.get("attached_resources") or []
        if attached is True:
            status_para = Paragraph("Attached", cell_bold)
            resource_text = _fmt_int(len(resources)) + " resource(s)"
        elif attached is False:
            orphan_idx.append(i)
            status_para = Paragraph("ORPHANED", cell_orphan)
            resource_text = "none"
        else:  # None — unknown (AccessDenied / CloudFront unreliable)
            status_para = Paragraph("Unknown", cell_bold)
            resource_text = "could not verify"
        rows.append([
            Paragraph(str(acl.get("name") or "—"), cell_bold),
            Paragraph(str(acl.get("scope") or "REGIONAL"), cell),
            Paragraph(resource_text, cell),
            status_para,
        ])

    table = Table(
        rows,
        colWidths=[2.7 * inch, 1.0 * inch, 2.1 * inch, 1.7 * inch],
        repeatRows=1,
    )
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 7),
        ("TOPPADDING", (0, 0), (-1, 0), 7),
        ("FONTSIZE", (0, 1), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, HAIRLINE),
        ("BOX", (0, 0), (-1, -1), 0.4, HAIRLINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 1), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
    ]
    for i in orphan_idx:
        style_cmds.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fef2f2")))
    table.setStyle(TableStyle(style_cmds))
    out.append(table)
    out.append(Spacer(1, 16))
    return out


def _build_inventory_table(rules: Sequence[Dict[str, Any]],
                            S: Dict[str, ParagraphStyle]) -> List[Flowable]:
    out: List[Flowable] = []
    out.append(Paragraph("Rule Inventory", S["h2"]))
    out.append(Paragraph(
        f"All {len(rules)} rule(s) seen during this audit, sorted by web ACL "
        "and priority.",
        S["muted"],
    ))
    out.append(Spacer(1, 6))

    # Cell paragraph styles — slightly tighter so wrap doesn't blow row height.
    cell_style = ParagraphStyle(
        "cell", parent=S["body_small"], fontSize=8.5, leading=10.5,
        textColor=INK_SOFT, fontName="Helvetica",
    )
    cell_style_bold = ParagraphStyle(
        "cell_bold", parent=cell_style, fontName="Helvetica-Bold", textColor=INK,
    )
    header_style = ParagraphStyle(
        "cell_header", parent=cell_style, fontName="Helvetica-Bold",
        textColor=colors.white, fontSize=9,
    )

    rows: List[List[Any]] = [[
        Paragraph("Rule Name", header_style),
        Paragraph("Web ACL", header_style),
        Paragraph("Hits (30d)", header_style),
        Paragraph("Last Fired", header_style),
        Paragraph("Mode", header_style),
        Paragraph("Status", header_style),
    ]]

    sorted_rules = sorted(
        rules,
        key=lambda r: (r.get("web_acl_name") or "", int(r.get("priority") or 0)),
    )
    total_hits = 0
    never_fired_idx: List[int] = []
    fms_idx: List[int] = []

    for i, r in enumerate(sorted_rules, start=1):
        name = str(r.get("rule_name") or "—")
        acl = str(r.get("web_acl_name") or "—")
        hits = int(r.get("hit_count") or 0)
        total_hits += hits
        last = r.get("last_fired")
        if not last or hits == 0:
            never_fired_idx.append(i)
            last_cell = "Never fired"
        else:
            last_cell = _fmt_last_fired(last)
        mode = str(r.get("action") or "—")
        # Phase 5 production fix: preserve case so "Block (group)" /
        # "Count (override)" don't get upper-cased into noise.
        if mode in ("ALLOW", "BLOCK", "COUNT", "CAPTCHA", "CHALLENGE"):
            mode = mode.upper()
        status = _rule_status(r)
        if status == "FMS-managed":
            fms_idx.append(i)

        rows.append([
            Paragraph(name, cell_style_bold),
            Paragraph(acl, cell_style),
            _fmt_int(hits),
            last_cell,
            mode,
            status,
        ])

    rows.append([
        Paragraph("TOTAL", cell_style_bold),
        "",
        _fmt_int(total_hits),
        "",
        "",
        f"{len(rules)} rules",
    ])

    # Total page width = LETTER 8.5" - margins 0.5"+0.5" = 7.5".
    # Allocations: Rule Name 30%, Web ACL 17%, Hits 9%, Last Fired 21%,
    # Mode 9%, Status 14%.
    col_widths = [
        2.25 * inch,   # Rule Name (30%)
        1.275 * inch,  # Web ACL (17%)
        0.675 * inch,  # Hits (9%)
        1.575 * inch,  # Last Fired (21%, fits "2026-01-15 14:32 UTC")
        0.675 * inch,  # Mode (9%)
        1.05 * inch,   # Status (14%)
    ]

    table = Table(rows, colWidths=col_widths, repeatRows=1)
    style = TableStyle([
        # header
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        # body
        ("FONTSIZE", (0, 1), (-1, -1), 8.5),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("TEXTCOLOR", (0, 1), (-1, -1), INK_SOFT),
        ("ALIGN", (2, 1), (2, -1), "RIGHT"),  # Hits column
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, HAIRLINE),
        ("BOX", (0, 0), (-1, -1), 0.4, HAIRLINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 1), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
        # alternating row tint (skip header & total row)
        *[
            ("BACKGROUND", (0, i), (-1, i), ROW_ALT)
            for i in range(2, len(rows) - 1, 2)
        ],
        # Never-fired → red text in Last Fired col
        *[
            ("TEXTCOLOR", (3, i), (3, i), SEV_HIGH)
            for i in never_fired_idx
        ],
        # FMS-managed accent in Status col
        *[
            ("TEXTCOLOR", (5, i), (5, i), ACCENT)
            for i in fms_idx
        ],
        # Total row
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("LINEABOVE", (0, -1), (-1, -1), 0.6, INK),
        ("BACKGROUND", (0, -1), (-1, -1), colors.white),
    ])
    table.setStyle(style)
    out.append(table)
    return out


# ---- Public entry point ------------------------------------------------------


def _build_observed_gaps_section(audit_run: Dict[str, Any],
                                  findings: Sequence[Dict[str, Any]],
                                  S: Dict[str, ParagraphStyle]) -> List[Flowable]:
    """Phase 5.5 — surface the audit-time evidence sample.

    Pulls `suspicious_request_sample` off the audit run and renders the
    top-N attack-shaped ALLOW requests that reached the origin during the
    audit window. This is the *evidence* that drove every
    `bypass_candidate` finding tagged `evidence='log-sample'` — having it
    in the PDF gives the reviewer a one-glance answer to "why does the AI
    think a bypass happened?"

    Empty sample (no real-traffic audit, or no events scored above
    threshold) ⇒ section omitted entirely.
    """
    sample = audit_run.get("suspicious_request_sample") or []
    bypass_findings = [
        f for f in findings if f.get("type") == "bypass_candidate"
    ]
    if not sample and not bypass_findings:
        return []
    out: List[Flowable] = []
    out.append(Paragraph("Observed WAF Gaps", S["h2"]))
    out.append(Paragraph(
        "Attack-shaped requests that reached the origin (action=ALLOW, "
        "response 2xx/3xx) during the audit window. Each row is the "
        "primary evidence behind a 'bypass candidate' finding.",
        S["muted"],
    ))
    out.append(Spacer(1, 6))

    if not sample:
        out.append(Paragraph(
            "No suspicious-allow samples observed. Bypass findings below were "
            "produced from rule statistics alone (no log-sample evidence).",
            S["muted"],
        ))
        out.append(Spacer(1, 12))
        return out

    cell = ParagraphStyle(
        "gap_cell", parent=S["body_small"], fontSize=8, leading=10,
        textColor=INK_SOFT, fontName="Helvetica",
    )
    cell_mono = ParagraphStyle(
        "gap_mono", parent=cell, fontName="Courier", fontSize=7.5,
        textColor=INK,
    )
    cell_score = ParagraphStyle(
        "gap_score", parent=cell, fontName="Helvetica-Bold",
        textColor=SEV_HIGH,
    )
    header_style = ParagraphStyle(
        "gap_header", parent=cell, fontName="Helvetica-Bold",
        textColor=colors.white, fontSize=8,
    )

    rows: List[List[Any]] = [[
        Paragraph("Score", header_style),
        Paragraph("URI", header_style),
        Paragraph("Signature", header_style),
        Paragraph("User-Agent", header_style),
    ]]
    # Show top 10 (already sorted by score desc).
    for ev in sample[:10]:
        http = ev.get("httpRequest") or {}
        uri = (http.get("uri") or "")[:80]
        args = (http.get("args") or "").lower()
        headers = http.get("headers") or []
        ua = ""
        header_text_blob = ""
        for h in headers:
            v = (h.get("value") or "")
            if (h.get("name") or "").lower() == "user-agent":
                ua = v[:60]
            header_text_blob += " " + v.lower()
        signature = _classify_signature(uri.lower(), args, header_text_blob)
        rows.append([
            Paragraph(str(ev.get("_suspicion_score") or 0), cell_score),
            Paragraph(uri or "—", cell_mono),
            Paragraph(signature, cell),
            Paragraph(ua or "—", cell_mono),
        ])

    table = Table(
        rows,
        colWidths=[0.55 * inch, 2.85 * inch, 1.45 * inch, 2.65 * inch],
        repeatRows=1,
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, HAIRLINE),
        ("BOX", (0, 0), (-1, -1), 0.4, HAIRLINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#fff7ed")),
    ]))
    out.append(table)
    if len(sample) > 10:
        out.append(Spacer(1, 4))
        out.append(Paragraph(
            f"+{len(sample) - 10} additional sampled requests not shown "
            "(retained on the audit document for review).",
            S["muted"],
        ))
    out.append(Spacer(1, 16))
    return out


def _classify_signature(uri: str, args: str, header_blob: str) -> str:
    """One-line attack-class label for the PDF gap table."""
    if "() { :;}" in header_blob or "() {:;}" in header_blob:
        return "Shellshock"
    if "${jndi:" in header_blob or "${jndi:" in uri or "${jndi:" in args:
        return "Log4Shell / JNDI"
    if any(t in (uri + " " + args) for t in (
        "union+select", "union select", "' or '1'='1", "'; drop table"
    )):
        return "SQL Injection"
    if any(t in (uri + " " + args) for t in (
        "<script", "javascript:", "onerror=", "onload=",
    )):
        return "XSS"
    if any(t in uri for t in ("../", "..\\", "/etc/passwd", "/proc/self")):
        return "Path Traversal / LFI"
    if any(t in (uri + " " + args) for t in (
        "wget ", "curl ", "bash -c", "eval(", "system(",
    )):
        return "Command Injection"
    if any(uri.startswith(p) for p in (
        "/admin", "/.git", "/.env", "/wp-admin", "/cgi-bin/", "/phpmyadmin"
    )):
        return "Sensitive Path"
    return "Scanner / Recon"


def render_audit_pdf(
    audit_run: Dict[str, Any],
    rules: Sequence[Dict[str, Any]],
    findings: Sequence[Dict[str, Any]],
) -> bytes:
    """Render a full audit report. Returns raw PDF bytes."""
    buf = io.BytesIO()
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    doc = BaseDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=0.5 * inch,
        rightMargin=0.5 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.6 * inch,
        title="RuleIQ Audit Report",
        author="RuleIQ",
    )
    frame = Frame(
        doc.leftMargin,
        doc.bottomMargin,
        doc.width,
        doc.height,
        id="main",
        showBoundary=0,
    )
    doc.addPageTemplates([
        PageTemplate(
            id="default",
            frames=[frame],
            onPage=_make_footer(generated_at),
        )
    ])

    S = _styles()
    stats = _summary_stats(audit_run, rules, findings)

    story: List[Flowable] = []
    story += _build_cover(audit_run, stats, generated_at, S)
    story += _build_executive_summary(audit_run, findings, stats, S)
    story += _build_observed_gaps_section(audit_run, findings, S)
    story += _build_findings_detail(rules, findings, S)
    story += _build_web_acl_section(audit_run, S)
    story += _build_inventory_table(rules, S)

    doc.build(story)
    return buf.getvalue()
