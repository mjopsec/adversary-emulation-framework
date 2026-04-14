"""
PDF Report Generator — Enterprise Grade.

Menghasilkan laporan PDF berkualitas enterprise menggunakan ReportLab Platypus.
Fitur:
  - Cover page full-colour dengan logo, metadata, dan classification banner
  - Header/footer pada setiap halaman konten (nama dokumen, tanggal, halaman X/Y)
  - Warna navy + blue profesional, tipografi bersih
  - Metric highlight boxes untuk executive summary
  - Tabel dengan header navy, alternating rows, dan row-level status colouring
  - Sigma rule hints dalam code block mono
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ─── Color Palette ────────────────────────────────────────────────────────────

C_NAVY       = colors.HexColor("#0F1E3C")   # cover / section bg
C_NAVY_MED   = colors.HexColor("#1B2A4A")   # table header
C_NAVY_LIGHT = colors.HexColor("#243654")   # subtle bg
C_ACCENT     = colors.HexColor("#2563EB")   # brand blue
C_ACCENT_DARK= colors.HexColor("#1D4ED8")
C_WHITE      = colors.white
C_TEXT       = colors.HexColor("#111827")
C_TEXT_MED   = colors.HexColor("#374151")
C_TEXT_LIGHT = colors.HexColor("#9CA3AF")
C_BG         = colors.HexColor("#F9FAFB")
C_BG_ALT     = colors.HexColor("#F3F4F6")
C_BG_BLUE    = colors.HexColor("#EFF6FF")
C_LINE       = colors.HexColor("#E5E7EB")

# Status colours
C_SUCCESS    = colors.HexColor("#065F46")
C_SUCCESS_BG = colors.HexColor("#D1FAE5")
C_WARNING    = colors.HexColor("#92400E")
C_WARNING_BG = colors.HexColor("#FFFBEB")
C_DANGER     = colors.HexColor("#991B1B")
C_DANGER_BG  = colors.HexColor("#FEE2E2")
C_INFO       = colors.HexColor("#1E40AF")
C_INFO_BG    = colors.HexColor("#DBEAFE")
C_PURPLE     = colors.HexColor("#4C1D95")
C_PURPLE_BG  = colors.HexColor("#EDE9FE")

PAGE_W, PAGE_H = A4
LM = 2.0 * cm
RM = 2.0 * cm
TM = 2.8 * cm   # extra space for header
BM = 2.2 * cm   # extra space for footer
CONTENT_W = PAGE_W - LM - RM


# ─── Numbered Canvas ("Page X of Y") ─────────────────────────────────────────

class _NumberedCanvas(rl_canvas.Canvas):
    """Canvas subclass that supports 'Page X of Y' in the footer."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict] = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_page_states)
        for i, state in enumerate(self._saved_page_states):
            self.__dict__.update(state)
            page_num = i + 1
            if page_num > 1:          # skip cover page
                self.setFont("Helvetica", 7)
                self.setFillColor(C_TEXT_LIGHT)
                self.drawRightString(
                    PAGE_W - RM,
                    BM - 0.5 * cm,
                    f"Page {page_num} of {total}",
                )
            rl_canvas.Canvas.showPage(self)
        rl_canvas.Canvas.save(self)


# ─── Cover Page (Canvas Drawing) ─────────────────────────────────────────────

def _draw_cover(
    canv: rl_canvas.Canvas,
    doc: Any,
    title: str,
    doc_type: str,
    meta: list[tuple[str, str]],
    gen_date: str,
) -> None:
    """Draw a full-page enterprise cover using direct canvas operations."""
    canv.saveState()

    # ── Background ──────────────────────────────────────────────────────────
    canv.setFillColor(C_NAVY)
    canv.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

    # Right accent bar
    canv.setFillColor(C_ACCENT)
    canv.rect(PAGE_W - 1.1 * cm, 0, 1.1 * cm, PAGE_H, fill=1, stroke=0)

    # Top accent stripe
    canv.setFillColor(C_ACCENT)
    canv.rect(0, PAGE_H - 0.9 * cm, PAGE_W - 1.1 * cm, 0.9 * cm, fill=1, stroke=0)

    # ── Logo / Brand Block ──────────────────────────────────────────────────
    bx, by = LM, PAGE_H - 2.6 * cm
    # Circle logo
    canv.setFillColor(C_ACCENT)
    canv.circle(bx + 0.65 * cm, by + 0.3 * cm, 0.6 * cm, fill=1, stroke=0)
    canv.setFillColor(C_WHITE)
    canv.setFont("Helvetica-Bold", 8)
    canv.drawCentredString(bx + 0.65 * cm, by + 0.08 * cm, "AEP")

    # Brand text
    canv.setFont("Helvetica-Bold", 9)
    canv.setFillColor(colors.HexColor("#93C5FD"))
    canv.drawString(bx + 1.6 * cm, by + 0.45 * cm, "ADVERSARY EMULATION PLATFORM")
    canv.setFont("Helvetica", 7.5)
    canv.setFillColor(colors.HexColor("#60A5FA"))
    canv.drawString(bx + 1.6 * cm, by + 0.13 * cm, "Red Team Operations & Detection Analysis")

    # Separator
    sep_y = by - 0.7 * cm
    canv.setStrokeColor(colors.HexColor("#1E3A5F"))
    canv.setLineWidth(0.6)
    canv.line(LM, sep_y, PAGE_W - RM - 1.3 * cm, sep_y)

    # ── Document Type Label ─────────────────────────────────────────────────
    canv.setFont("Helvetica-Bold", 7.5)
    canv.setFillColor(colors.HexColor("#93C5FD"))
    canv.drawString(LM, sep_y - 0.8 * cm, doc_type.upper())

    # ── Main Title ──────────────────────────────────────────────────────────
    title_y = sep_y - 1.8 * cm
    max_w = PAGE_W - LM - RM - 1.5 * cm
    canv.setFont("Helvetica-Bold", 24)
    canv.setFillColor(C_WHITE)

    # Manual word-wrap for long titles
    title_lines: list[str] = []
    words = title.split()
    current = ""
    for w in words:
        test = (current + " " + w).strip()
        if canv.stringWidth(test, "Helvetica-Bold", 24) <= max_w:
            current = test
        else:
            if current:
                title_lines.append(current)
            current = w
    if current:
        title_lines.append(current)

    for line in title_lines:
        canv.drawString(LM, title_y, line)
        title_y -= 1.0 * cm

    # Blue underline accent
    title_y -= 0.15 * cm
    canv.setStrokeColor(C_ACCENT)
    canv.setLineWidth(2.5)
    canv.line(LM, title_y, LM + 2.8 * cm, title_y)

    # ── Metadata Grid ───────────────────────────────────────────────────────
    meta_top_y = title_y - 1.6 * cm
    col_w = max_w / 2
    row_h = 1.05 * cm

    for i, (label, value) in enumerate(meta):
        col = i % 2
        row = i // 2
        x = LM + col * col_w
        y = meta_top_y - row * row_h

        canv.setFont("Helvetica-Bold", 7)
        canv.setFillColor(colors.HexColor("#93C5FD"))
        canv.drawString(x, y, label.upper())
        canv.setFont("Helvetica", 9)
        canv.setFillColor(C_WHITE)
        canv.drawString(x, y - 0.35 * cm, str(value)[:45])

    # ── Classification Banner ───────────────────────────────────────────────
    banner_h = 1.0 * cm
    canv.setFillColor(colors.HexColor("#0A1628"))
    canv.rect(0, 0, PAGE_W, banner_h, fill=1, stroke=0)
    # Top border of banner
    canv.setFillColor(colors.HexColor("#1E3A5F"))
    canv.rect(0, banner_h, PAGE_W, 0.5, fill=1, stroke=0)

    canv.setFont("Helvetica-Bold", 8)
    canv.setFillColor(colors.HexColor("#FCA5A5"))
    canv.drawCentredString(
        (PAGE_W - 1.1 * cm) / 2,
        banner_h / 2 + 0.05 * cm,
        "CONFIDENTIAL  —  FOR AUTHORIZED PERSONNEL ONLY",
    )
    canv.setFont("Helvetica", 7)
    canv.setFillColor(colors.HexColor("#6B7280"))
    canv.drawString(LM, 0.2 * cm, f"Generated: {gen_date}")

    canv.restoreState()


# ─── Header / Footer (Content Pages) ─────────────────────────────────────────

def _draw_content_page(
    canv: rl_canvas.Canvas,
    doc: Any,
    doc_title: str,
    gen_date: str,
) -> None:
    """Draw header and footer on every content page (page > 1)."""
    if doc.page == 1:
        return

    canv.saveState()

    hx  = LM
    hx2 = PAGE_W - RM

    # ── Header ──────────────────────────────────────────────────────────────
    # Accent stripe at very top
    canv.setFillColor(C_ACCENT)
    canv.rect(0, PAGE_H - 3.5 * mm, PAGE_W, 3.5 * mm, fill=1, stroke=0)

    # Platform label (left)
    hy = PAGE_H - TM + 0.55 * cm
    canv.setFont("Helvetica-Bold", 7.5)
    canv.setFillColor(C_NAVY)
    canv.drawString(hx, hy, "ADVERSARY EMULATION PLATFORM")

    # Document title (left, smaller)
    canv.setFont("Helvetica", 7)
    canv.setFillColor(C_TEXT_LIGHT)
    canv.drawString(hx, hy - 0.3 * cm, doc_title[:70])

    # CONFIDENTIAL badge (right)
    badge_w = 2.2 * cm
    badge_x = hx2 - badge_w
    badge_y = hy - 0.15 * cm
    canv.setFillColor(C_DANGER_BG)
    canv.roundRect(badge_x, badge_y, badge_w, 0.42 * cm, 2, fill=1, stroke=0)
    canv.setFont("Helvetica-Bold", 6.5)
    canv.setFillColor(C_DANGER)
    canv.drawCentredString(badge_x + badge_w / 2, badge_y + 0.11 * cm, "CONFIDENTIAL")

    # Header rule
    canv.setStrokeColor(C_LINE)
    canv.setLineWidth(0.5)
    canv.line(hx, PAGE_H - TM + 0.02 * cm, hx2, PAGE_H - TM + 0.02 * cm)

    # ── Footer ──────────────────────────────────────────────────────────────
    fy = BM - 0.42 * cm

    # Footer rule
    canv.setStrokeColor(C_LINE)
    canv.setLineWidth(0.5)
    canv.line(hx, fy + 0.28 * cm, hx2, fy + 0.28 * cm)

    canv.setFont("Helvetica", 7)
    canv.setFillColor(C_TEXT_LIGHT)
    canv.drawString(hx, fy, "For Authorized Personnel Only — Do Not Distribute")
    canv.drawCentredString(PAGE_W / 2, fy, gen_date)
    # Page number is rendered by _NumberedCanvas.save()

    canv.restoreState()


# ─── Style Definitions ────────────────────────────────────────────────────────

def _styles() -> dict:
    return {
        "section": ParagraphStyle(
            "section", fontSize=13, textColor=C_NAVY,
            fontName="Helvetica-Bold", spaceBefore=20, spaceAfter=5, leading=16,
        ),
        "subsection": ParagraphStyle(
            "subsection", fontSize=10, textColor=C_NAVY_MED,
            fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body", fontSize=9, textColor=C_TEXT_MED,
            fontName="Helvetica", spaceAfter=4, leading=13,
        ),
        "caption": ParagraphStyle(
            "caption", fontSize=7.5, textColor=C_TEXT_LIGHT,
            fontName="Helvetica", spaceAfter=3,
        ),
        "mono": ParagraphStyle(
            "mono", fontSize=7, textColor=colors.HexColor("#D1FAE5"),
            fontName="Courier",
            backColor=colors.HexColor("#0D1F2D"),
            leading=10.5, spaceAfter=2, spaceBefore=2,
            leftIndent=8, rightIndent=8,
        ),
        "tag_detected": ParagraphStyle(
            "tag_d", fontSize=7.5, textColor=C_SUCCESS, fontName="Helvetica-Bold",
        ),
        "tag_gap": ParagraphStyle(
            "tag_g", fontSize=7.5, textColor=C_DANGER, fontName="Helvetica-Bold",
        ),
    }


# ─── Table Style Helper ───────────────────────────────────────────────────────

def _tbl(col_widths: list[float], data: list, extra: list | None = None) -> Table:
    """Build a styled enterprise table."""
    cmds = [
        # Header
        ("BACKGROUND",    (0, 0), (-1, 0), C_NAVY_MED),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 7.5),
        ("TOPPADDING",    (0, 0), (-1, 0), 7),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 7),
        ("LEFTPADDING",   (0, 0), (-1, 0), 8),
        ("RIGHTPADDING",  (0, 0), (-1, 0), 8),
        # Data rows
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("TEXTCOLOR",     (0, 1), (-1, -1), C_TEXT_MED),
        ("TOPPADDING",    (0, 1), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
        ("LEFTPADDING",   (0, 1), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 1), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        # Alternating rows
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_BG_ALT]),
        # Borders
        ("LINEBELOW",     (0, 0), (-1, 0), 0.5, colors.HexColor("#3B5998")),
        ("LINEBELOW",     (0, 1), (-1, -2), 0.3, C_LINE),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_LINE),
    ]
    if extra:
        cmds.extend(extra)
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle(cmds))
    return t


def _metric_row(metrics: list[tuple[str, str, Any, Any]]) -> Table:
    """
    Build a row of metric highlight boxes.
    Each tuple: (label, value, fg_color, bg_color)
    """
    cells = []
    for label, value, fg, bg in metrics:
        val_style = ParagraphStyle(
            "mv", fontSize=20, textColor=fg or C_NAVY,
            fontName="Helvetica-Bold", leading=24, spaceAfter=1,
        )
        lbl_style = ParagraphStyle(
            "ml", fontSize=7.5, textColor=C_TEXT_LIGHT, fontName="Helvetica", leading=10,
        )
        cells.append([Paragraph(value, val_style), Paragraph(label, lbl_style)])

    # Stack each metric vertically in its own inner table
    inner_tables = []
    box_w = CONTENT_W / len(metrics) - 0.2 * cm
    for label, value, fg, bg in metrics:
        val_style = ParagraphStyle(
            "mv2", fontSize=18, textColor=fg or C_NAVY,
            fontName="Helvetica-Bold", leading=22, spaceAfter=2, alignment=TA_CENTER,
        )
        lbl_style = ParagraphStyle(
            "ml2", fontSize=7.5, textColor=C_TEXT_LIGHT, fontName="Helvetica",
            leading=10, alignment=TA_CENTER,
        )
        inner = Table(
            [[Paragraph(value, val_style)], [Paragraph(label, lbl_style)]],
            colWidths=[box_w],
        )
        inner.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), bg or C_BG_BLUE),
            ("TOPPADDING",    (0, 0), (-1, 0), 12),
            ("BOTTOMPADDING", (0, -1), (-1, -1), 10),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("BOX",           (0, 0), (-1, -1), 0.5, C_LINE),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("LINEABOVE",     (0, 0), (-1, 0), 2.5, fg or C_ACCENT),
        ]))
        inner_tables.append(inner)

    row_tbl = Table(
        [inner_tables],
        colWidths=[box_w + 0.2 * cm] * len(metrics),
        hAlign="LEFT",
    )
    row_tbl.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING",   (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
    ]))
    return row_tbl


def _section(text: str, s: dict) -> list:
    """Return section header flowables (title + accent rule)."""
    return [
        Paragraph(text, s["section"]),
        HRFlowable(width="100%", thickness=1.5, color=C_ACCENT, spaceAfter=8),
    ]


def _severity_colors(sev: str) -> tuple:
    return {
        "critical": (C_NAVY, C_WHITE),
        "high":     (C_DANGER_BG, C_DANGER),
        "medium":   (C_WARNING_BG, C_WARNING),
        "low":      (C_SUCCESS_BG, C_SUCCESS),
    }.get((sev or "").lower(), (C_BG, C_TEXT_LIGHT))


# ─── Campaign PDF ─────────────────────────────────────────────────────────────

def generate_campaign_pdf(report_data: dict) -> bytes:
    """Generate enterprise-grade campaign PDF report."""
    buf = io.BytesIO()
    now = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")

    campaign = report_data.get("campaign", {})
    summary  = report_data.get("summary", {})
    findings = report_data.get("findings", [])
    path     = report_data.get("attack_path", [])
    recs     = report_data.get("recommendations", [])

    camp_name = campaign.get("name", "Campaign Report")

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=LM, rightMargin=RM,
        topMargin=TM, bottomMargin=BM,
        title=camp_name,
        author="Adversary Emulation Platform",
        subject="Red Team Campaign Report",
    )

    def on_first(canv, doc_):
        _draw_cover(
            canv, doc_,
            title=camp_name,
            doc_type="Adversary Emulation Report",
            meta=[
                ("Client",      campaign.get("client", "—")),
                ("Engagement",  campaign.get("engagement_type", "—").title()),
                ("Environment", campaign.get("environment_type", "—").upper()),
                ("Status",      campaign.get("status", "—").upper()),
                ("Start Date",  (campaign.get("start_date") or "—")[:10]),
                ("Generated",   now),
            ],
            gen_date=now,
        )

    def on_later(canv, doc_):
        _draw_content_page(canv, doc_, camp_name, now)

    s = _styles()
    story: list[Any] = [PageBreak()]   # page 1 = cover (drawn by on_first)

    # ── Executive Summary ──────────────────────────────────────────────────────
    story.extend(_section("Executive Summary", s))

    total_exec = summary.get("total_techniques_executed", 0)
    detected   = summary.get("detected", 0)
    det_rate   = summary.get("detection_rate_percent", 0)
    gap_count  = sum(summary.get("gaps_by_severity", {}).values())

    # Metric highlight row
    story.append(_metric_row([
        ("Techniques Executed", str(total_exec), C_NAVY,    C_BG_BLUE),
        ("Detected",            str(detected),   C_SUCCESS, C_SUCCESS_BG),
        ("Detection Gaps",      str(gap_count),  C_DANGER,  C_DANGER_BG),
        ("Detection Rate",      f"{det_rate}%",
            C_SUCCESS if det_rate >= 70 else C_WARNING if det_rate >= 40 else C_DANGER,
            C_SUCCESS_BG if det_rate >= 70 else C_WARNING_BG if det_rate >= 40 else C_DANGER_BG,
        ),
    ]))
    story.append(Spacer(1, 0.5 * cm))

    # Summary table
    story.append(Paragraph("Engagement Overview", s["subsection"]))
    eng_data = [
        ["Parameter", "Value"],
        ["Campaign Name",       camp_name],
        ["Client",              campaign.get("client", "—")],
        ["Engagement Type",     campaign.get("engagement_type", "—").title()],
        ["Environment",         campaign.get("environment_type", "—").upper()],
        ["Production Safe Mode",
            "Enabled" if campaign.get("production_safe_mode") else "Disabled"],
        ["Emergency Contact",   campaign.get("emergency_contact") or "—"],
        ["Status",              campaign.get("status", "—").upper()],
    ]
    story.append(_tbl([6 * cm, CONTENT_W - 6 * cm], eng_data))
    story.append(Spacer(1, 0.4 * cm))

    # Gaps by severity
    gaps_by_sev = summary.get("gaps_by_severity", {})
    if gaps_by_sev:
        story.append(Paragraph("Detection Gaps by Severity", s["subsection"]))
        sev_data = [["Severity", "Gap Count", "Risk Level"]]
        risk_map = {"critical": "Critical Risk", "high": "High Risk",
                    "medium": "Medium Risk", "low": "Low Risk"}
        extra_cmds = []
        for i, (sev, cnt) in enumerate(
            sorted(gaps_by_sev.items(), key=lambda x: ["critical","high","medium","low"].index(x[0])
                   if x[0] in ["critical","high","medium","low"] else 99), start=1
        ):
            bg, fg = _severity_colors(sev)
            sev_data.append([sev.title(), str(cnt), risk_map.get(sev, "—")])
            extra_cmds += [
                ("BACKGROUND", (0, i), (0, i), bg),
                ("TEXTCOLOR",  (0, i), (0, i), fg),
                ("FONTNAME",   (0, i), (0, i), "Helvetica-Bold"),
            ]
        story.append(_tbl(
            [4 * cm, 3 * cm, CONTENT_W - 7 * cm], sev_data, extra_cmds,
        ))

    story.append(PageBreak())

    # ── Execution Timeline ─────────────────────────────────────────────────────
    if path:
        story.extend(_section("Execution Timeline", s))
        story.append(Paragraph(
            f"Chronological record of {len(path)} technique executions during this engagement.",
            s["body"],
        ))
        story.append(Spacer(1, 0.2 * cm))

        ex_data = [["#", "Technique ID", "Technique Name", "Target", "Status", "Duration"]]
        extra_cmds = []
        for i, ex in enumerate(path, 1):
            status = ex.get("status", "—")
            bg_map = {"success": C_SUCCESS_BG, "failed": C_DANGER_BG, "simulated": C_INFO_BG}
            fg_map = {"success": C_SUCCESS, "failed": C_DANGER, "simulated": C_INFO}
            ex_data.append([
                str(i),
                ex.get("technique_id", ""),
                Paragraph((ex.get("technique_name") or "")[:40], ParagraphStyle(
                    "tn", fontSize=8, textColor=C_TEXT_MED, fontName="Helvetica", leading=10,
                )),
                Paragraph((ex.get("target") or "—")[:22], ParagraphStyle(
                    "tg", fontSize=8, textColor=C_TEXT_LIGHT, fontName="Helvetica", leading=10,
                )),
                Paragraph(status.title(), ParagraphStyle(
                    "st", fontSize=7.5, textColor=fg_map.get(status, C_TEXT_LIGHT),
                    fontName="Helvetica-Bold", leading=10,
                )),
                f"{ex.get('duration_seconds', 0) or 0:.1f}s"
                    if ex.get("duration_seconds") else "—",
            ])
            if status in bg_map:
                extra_cmds.append(("BACKGROUND", (4, i), (4, i), bg_map[status]))

        story.append(_tbl(
            [0.7*cm, 2.3*cm, 5.3*cm, 3.0*cm, 1.9*cm, 1.8*cm],
            ex_data, extra_cmds,
        ))
        story.append(PageBreak())

    # ── Findings & Gaps ────────────────────────────────────────────────────────
    if findings:
        story.extend(_section("Findings & Detection Gaps", s))
        story.append(Paragraph(
            "Rows highlighted in red indicate techniques that were NOT detected by defensive controls "
            "and represent actionable detection gaps.",
            s["body"],
        ))
        story.append(Spacer(1, 0.2 * cm))

        f_data = [["Technique", "Severity", "Detected", "Quality", "Description"]]
        extra_cmds = []
        for i, f in enumerate(findings, 1):
            is_gap = not f.get("detected", True)
            detected_txt = "Yes" if f.get("detected") else "No"
            det_style = ParagraphStyle(
                "det", fontSize=7.5, fontName="Helvetica-Bold",
                textColor=C_SUCCESS if f.get("detected") else C_DANGER, leading=10,
            )
            f_data.append([
                Paragraph(f.get("technique_id", ""), ParagraphStyle(
                    "ti", fontSize=8, textColor=C_ACCENT, fontName="Helvetica-Bold", leading=10,
                )),
                f.get("severity", "—").title(),
                Paragraph(detected_txt, det_style),
                f.get("detection_quality", "—"),
                Paragraph((f.get("gap_description") or "—")[:80], ParagraphStyle(
                    "gd", fontSize=7.5, textColor=C_TEXT_MED, fontName="Helvetica", leading=10,
                )),
            ])
            if is_gap:
                extra_cmds += [
                    ("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FFF5F5")),
                    ("LINEABOVE",  (0, i), (-1, i), 0.3, colors.HexColor("#FECACA")),
                    ("LINEBELOW",  (0, i), (-1, i), 0.3, colors.HexColor("#FECACA")),
                ]
        story.append(_tbl(
            [2.5*cm, 2.0*cm, 1.8*cm, 2.2*cm, CONTENT_W - 8.5*cm],
            f_data, extra_cmds,
        ))

    # ── Sigma Rule Hints ───────────────────────────────────────────────────────
    gap_findings = [f for f in findings if not f.get("detected") and f.get("sigma_rule")]
    if gap_findings:
        story.append(PageBreak())
        story.extend(_section("Sigma Rule Hints for Undetected Techniques", s))
        story.append(Paragraph(
            "The following Sigma rule templates are starting points for detection engineering. "
            "Adapt log sources and thresholds to your environment before deploying.",
            s["body"],
        ))

        for f in gap_findings:
            story.append(Spacer(1, 0.3 * cm))
            bg_c, fg_c = _severity_colors(f.get("severity", "medium"))
            header_tbl = Table(
                [[
                    Paragraph(
                        f"<b>{f['technique_id']}</b>  —  {f.get('technique_name', '')}",
                        ParagraphStyle("th", fontSize=9, textColor=fg_c,
                                       fontName="Helvetica-Bold", leading=12),
                    ),
                    Paragraph(
                        f.get("severity", "—").upper(),
                        ParagraphStyle("ts", fontSize=7.5, textColor=fg_c,
                                       fontName="Helvetica-Bold", alignment=TA_RIGHT),
                    ),
                ]],
                colWidths=[CONTENT_W * 0.8, CONTENT_W * 0.2],
            )
            header_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), bg_c),
                ("TOPPADDING",    (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]))
            sigma_lines = (f.get("sigma_rule") or "").splitlines() or ["# No Sigma rule available"]
            code_rows = [[Paragraph(line or " ", s["mono"])] for line in sigma_lines]
            code_tbl = Table(code_rows, colWidths=[CONTENT_W])
            code_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#0D1F2D")),
                ("TOPPADDING",    (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ("BOX",           (0, 0), (-1, -1), 0.5, colors.HexColor("#1E3A5F")),
            ]))
            story.append(KeepTogether([header_tbl, code_tbl]))

    # ── Recommendations ────────────────────────────────────────────────────────
    if recs:
        story.append(PageBreak())
        story.extend(_section("Remediation Recommendations", s))
        story.append(Paragraph(
            "Prioritised by severity and detection impact. Address critical and high items first.",
            s["body"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        for rec in recs:
            sev = rec.get("gap_severity") or "medium"
            bg, fg = _severity_colors(sev)
            title_para = Paragraph(
                f"<b>#{rec.get('priority', '?')}  {rec.get('technique_id', '')}  —  "
                f"{rec.get('title', '')}</b>",
                ParagraphStyle("rt", fontSize=9, textColor=fg, fontName="Helvetica-Bold", leading=12),
            )
            title_row = Table([[title_para]], colWidths=[CONTENT_W])
            title_row.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), bg),
                ("TOPPADDING",    (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING",   (0, 0), (-1, -1), 12),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
                ("LINEABOVE",     (0, 0), (-1, 0), 2, fg),
            ]))
            step_rows = [
                [Paragraph(f"• {step}", ParagraphStyle(
                    "rs", fontSize=8.5, textColor=C_TEXT_MED, fontName="Helvetica",
                    leading=12, leftIndent=4,
                ))]
                for step in rec.get("steps", [])
            ]
            if step_rows:
                steps_tbl = Table(step_rows, colWidths=[CONTENT_W])
                steps_tbl.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), C_WHITE),
                    ("TOPPADDING",    (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 16),
                    ("BOX",           (0, 0), (-1, -1), 0.5, C_LINE),
                    ("LINEBELOW",     (0, 0), (-1, -2), 0.3, C_LINE),
                ]))
                story.append(KeepTogether([title_row, steps_tbl]))
            else:
                story.append(title_row)
            story.append(Spacer(1, 0.2 * cm))

    doc.build(story, onFirstPage=on_first, onLaterPages=on_later, canvasmaker=_NumberedCanvas)
    return buf.getvalue()


# ─── Purple Team PDF ──────────────────────────────────────────────────────────

def generate_purple_pdf(report_dict: dict) -> bytes:
    """Generate enterprise-grade purple team PDF report."""
    buf = io.BytesIO()
    now = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")

    metrics = report_dict.get("metrics", {})
    events  = report_dict.get("events", [])
    recs    = report_dict.get("recommendations", [])
    session_name = report_dict.get("session_name", "Purple Team Session")

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=LM, rightMargin=RM,
        topMargin=TM, bottomMargin=BM,
        title=session_name,
        author="Adversary Emulation Platform",
        subject="Purple Team Detection Report",
    )

    def on_first(canv, doc_):
        _draw_cover(
            canv, doc_,
            title=session_name,
            doc_type="Purple Team Detection Report",
            meta=[
                ("Environment",   (report_dict.get("environment") or "—").upper()),
                ("Red Team Lead",  report_dict.get("red_team_lead") or "—"),
                ("Blue Team Lead", report_dict.get("blue_team_lead") or "—"),
                ("Facilitator",   report_dict.get("facilitator") or "—"),
                ("Status",        report_dict.get("status", "—").upper()),
                ("Generated",     now),
            ],
            gen_date=now,
        )

    def on_later(canv, doc_):
        _draw_content_page(canv, doc_, session_name, now)

    s = _styles()
    story: list[Any] = [PageBreak()]

    # ── Detection Coverage Summary ─────────────────────────────────────────────
    story.extend(_section("Detection Coverage Summary", s))

    total_ev = metrics.get("total_events", 0)
    det_cnt  = metrics.get("detected_count", 0)
    gap_cnt  = metrics.get("gap_count", 0)
    cov_pct  = round(metrics.get("detection_coverage", 0) * 100, 1)
    mttd     = metrics.get("mttd_seconds")

    story.append(_metric_row([
        ("Total Events",       str(total_ev), C_NAVY,    C_BG_BLUE),
        ("Detected / Blocked", str(det_cnt),  C_SUCCESS, C_SUCCESS_BG),
        ("Detection Gaps",     str(gap_cnt),  C_DANGER,  C_DANGER_BG),
        ("Coverage",           f"{cov_pct}%",
            C_SUCCESS if cov_pct >= 70 else C_WARNING if cov_pct >= 40 else C_DANGER,
            C_SUCCESS_BG if cov_pct >= 70 else C_WARNING_BG if cov_pct >= 40 else C_DANGER_BG,
        ),
    ]))
    story.append(Spacer(1, 0.4 * cm))

    # Overview table
    ov_data = [
        ["Metric", "Value"],
        ["Session Name",        session_name],
        ["Environment",         (report_dict.get("environment") or "—").upper()],
        ["Total Events",        str(total_ev)],
        ["Detected / Blocked",  str(det_cnt)],
        ["Detection Gaps",      str(gap_cnt)],
        ["Detection Coverage",  f"{cov_pct}%"],
        ["Avg MTTD",            f"{mttd:.0f}s" if mttd else "N/A"],
        ["False Positives",     str(metrics.get("false_positive_count", 0))],
    ]
    story.append(_tbl([6 * cm, CONTENT_W - 6 * cm], ov_data))

    # Coverage by tactic
    cov_tactic = metrics.get("coverage_by_tactic", {})
    if cov_tactic:
        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph("Coverage by Tactic", s["subsection"]))
        tactic_data = [["Tactic", "Coverage %", "Assessment"]]
        for tactic, pct in sorted(cov_tactic.items()):
            pct_val = round(pct * 100)
            assess = "Good" if pct_val >= 70 else "Needs Work" if pct_val >= 40 else "Gap"
            fg = C_SUCCESS if pct_val >= 70 else C_WARNING if pct_val >= 40 else C_DANGER
            tactic_data.append([
                tactic.replace("_", " ").title(),
                f"{pct_val}%",
                Paragraph(assess, ParagraphStyle(
                    "ta", fontSize=8, textColor=fg, fontName="Helvetica-Bold", leading=10,
                )),
            ])
        story.append(_tbl([6 * cm, 3 * cm, CONTENT_W - 9 * cm], tactic_data))

    story.append(PageBreak())

    # ── Event Detail ───────────────────────────────────────────────────────────
    if events:
        story.extend(_section("Event Detail", s))
        story.append(Paragraph(
            f"{len(events)} red team events recorded. "
            "Rows in red indicate detection gaps — techniques missed by defensive controls.",
            s["body"],
        ))
        story.append(Spacer(1, 0.2 * cm))

        ev_data = [["#", "Technique", "Tactic", "Response", "Severity", "MTTD"]]
        extra_cmds = []
        for i, ev in enumerate(events, 1):
            is_gap = ev.get("is_gap", False)
            resp = ev.get("blue_response") or "—"
            sev = ev.get("gap_severity") or "—"
            lat = ev.get("detection_latency_seconds")
            resp_color = {
                "detected": C_SUCCESS, "blocked": C_INFO,
                "partial": C_WARNING, "missed": C_DANGER,
                "false_positive": C_PURPLE,
            }.get(resp, C_TEXT_LIGHT)

            ev_data.append([
                str(i),
                Paragraph(ev.get("technique_id", ""), ParagraphStyle(
                    "eid", fontSize=8, textColor=C_ACCENT, fontName="Helvetica-Bold", leading=10,
                )),
                Paragraph((ev.get("tactic") or "—")[:18], ParagraphStyle(
                    "et", fontSize=7.5, textColor=C_TEXT_MED, fontName="Helvetica", leading=10,
                )),
                Paragraph(resp.title(), ParagraphStyle(
                    "er", fontSize=7.5, textColor=resp_color, fontName="Helvetica-Bold", leading=10,
                )),
                sev.title(),
                f"{lat:.0f}s" if lat else "—",
            ])
            if is_gap:
                extra_cmds += [
                    ("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FFF5F5")),
                    ("LINEABOVE",  (0, i), (-1, i), 0.3, colors.HexColor("#FECACA")),
                    ("LINEBELOW",  (0, i), (-1, i), 0.3, colors.HexColor("#FECACA")),
                ]

        story.append(_tbl(
            [0.7*cm, 2.5*cm, 3.3*cm, 2.8*cm, 2.2*cm, 1.8*cm],
            ev_data, extra_cmds,
        ))

    # ── Sigma Hints ────────────────────────────────────────────────────────────
    gap_events = [e for e in events if e.get("is_gap") and e.get("sigma_rule_hint")]
    if gap_events:
        story.append(PageBreak())
        story.extend(_section("Sigma Rule Hints for Detection Gaps", s))
        story.append(Paragraph(
            "Template Sigma rules for techniques missed by defensive controls. "
            "Validate and tune to your SIEM/EDR before deployment.",
            s["body"],
        ))

        for ev in gap_events:
            story.append(Spacer(1, 0.3 * cm))
            sev = ev.get("gap_severity", "medium")
            bg, fg = _severity_colors(sev)
            header_tbl = Table(
                [[
                    Paragraph(
                        f"<b>{ev['technique_id']}</b>  —  "
                        f"{ev.get('technique_name', '')}",
                        ParagraphStyle("ph", fontSize=9, textColor=fg,
                                       fontName="Helvetica-Bold", leading=12),
                    ),
                    Paragraph(
                        sev.upper(),
                        ParagraphStyle("ps", fontSize=7.5, textColor=fg,
                                       fontName="Helvetica-Bold", alignment=TA_RIGHT),
                    ),
                ]],
                colWidths=[CONTENT_W * 0.8, CONTENT_W * 0.2],
            )
            header_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), bg),
                ("TOPPADDING",    (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]))
            sigma_lines = (ev.get("sigma_rule_hint") or "").splitlines() or ["# No hint available"]
            code_rows = [[Paragraph(line or " ", s["mono"])] for line in sigma_lines]
            code_tbl = Table(code_rows, colWidths=[CONTENT_W])
            code_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0D1F2D")),
                ("TOPPADDING",    (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 2),
                ("LEFTPADDING",  (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("BOX",          (0, 0), (-1, -1), 0.5, colors.HexColor("#1E3A5F")),
            ]))
            story.append(KeepTogether([header_tbl, code_tbl]))

    # ── Recommendations ────────────────────────────────────────────────────────
    if recs:
        story.append(PageBreak())
        story.extend(_section("Remediation Recommendations", s))
        story.append(Paragraph(
            "Prioritised by severity. Each recommendation includes concrete remediation steps "
            "for the blue team.",
            s["body"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        for rec in recs:
            sev = rec.get("gap_severity") or "medium"
            bg, fg = _severity_colors(sev)
            title_row = Table(
                [[Paragraph(
                    f"<b>#{rec.get('priority', '?')}  {rec.get('technique_id', '')}  —  "
                    f"{rec.get('title', '')}</b>",
                    ParagraphStyle("rrt", fontSize=9, textColor=fg,
                                   fontName="Helvetica-Bold", leading=12),
                )]],
                colWidths=[CONTENT_W],
            )
            title_row.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), bg),
                ("TOPPADDING",    (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING",   (0, 0), (-1, -1), 12),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
                ("LINEABOVE",     (0, 0), (-1, 0), 2, fg),
            ]))
            step_rows = [
                [Paragraph(f"• {step}", ParagraphStyle(
                    "rrs", fontSize=8.5, textColor=C_TEXT_MED, fontName="Helvetica",
                    leading=12, leftIndent=4,
                ))]
                for step in rec.get("steps", [])
            ]
            if step_rows:
                steps_tbl = Table(step_rows, colWidths=[CONTENT_W])
                steps_tbl.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), C_WHITE),
                    ("TOPPADDING",    (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 16),
                    ("BOX",           (0, 0), (-1, -1), 0.5, C_LINE),
                    ("LINEBELOW",     (0, 0), (-1, -2), 0.3, C_LINE),
                ]))
                story.append(KeepTogether([title_row, steps_tbl]))
            else:
                story.append(title_row)
            story.append(Spacer(1, 0.2 * cm))

    doc.build(story, onFirstPage=on_first, onLaterPages=on_later, canvasmaker=_NumberedCanvas)
    return buf.getvalue()
