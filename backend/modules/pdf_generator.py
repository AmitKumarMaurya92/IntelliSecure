"""
PDF Report Generator â€” IntelliSecure
=====================================
Generates professional PDF security incident and threat reports
using the ReportLab library.

Generates:
  - Incident Report:  Summary of active threats, recommendations, score
  - Security Report:  Full system health with trend data

Output: reports/pdf/incident_YYYYMMDD_HHMMSS.pdf

Author: IntelliSecure Team
"""

import os
import sys
import datetime

ROOT_DIR   = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PDF_DIR    = os.path.join(ROOT_DIR, "reports", "pdf")

try:
    from reportlab.lib.pagesizes   import A4
    from reportlab.lib             import colors
    from reportlab.lib.styles      import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units       import cm
    from reportlab.platypus        import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    )
    from reportlab.lib.enums       import TA_LEFT, TA_CENTER, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def _ensure_output_dir():
    """Ensure the PDF output directory exists."""
    os.makedirs(PDF_DIR, exist_ok=True)


def generate_incident_report(stats: dict, alerts: list, score: dict, recommendations: dict) -> str:
    """
    Generate a PDF incident report.

    Args:
        stats:           Dashboard stats (total_logs, active_threats, etc.)
        alerts:          List of active alert dicts
        score:           Security score dict (score, risk_level, breakdown)
        recommendations: Prioritized recommendations dict

    Returns:
        Absolute path to the generated PDF file.
    """
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("ReportLab is not installed. Run: pip install reportlab")

    _ensure_output_dir()
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename  = f"incident_report_{timestamp}.pdf"
    filepath  = os.path.join(PDF_DIR, filename)

    doc     = SimpleDocTemplate(filepath, pagesize=A4,
                                leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
    styles  = getSampleStyleSheet()
    content = []

    # â”€â”€ Color Palette â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    PRIMARY   = colors.HexColor("#1e40af")
    DANGER    = colors.HexColor("#ef4444")
    SUCCESS   = colors.HexColor("#10b981")
    WARNING   = colors.HexColor("#f59e0b")
    LIGHT_BG  = colors.HexColor("#f8fafc")
    HEADER_BG = colors.HexColor("#0f172a")

    # â”€â”€ Custom Styles â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    title_style   = ParagraphStyle("Title",   parent=styles["Heading1"], fontSize=22, textColor=PRIMARY, spaceAfter=4)
    h2_style      = ParagraphStyle("H2",      parent=styles["Heading2"], fontSize=14, textColor=PRIMARY, spaceBefore=12, spaceAfter=4)
    body_style    = ParagraphStyle("Body",    parent=styles["Normal"],   fontSize=10, leading=14)
    caption_style = ParagraphStyle("Caption", parent=styles["Normal"],   fontSize=8,  textColor=colors.grey)
    bold_style    = ParagraphStyle("Bold",    parent=styles["Normal"],   fontSize=10, fontName="Helvetica-Bold")

    # â”€â”€ Header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    content.append(Paragraph("ðŸ”’ IntelliSecure", title_style))
    content.append(Paragraph("AI-Powered Cybersecurity â€” Incident Report", h2_style))
    content.append(Paragraph(
        f"Generated: {datetime.datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')}",
        caption_style
    ))
    content.append(HRFlowable(width="100%", thickness=1, color=PRIMARY))
    content.append(Spacer(1, 0.4*cm))

    # â”€â”€ Executive Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    content.append(Paragraph("1. Executive Summary", h2_style))
    summary_text = (
        f"This report summarizes the current security status of the IntelliSecure monitored network. "
        f"The system detected <b>{stats.get('active_threats', 0)}</b> active threat(s), with "
        f"<b>{stats.get('critical_alerts', 0)}</b> critical alert(s) requiring immediate attention. "
        f"The current security score is <b>{score.get('score', 'N/A')}/100</b> â€” "
        f"Risk Level: <b>{score.get('risk_level', 'Unknown')}</b>."
    )
    content.append(Paragraph(summary_text, body_style))
    content.append(Spacer(1, 0.3*cm))

    # â”€â”€ KPI Table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    kpi_data = [
        ["Metric",              "Value"],
        ["Total Logs Collected",    str(stats.get("total_logs", 0))],
        ["Active Threats",          str(stats.get("active_threats", 0))],
        ["Critical Alerts",         str(stats.get("critical_alerts", 0))],
        ["Security Score",          f"{score.get('score', 'N/A')} / 100"],
        ["Risk Level",              score.get("risk_level", "Unknown")],
    ]
    kpi_table = Table(kpi_data, colWidths=[9*cm, 7*cm])
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), HEADER_BG),
        ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0), 11),
        ("BACKGROUND",   (0, 1), (-1, -1), LIGHT_BG),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
        ("PADDING",      (0, 0), (-1, -1), 6),
    ]))
    content.append(kpi_table)
    content.append(Spacer(1, 0.5*cm))

    # â”€â”€ Active Alerts Table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    content.append(Paragraph("2. Active Security Alerts", h2_style))

    if alerts:
        alert_data = [["#", "Threat Type", "Severity", "Source", "Timestamp"]]
        for i, a in enumerate(alerts[:20], 1):
            alert_data.append([
                str(i),
                a.get("threat_type", "â€”"),
                a.get("severity",    "â€”"),
                a.get("source",      "â€”")[:30],
                str(a.get("timestamp", "â€”"))[:19]
            ])

        alert_table = Table(alert_data, colWidths=[1*cm, 5*cm, 3*cm, 4*cm, 4*cm])
        alert_table.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), HEADER_BG),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID",         (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
            ("PADDING",      (0, 0), (-1, -1), 5),
            ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ]))
        content.append(alert_table)
    else:
        content.append(Paragraph("No active alerts at time of report generation.", body_style))

    content.append(Spacer(1, 0.5*cm))

    # â”€â”€ Score Breakdown â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    content.append(Paragraph("3. Security Score Breakdown", h2_style))
    breakdown = score.get("breakdown", {})
    if breakdown:
        bd_data = [["Factor", "Count", "Penalty Applied", "Max Penalty"]]
        labels = {
            "failed_logins":          "Failed Login Attempts (24h)",
            "malware_detected":       "Malware Events (24h)",
            "port_scan_sources":      "Port Scan Sources (1h)",
            "unauthorized_accesses":  "Unauthorized File Access (24h)",
            "active_critical_alerts": "Active Critical Alerts"
        }
        for key, label in labels.items():
            if key in breakdown:
                bd = breakdown[key]
                bd_data.append([label, str(bd.get("value", 0)),
                                 f"-{bd.get('penalty', 0)}", f"-{bd.get('max_penalty', 0)}"])
        bd_table = Table(bd_data, colWidths=[8*cm, 2.5*cm, 3.5*cm, 3*cm])
        bd_table.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), HEADER_BG),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID",         (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
            ("PADDING",      (0, 0), (-1, -1), 5),
            ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ]))
        content.append(bd_table)

    content.append(Spacer(1, 0.5*cm))

    # â”€â”€ Recommendations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    content.append(Paragraph("4. Priority Recommendations", h2_style))

    p1_recs = recommendations.get("p1_critical", [])
    p2_recs = recommendations.get("p2_high", [])

    for priority, recs, color in [("P1 â€” Critical", p1_recs, DANGER), ("P2 â€” High", p2_recs, WARNING)]:
        if recs:
            content.append(Paragraph(priority, bold_style))
            for rec in recs[:5]:
                content.append(Paragraph(
                    f"â€¢ <b>{rec.get('action', '')}</b>: {rec.get('description', '')}",
                    body_style
                ))
            content.append(Spacer(1, 0.2*cm))

    # â”€â”€ Footer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    content.append(Spacer(1, 0.5*cm))
    content.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
    content.append(Paragraph(
        f"IntelliSecure v2.0 | Confidential â€” For Authorized Personnel Only | {datetime.datetime.utcnow().strftime('%Y-%m-%d')}",
        caption_style
    ))

    doc.build(content)
    return filepath
