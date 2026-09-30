"""Report rendering: JSON, HTML and PDF.

Design notes
------------
The PDF is the document that leaves the building, so it is laid out as a document rather than
a data dump:

* every table cell is a ``Paragraph``, so long evidence text **wraps** instead of running over
  the neighbouring column (the original version put plain strings in fixed-width cells, which
  is what made the finding rows overlap),
* a summary band, a metric strip and a severity distribution come before the detail, so the
  first screen answers "how bad is this capture?",
* the evidence limits are printed on the report itself, not only in the documentation,

The HTML report is the same content with the same palette, and the JSON export stays the
machine-readable form that the dashboard and the tests read. All three are generated from the
same :class:`AnalysisResult`, so they cannot disagree with each other.
"""

from __future__ import annotations

import html
import io
import json
from collections import Counter
from typing import Any

from .schemas import AnalysisResult, SessionAnalysis

# A single palette shared by the HTML and PDF renderers, so the two documents look like
# they came from the same tool.
PALETTE = {
    "ink": "#0b1f33",
    "body": "#1f2a37",
    "muted": "#5b6b7f",
    "line": "#dfe5ec",
    "panel": "#f6f8fb",
    "accent": "#1d4ed8",
    "accent_soft": "#e8eefc",
    "CRITICAL": "#b42318",
    "HIGH": "#c2410c",
    "MEDIUM": "#a16207",
    "LOW": "#15803d",
    "INFO": "#64748b",
}

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# One extra sentence per severity band, so a reader who does not know the classification can
# still triage: what the band means in practice.
SEVERITY_MEANING = {
    "CRITICAL": "Act now: credentials or content were exposed.",
    "HIGH": "Serious weakness: fix before the next mail flow that relies on it.",
    "MEDIUM": "Weak configuration: schedule a fix.",
    "LOW": "Minor or hygiene item.",
    "INFO": "Context, or evidence that was not visible.",
}

FINDING_CAP_PDF = 40
SESSION_CAP_PDF = 60


def _safe(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _protocol(session: SessionAnalysis) -> str:
    return str(getattr(session.protocol, "value", session.protocol))


def _severity_counts(result: AnalysisResult) -> Counter:
    counts: Counter = Counter({name: 0 for name in SEVERITY_ORDER})
    for finding in result.findings:
        counts[str(finding.severity)] += 1
    return counts


def _capture_facts(result: AnalysisResult) -> dict[str, str]:
    summary = result.summary
    protocols = summary.protocols or Counter(_protocol(s) for s in result.sessions)
    facts = {
        "Protocols": ", ".join(f"{name} x{count}" for name, count in sorted(protocols.items())) or "-",
        "TLS versions": ", ".join(
            f"{name} x{count}" for name, count in sorted(summary.tls_versions.items())
        ) or "-",
        "Cipher suites": ", ".join(
            f"{name} x{count}" for name, count in sorted(summary.ciphers.items())
        ) or "-",
    }
    return facts


def _plaintext_note(result: AnalysisResult) -> str:
    plaintext = result.summary.plaintext_sessions
    if not plaintext:
        return ""
    return (
        f"{plaintext} of {result.summary.total_sessions} sessions carry mail without encryption."
    )


def render_json(result: AnalysisResult) -> bytes:
    return result.model_dump_json(indent=2).encode("utf-8")


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
def _severity_strip(result: AnalysisResult) -> str:
    counts = _severity_counts(result)
    worst = max(counts.values()) or 1
    rows = []
    for name in SEVERITY_ORDER:
        value = counts[name]
        width = round(value / worst * 100) if value else 0
        rows.append(
            f"<div class='sevrow'>"
            f"<span class='sevname'><i class='dot' style='background:{PALETTE[name]}'></i>{name}</span>"
            f"<span class='sevbar'><i style='width:{width}%;background:{PALETTE[name]}'></i></span>"
            f"<span class='sevcount'>{value}</span></div>"
            f"<div class='sevwhat'>{_safe(SEVERITY_MEANING[name])}</div>"
        )
    return "".join(rows)


def _session_row_html(session: SessionAnalysis) -> str:
    tls = session.tls
    starttls = session.starttls
    if starttls.upgrade_successful:
        upgrade = "upgraded"
    elif starttls.rejected:
        upgrade = "rejected"
    elif tls.detected:
        upgrade = "-"
    else:
        upgrade = "cleartext"
    return (
        "<tr>"
        f"<td class='mono'>{_safe(session.session_id)}</td>"
        f"<td><b>{_safe(_protocol(session))}</b><div class='sub'>port {_safe(session.server_port)}</div></td>"
        f"<td>{_safe(tls.tls_version or 'UNKNOWN')}"
        f"<div class='sub'>{_safe(tls.version_source or '-')}</div></td>"
        f"<td class='mono small'>{_safe(tls.cipher_suite or 'UNKNOWN')}</td>"
        f"<td>{_safe(upgrade)}</td>"
        f"<td><span class='chip s-{_safe(session.policy_risk_class)}'>"
        f"{_safe(session.policy_risk_class)}</span></td>"
        f"<td><span class='chip s-{_safe(session.ml.risk_class)}'>"
        f"{_safe(session.ml.risk_class)}</span></td>"
        f"<td class='num'>{_safe(session.policy_risk_score)}</td>"
        "</tr>"
    )


def _finding_rows_html(result: AnalysisResult) -> str:
    if not result.findings:
        return "<tr><td colspan='5' class='empty'>No findings were raised for this capture.</td></tr>"
    rows = []
    for finding in result.findings:
        evidence = "<br>".join(_safe(item) for item in finding.evidence) or "-"
        rows.append(
            "<tr>"
            f"<td><span class='chip s-{_safe(finding.severity)}'>{_safe(finding.severity)}</span></td>"
            f"<td><b>{_safe(finding.title)}</b><div class='sub'>{_safe(finding.description)}</div></td>"
            f"<td class='mono small'>{_safe(finding.session_id or '-')}</td>"
            f"<td class='small'>{evidence}</td>"
            f"<td class='small'>{_safe(finding.recommendation)}</td>"
            "</tr>"
        )
    return "".join(rows)


def render_html(result: AnalysisResult) -> bytes:
    summary = result.summary
    counts = _severity_counts(result)
    facts = _capture_facts(result)
    plaintext_note = _plaintext_note(result)

    metrics = [
        ("Posture", f"{summary.overall_posture_score}/100", "higher is better", "accent"),
        ("Risk score", f"{summary.overall_risk_score}/100", summary.overall_risk_class, "risk"),
        ("Sessions", str(summary.total_sessions), f"{summary.tls_sessions} encrypted", "plain"),
        ("Upgrades", str(summary.successful_upgrades), "STARTTLS / STLS completed", "plain"),
        ("Findings", str(summary.total_findings), f"{counts['CRITICAL']} critical", "plain"),
        ("Evidence", str(summary.evidence_completeness), "1.0 = everything visible", "plain"),
    ]
    metric_html = "".join(
        f"<div class='metric {kind}'>"
        f"<div class='mlabel'>{_safe(label)}</div>"
        f"<div class='mvalue'>{_safe(value)}</div>"
        f"<div class='msub'>{_safe(sub)}</div></div>"
        for label, value, sub, kind in metrics
    )

    facts_html = "".join(
        f"<div class='fact'><span class='k'>{_safe(key)}</span>"
        f"<span class='v'>{_safe(value)}</span></div>"
        for key, value in facts.items()
    )

    recommendations = "".join(
        f"<li><span class='num'>{index}</span><span>{_safe(item)}</span></li>"
        for index, item in enumerate(result.recommendations, 1)
    ) or "<li>No actions were generated for this capture.</li>"

    unclassified = ""
    streams = getattr(result, "unclassified_streams", None) or []
    if streams:
        rows = "".join(
            f"<div class='fact'><span class='k'>{_safe(stream.stream_id)}</span>"
            f"<span class='v'>port {_safe(stream.server_port)} &middot; "
            f"{_safe(stream.tls_version or 'TLS version UNKNOWN')} &middot; "
            f"{'certificate visible' if stream.certificate_visible else 'certificate not observable'}"
            f"</span></div>"
            for stream in streams[:20]
        )
        unclassified = (
            "<section class='card warn'>"
            "<h2>Encrypted traffic that could not be attributed to a mail protocol</h2>"
            f"<p class='lead'>{_safe(getattr(result, 'unclassified_note', '') or '')}</p>"
            f"{rows}"
            "<p class='note'>Implicit TLS sends a ClientHello before any mail command, so there is "
            "no protocol vocabulary in the capture to read. The protocol is left UNKNOWN rather "
            "than guessed. This is a limit of the capture, not a finding against the server.</p>"
            "</section>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureMailScope report - {_safe(result.source_filename)}</title>
<style>
  :root {{
    --ink: {PALETTE['ink']}; --body: {PALETTE['body']}; --muted: {PALETTE['muted']};
    --line: {PALETTE['line']}; --panel: {PALETTE['panel']}; --accent: {PALETTE['accent']};
    --accent-soft: {PALETTE['accent_soft']};
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: #eef1f6; color: var(--body);
    font: 15px/1.55 "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
  }}
  .sheet {{ max-width: 1180px; margin: 0 auto; padding: 28px 20px 56px; }}
  .card {{
    background: #fff; border: 1px solid var(--line); border-radius: 14px;
    padding: 22px 24px; margin: 0 0 18px;
  }}
  h1 {{ font-size: 26px; margin: 0 0 6px; color: var(--ink); letter-spacing: -0.2px; }}
  h2 {{ font-size: 17px; margin: 0 0 14px; color: var(--ink); letter-spacing: -0.1px; }}
  p {{ margin: 0 0 10px; }}
  .lead {{ color: var(--muted); }}
  .note {{ color: var(--muted); font-size: 13px; }}

  header.top {{
    background: linear-gradient(135deg, {PALETTE['ink']} 0%, #16324f 55%, #1d4ed8 140%);
    color: #fff; border-radius: 16px; padding: 26px 28px; margin-bottom: 18px;
  }}
  header.top h1 {{ color: #fff; font-size: 27px; }}
  header.top .sub {{ color: #c7d6ea; font-size: 14px; }}
  .meta {{ display: flex; flex-wrap: wrap; gap: 8px 22px; margin-top: 18px;
           border-top: 1px solid rgba(255,255,255,.18); padding-top: 14px; font-size: 13px; }}
  .meta div span {{ color: #9db4d0; display: block; font-size: 11px; text-transform: uppercase;
                    letter-spacing: .08em; }}
  .meta div b {{ font-weight: 600; color: #eef4fc; }}
  .hash {{ font-family: ui-monospace, Consolas, monospace; word-break: break-all; }}

  .metrics {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 18px; }}
  .metric {{ background: #fff; border: 1px solid var(--line); border-radius: 12px; padding: 14px 16px; }}
  .metric .mlabel {{ font-size: 11px; text-transform: uppercase; letter-spacing: .09em; color: var(--muted); }}
  .metric .mvalue {{ font-size: 24px; font-weight: 700; color: var(--ink); margin-top: 6px; }}
  .metric .msub {{ font-size: 12px; color: var(--muted); }}
  .metric.accent {{ border-color: #c9d8f8; background: var(--accent-soft); }}
  .metric.risk {{ border-color: #f0c9c4; background: #fdf3f2; }}

  .cols {{ display: grid; grid-template-columns: 1.05fr .95fr; gap: 18px; }}
  .sevrow {{ display: grid; grid-template-columns: 118px 1fr 42px; align-items: center; gap: 10px; }}
  .sevbar {{ background: #eef1f6; border-radius: 999px; height: 9px; overflow: hidden; display: block; }}
  .sevbar i {{ display: block; height: 100%; border-radius: 999px; }}
  .sevname {{ font-size: 12.5px; font-weight: 600; color: var(--ink); display: flex; align-items: center; gap: 7px; }}
  .sevcount {{ text-align: right; font-variant-numeric: tabular-nums; font-size: 13px; color: var(--muted); }}
  .sevwhat {{ font-size: 12px; color: var(--muted); margin: 2px 0 10px 128px; }}
  .dot {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; }}

  .fact {{ display: grid; grid-template-columns: 150px 1fr; gap: 10px; padding: 7px 0;
           border-bottom: 1px dashed var(--line); font-size: 13.5px; }}
  .fact:last-child {{ border-bottom: 0; }}
  .fact .k {{ color: var(--muted); }}
  .fact .v {{ color: var(--body); word-break: break-word; }}

  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  thead th {{
    text-align: left; background: var(--panel); color: var(--muted); font-weight: 600;
    font-size: 11px; text-transform: uppercase; letter-spacing: .07em;
    padding: 10px 10px; border-bottom: 1px solid var(--line); position: sticky; top: 0;
  }}
  tbody td {{ padding: 11px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }}
  tbody tr:nth-child(even) {{ background: #fbfcfe; }}
  .mono {{ font-family: ui-monospace, Consolas, monospace; font-size: 12px; }}
  .small {{ font-size: 12.5px; }}
  .sub {{ color: var(--muted); font-size: 11.5px; margin-top: 3px; }}
  .empty {{ color: var(--muted); }}
  .num {{ font-variant-numeric: tabular-nums; text-align: right; }}

  .chip {{ display: inline-block; padding: 3px 9px; border-radius: 999px; font-size: 11px;
           font-weight: 700; letter-spacing: .04em; }}
  .s-CRITICAL {{ background: #fdecea; color: {PALETTE['CRITICAL']}; }}
  .s-HIGH {{ background: #fdf0e7; color: {PALETTE['HIGH']}; }}
  .s-MEDIUM {{ background: #fdf6e3; color: {PALETTE['MEDIUM']}; }}
  .s-LOW {{ background: #e9f7ef; color: {PALETTE['LOW']}; }}
  .s-INFO {{ background: #eef1f6; color: {PALETTE['INFO']}; }}

  ol.actions {{ list-style: none; margin: 0; padding: 0; counter-reset: act; }}
  ol.actions li {{ display: flex; gap: 12px; padding: 11px 0; border-bottom: 1px solid var(--line); }}
  ol.actions li:last-child {{ border-bottom: 0; }}
  ol.actions .num {{ width: 26px; height: 26px; flex: 0 0 26px; border-radius: 50%;
                     background: var(--accent-soft); color: var(--accent); font-weight: 700;
                     display: grid; place-items: center; font-size: 12.5px; text-align: center; }}

  .card.warn {{ border-left: 4px solid {PALETTE['MEDIUM']}; }}
  footer {{ color: var(--muted); font-size: 12px; margin-top: 22px; text-align: center; }}

  @media (max-width: 980px) {{
    .metrics {{ grid-template-columns: repeat(3, 1fr); }}
    .cols {{ grid-template-columns: 1fr; }}
  }}
  @media print {{
    body {{ background: #fff; }}
    .sheet {{ max-width: none; padding: 0; }}
    .card, header.top {{ border-radius: 0; break-inside: avoid; }}
    thead th {{ position: static; }}
  }}
</style>
</head>
<body>
<div class="sheet">

  <header class="top">
    <h1>SecureMailScope</h1>
    <div class="sub">Cryptographic security posture of SMTP, IMAP and POP3 traffic - passive evidence report</div>
    <div class="meta">
      <div><span>Capture</span><b>{_safe(result.source_filename)}</b></div>
      <div><span>Uploaded by</span><b>{_safe(result.uploaded_by)}</b></div>
      <div><span>Analysed</span><b>{_safe(result.created_at)}</b></div>
      <div><span>Analyzer</span><b>{_safe(result.analyzer_version)}</b></div>
      <div><span>Risk / posture</span><b>{_safe(summary.overall_risk_score)}/100 &middot;
        {_safe(summary.overall_risk_class)} &middot; {_safe(summary.overall_posture_score)}/100</b></div>
      <div><span>Capture SHA-256</span><b class="hash">{_safe(result.source_sha256)}</b></div>
    </div>
  </header>

  <div class="metrics">{metric_html}</div>

  <div class="cols">
    <section class="card">
      <h2>Finding severity</h2>
      {_severity_strip(result)}
    </section>
    <section class="card">
      <h2>Capture facts</h2>
      {facts_html}
      {'<p class="note" style="margin-top:12px">' + _safe(plaintext_note) + '</p>' if plaintext_note else ''}
      <p class="note" style="margin-top:12px">Session risk is a policy score derived from the
      findings below. The ML column is a triage hint trained on this project's own rule labels;
      it never replaces the findings.</p>
    </section>
  </div>

  {unclassified}

  <section class="card">
    <h2>Prioritised findings ({len(result.findings)})</h2>
    <table>
      <thead><tr><th>Severity</th><th>Finding</th><th>Session</th><th>Evidence</th><th>Recommended action</th></tr></thead>
      <tbody>{_finding_rows_html(result)}</tbody>
    </table>
  </section>

  <section class="card">
    <h2>Sessions ({len(result.sessions)})</h2>
    <table>
      <thead><tr><th>Session</th><th>Protocol</th><th>TLS version</th><th>Cipher suite</th>
        <th>Upgrade</th><th>Rules</th><th>ML</th><th>Score</th></tr></thead>
      <tbody>{''.join(_session_row_html(s) for s in result.sessions)
             or "<tr><td colspan='8' class='empty'>No mail session was identified in this capture.</td></tr>"}</tbody>
    </table>
  </section>

  <section class="card">
    <h2>Recommended actions</h2>
    <ol class="actions">{recommendations}</ol>
  </section>

  <section class="card">
    <h2>What this report does and does not claim</h2>
    <p>It reports what the capture shows. Every value labelled <b>negotiated</b> comes from the
    server's own handshake; values the client merely offered are labelled as offers.</p>
    <p>Missing evidence is reported as <b>UNKNOWN</b> or <b>PARTIAL</b>, never as a weakness: an
    unobserved certificate, an encrypted TLS 1.3 certificate or a truncated handshake are
    absences of evidence, not findings.</p>
    <p>The analysis is passive. No email content is read, stored or decrypted, and an incomplete
    capture cannot prove an attack - it can only show that something is worth checking.</p>
    <p class="note">Evidence completeness for this capture: {_safe(summary.evidence_completeness)}
    (1.0 means every field the analyzer looks for was visible).</p>
  </section>

  <footer>Generated by SecureMailScope {_safe(result.analyzer_version)} &middot;
    analysis {_safe(result.analysis_id)} &middot; source SHA-256 {_safe(result.source_sha256)[:16]}...</footer>
</div>
</body>
</html>""".encode("utf-8")


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #
def render_pdf(result: AnalysisResult) -> bytes:
    """Render the PDF report.

    Two things are deliberate and both are fixes for how this used to look:

    * every cell is a ``Paragraph``, so text wraps inside its column instead of overlapping
      the next one,
    * the column widths are derived from the frame width rather than hard-coded, so the table
      can never be wider than the page.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            HRFlowable,
            KeepTogether,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("reportlab is required for PDF export") from exc

    ink = colors.HexColor(PALETTE["ink"])
    body = colors.HexColor(PALETTE["body"])
    muted = colors.HexColor(PALETTE["muted"])
    line = colors.HexColor(PALETTE["line"])
    panel = colors.HexColor(PALETTE["panel"])
    accent = colors.HexColor(PALETTE["accent"])
    accent_soft = colors.HexColor(PALETTE["accent_soft"])
    severity_colors = {name: colors.HexColor(PALETTE[name]) for name in SEVERITY_ORDER}

    page = landscape(A4)
    margin = 14 * mm
    frame_width = page[0] - 2 * margin

    styles = {
        "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=19, leading=23,
                                textColor=ink, spaceAfter=2),
        "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=10.5, leading=14,
                                   textColor=muted, spaceAfter=10),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=12.5, leading=16,
                             textColor=ink, spaceBefore=6, spaceAfter=7),
        "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9, leading=12.5,
                               textColor=body, alignment=TA_LEFT),
        "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8, leading=11,
                                textColor=muted),
        "meta_label": ParagraphStyle("meta_label", fontName="Helvetica", fontSize=7,
                                     leading=9, textColor=muted),
        "meta_value": ParagraphStyle("meta_value", fontName="Helvetica-Bold", fontSize=9,
                                     leading=12, textColor=ink),
        "metric_label": ParagraphStyle("metric_label", fontName="Helvetica", fontSize=7,
                                       leading=9, textColor=muted),
        "metric_value": ParagraphStyle("metric_value", fontName="Helvetica-Bold", fontSize=17,
                                       leading=20, textColor=ink),
        "th": ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=7.6, leading=10,
                             textColor=colors.white),
        "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=7.8, leading=10.4,
                               textColor=body),
        "cell_small": ParagraphStyle("cell_small", fontName="Helvetica", fontSize=7.2,
                                     leading=9.6, textColor=body),
        "cell_muted": ParagraphStyle("cell_muted", fontName="Helvetica", fontSize=7.2,
                                     leading=9.6, textColor=muted),
        "chip": ParagraphStyle("chip", fontName="Helvetica-Bold", fontSize=7.4, leading=9.6),
        "chip_row": ParagraphStyle("chip_row", fontName="Helvetica-Bold", fontSize=7.2,
                                   leading=8.8),
        "action": ParagraphStyle("action", fontName="Helvetica", fontSize=9, leading=13,
                                 textColor=body),
    }

    def paragraph(text: Any, style: str = "cell") -> Paragraph:
        return Paragraph(str(text if text not in (None, "") else "-"), styles[style])

    def header_footer(canvas, doc) -> None:
        canvas.saveState()
        width, height = page
        # A slim brand band on every page keeps the printed copy recognisable.
        canvas.setFillColor(ink)
        canvas.rect(0, height - 8 * mm, width, 8 * mm, stroke=0, fill=1)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(margin, height - 5.6 * mm, "SecureMailScope")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(width - margin, height - 5.6 * mm,
                               "Passive evidence report - no email content was read or decrypted")
        canvas.setStrokeColor(line)
        canvas.setLineWidth(0.5)
        canvas.line(margin, 12 * mm, width - margin, 12 * mm)
        canvas.setFillColor(muted)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(margin, 9 * mm, str(result.source_filename)[:70])
        canvas.drawCentredString(width / 2, 9 * mm,
                                 f"analysis {str(result.analysis_id)[:8]}  |  analyzer {result.analyzer_version}")
        canvas.drawRightString(width - margin, 9 * mm, f"page {doc.page}")
        canvas.restoreState()

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=page,
        rightMargin=margin, leftMargin=margin, topMargin=13 * mm, bottomMargin=16 * mm,
        title=f"SecureMailScope report - {result.source_filename}",
        author="SecureMailScope", subject="Passive mail security posture assessment",
    )

    story: list[Any] = []

    # -- header ------------------------------------------------------------- #
    story.append(Paragraph("Cryptographic Security Posture Report", styles["title"]))
    story.append(Paragraph(
        f"{_safe(result.source_filename)} &nbsp;&middot;&nbsp; uploaded by "
        f"{_safe(result.uploaded_by)} &nbsp;&middot;&nbsp; analysed {_safe(result.created_at)} "
        f"&nbsp;&middot;&nbsp; SHA-256 {_safe(str(result.source_sha256)[:32])}...",
        styles["subtitle"],
    ))

    # -- metric strip ------------------------------------------------------- #
    summary = result.summary
    counts = _severity_counts(result)
    metrics = [
        ("POSTURE", f"{summary.overall_posture_score}/100", "higher is better"),
        ("RISK SCORE", f"{summary.overall_risk_score}/100", str(summary.overall_risk_class)),
        ("SESSIONS", str(summary.total_sessions), f"{summary.tls_sessions} encrypted"),
        ("UPGRADES", str(summary.successful_upgrades), "STARTTLS / STLS"),
        ("FINDINGS", str(summary.total_findings), f"{counts['CRITICAL']} critical"),
        ("EVIDENCE", f"{summary.evidence_completeness}", "1.0 = all visible"),
    ]
    metric_cells = [
        [
            Paragraph(label, styles["metric_label"]),
            Paragraph(value, styles["metric_value"]),
            Paragraph(sub, styles["metric_label"]),
        ]
        for label, value, sub in metrics
    ]
    metric_table = Table(
        [[cell[0] for cell in metric_cells], [cell[1] for cell in metric_cells],
         [cell[2] for cell in metric_cells]],
        colWidths=[frame_width / len(metrics)] * len(metrics),
    )
    metric_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), panel),
        ("BOX", (0, 0), (-1, -1), 0.5, line),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("BACKGROUND", (0, 0), (0, -1), accent_soft),
    ]))
    story.extend([metric_table, Spacer(1, 10)])

    # -- severity distribution and capture facts ---------------------------- #
    max_count = max(counts.values()) or 1
    severity_rows = []
    for name in SEVERITY_ORDER:
        value = counts[name]
        severity_rows.append([
            Paragraph(name, ParagraphStyle(
                f"sev{name}", parent=styles["chip"], textColor=severity_colors[name])),
            Paragraph(SEVERITY_MEANING[name], styles["cell_muted"]),
            Paragraph(str(value), styles["cell"]),
        ])
    severity_table = Table(severity_rows, colWidths=[22 * mm, frame_width * 0.20, 12 * mm])
    severity_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (2, 0), (2, -1), "RIGHT"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, line),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))

    facts = _capture_facts(result)
    fact_rows = [[Paragraph(key, styles["cell_muted"]), Paragraph(value, styles["cell"])]
                 for key, value in facts.items()]
    fact_table = Table(fact_rows, colWidths=[28 * mm, frame_width * 0.20])
    fact_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, line),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))

    left_width = frame_width * 0.34
    right_width = frame_width - left_width
    overview = Table(
        [[Paragraph("Finding severity", styles["h2"]), Paragraph("Capture facts", styles["h2"])],
         [severity_table, fact_table]],
        colWidths=[left_width, right_width],
    )
    overview.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.extend([overview, Spacer(1, 6)])
    story.append(HRFlowable(width="100%", thickness=0.5, color=line, spaceBefore=4, spaceAfter=10))

    # -- findings ----------------------------------------------------------- #
    if len(result.findings) > FINDING_CAP_PDF:
        shown = FINDING_CAP_PDF
        heading = (f"Prioritised findings - showing the {shown} most severe of "
                   f"{len(result.findings)}")
    else:
        heading = f"Prioritised findings ({len(result.findings)})"
    story.append(Paragraph(heading, styles["h2"]))

    finding_header = ["SEVERITY", "FINDING", "SESSION", "EVIDENCE", "RECOMMENDED ACTION"]
    finding_widths = [18 * mm, 0.20 * frame_width, 22 * mm,
                      0.28 * frame_width, 0.28 * frame_width]
    # Scale the widths so the table is exactly as wide as the frame, whatever the page size.
    scale = frame_width / sum(finding_widths)
    finding_widths = [width * scale for width in finding_widths]

    finding_rows = [[Paragraph(head, styles["th"]) for head in finding_header]]
    for finding in result.findings[:FINDING_CAP_PDF]:
        finding_rows.append([
            Paragraph(str(finding.severity), ParagraphStyle(
                "chipcell", parent=styles["chip"],
                textColor=severity_colors.get(str(finding.severity), body))),
            [Paragraph(_safe(finding.title), styles["cell"]),
             Spacer(1, 2),
             Paragraph(_safe(finding.description), styles["cell_muted"])],
            Paragraph(str(finding.session_id or "-"), styles["cell_small"]),
            [Paragraph(_safe(item), styles["cell_small"]) for item in finding.evidence] or
            [Paragraph("-", styles["cell_small"])],
            Paragraph(_safe(finding.recommendation), styles["cell_small"]),
        ])

    findings_table = Table(finding_rows, colWidths=finding_widths, repeatRows=1)
    findings_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ink),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, line),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafbfd")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(findings_table)

    # The cap is stated where a reader sees it. HTML and JSON reports are complete, so a
    # reviewer comparing the two formats can tell the difference between a cap and a bug.
    if len(result.findings) > FINDING_CAP_PDF:
        story.extend([
            Spacer(1, 5),
            Paragraph(
                f"Showing the {FINDING_CAP_PDF} most severe of {len(result.findings)} findings in "
                "this document. The HTML and JSON reports contain every finding, and the "
                "dashboard lists them per session.", styles["small"]),
        ])

    # -- sessions ----------------------------------------------------------- #
    story.append(Spacer(1, 12))
    session_header = ["SESSION", "PROTOCOL", "TLS VERSION", "CIPHER SUITE", "UPGRADE",
                      "RULES", "ML", "SCORE"]
    session_widths_base = [24 * mm, 19 * mm, 22 * mm, 0.30 * frame_width, 18 * mm,
                           16 * mm, 16 * mm, 13 * mm]
    scale = frame_width / sum(session_widths_base)
    session_widths = [width * scale for width in session_widths_base]

    sessions = sorted(result.sessions, key=lambda item: -item.policy_risk_score)
    shown_sessions = sessions[:SESSION_CAP_PDF]
    session_rows = [[Paragraph(head, styles["th"]) for head in session_header]]
    for session in shown_sessions:
        tls, starttls = session.tls, session.starttls
        if starttls.upgrade_successful:
            upgrade = "upgraded"
        elif starttls.rejected:
            upgrade = "rejected"
        elif tls.detected:
            upgrade = "-"
        else:
            upgrade = "cleartext"
        session_rows.append([
            Paragraph(_safe(session.session_id), styles["cell_small"]),
            Paragraph(f"{_safe(_protocol(session))} {_safe(session.server_port)}",
                      styles["cell_small"]),
            Paragraph(_safe(tls.tls_version or "UNKNOWN"), styles["cell_small"]),
            Paragraph(_safe(tls.cipher_suite or "UNKNOWN"), styles["cell_small"]),
            Paragraph(upgrade, styles["cell_small"]),
            Paragraph(_safe(session.policy_risk_class), ParagraphStyle(
                "sr", parent=styles["chip_row"],
                textColor=severity_colors.get(str(session.policy_risk_class), body))),
            Paragraph(_safe(session.ml.risk_class), ParagraphStyle(
                "sm", parent=styles["chip_row"],
                textColor=severity_colors.get(str(session.ml.risk_class), body))),
            Paragraph(str(session.policy_risk_score), styles["cell_small"]),
        ])

    sessions_title = f"Sessions ({len(result.sessions)})"
    if len(sessions) > SESSION_CAP_PDF:
        sessions_title += f" - showing the {SESSION_CAP_PDF} highest-risk"
    story.append(KeepTogether([
        Paragraph(sessions_title, styles["h2"]),
        Table(session_rows, colWidths=session_widths, repeatRows=1, style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ink),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.35, line),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafbfd")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])),
    ]))
    if len(sessions) > SESSION_CAP_PDF:
        story.extend([Spacer(1, 4), Paragraph(
            f"{len(sessions) - SESSION_CAP_PDF} further session(s) are in the HTML and JSON "
            "reports, and in the dashboard.", styles["small"])])

    # -- recommendations ---------------------------------------------------- #
    story.append(Spacer(1, 12))
    story.append(Paragraph("Recommended actions", styles["h2"]))
    if result.recommendations:
        action_rows = [
            [Paragraph(str(index), styles["cell"]), Paragraph(_safe(item), styles["action"])]
            for index, item in enumerate(result.recommendations, 1)
        ]
        action_table = Table(action_rows, colWidths=[10 * mm, frame_width - 10 * mm])
        action_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -2), 0.4, line),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (0, -1), 0),
        ]))
        story.append(action_table)
    else:
        story.append(Paragraph("No actions were generated for this capture.", styles["body"]))

    # -- evidence statement ------------------------------------------------- #
    story.append(Spacer(1, 12))
    unclassified = getattr(result, "unclassified_streams", None) or []
    limits = [
        Paragraph("What this report does and does not claim", styles["h2"]),
        Paragraph(
            "It reports what the capture shows. Values labelled as negotiated come from the "
            "server's own handshake; values the client merely offered are labelled as offers. "
            "Missing evidence is reported as UNKNOWN or PARTIAL and never as a weakness: an "
            "unobserved certificate, a certificate encrypted inside TLS 1.3, or a truncated "
            "handshake are absences of evidence, not findings.", styles["body"]),
        Paragraph(
            "The analysis is passive. No email content is read, stored or decrypted, and an "
            "incomplete capture cannot prove an attack - it can only show that something is "
            f"worth checking. Evidence completeness for this capture: "
            f"{summary.evidence_completeness} (1.0 means every field the analyzer looks for was "
            "visible).", styles["body"]),
    ]
    if unclassified:
        limits.append(Paragraph(
            f"{len(unclassified)} encrypted stream(s) in this capture could not be attributed to "
            "a mail protocol. With implicit TLS there is no mail command in the clear to read, so "
            "the protocol is reported as UNKNOWN rather than guessed.", styles["body"]))
    story.extend(limits)

    document.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    return buffer.getvalue()
