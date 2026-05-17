"""
exporters/pdf_exporter.py
Generates a styled PDF risk report using Jinja2 + WeasyPrint.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Template

from app.core.models import AnalysisReport

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: Arial, sans-serif; font-size: 11px; color: #1a1a1a; background: #fff; }
  .page { padding: 30px 40px; }
  h1 { font-size: 22px; color: #1f4e79; border-bottom: 3px solid #2e75b6; padding-bottom: 8px; margin-bottom: 16px; }
  h2 { font-size: 15px; color: #2e75b6; margin: 20px 0 8px 0; border-bottom: 1px solid #d0e4f7; padding-bottom: 4px; }
  h3 { font-size: 12px; color: #404040; margin: 12px 0 6px 0; }
  .meta { color: #666; font-size: 10px; margin-bottom: 20px; }
  .score-box { display: inline-block; padding: 6px 14px; border-radius: 6px; font-size: 18px; font-weight: bold; margin: 10px 0; }
  .score-blocking  { background: #7f1d1d; color: white; }
  .score-critical  { background: #dc2626; color: white; }
  .score-high      { background: #ea580c; color: white; }
  .score-moderate  { background: #ca8a04; color: white; }
  .score-low       { background: #16a34a; color: white; }
  .stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 16px 0; }
  .stat-card { background: #f0f7ff; border: 1px solid #bdd7ee; border-radius: 6px; padding: 8px; text-align: center; }
  .stat-card .val { font-size: 20px; font-weight: bold; color: #1f4e79; }
  .stat-card .lbl { font-size: 9px; color: #666; text-transform: uppercase; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 10px; }
  th { background: #1f4e79; color: white; padding: 5px 8px; text-align: left; font-size: 10px; }
  td { padding: 4px 8px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
  tr:nth-child(even) td { background: #f9fafb; }
  .badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 9px; font-weight: bold; }
  .badge-critical  { background: #dc2626; color: white; }
  .badge-high      { background: #ea580c; color: white; }
  .badge-moderate  { background: #ca8a04; color: white; }
  .badge-low       { background: #16a34a; color: white; }
  .badge-blocking  { background: #7f1d1d; color: white; }
  .plan-item { border: 1px solid #e5e7eb; border-radius: 6px; padding: 8px 12px; margin: 6px 0; }
  .plan-item .priority { font-weight: bold; font-size: 11px; }
  .plan-item .reason { color: #555; font-size: 10px; margin-top: 3px; }
  .plan-item .meta { color: #888; font-size: 9px; margin-top: 3px; }
  .summary-box { background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 12px 16px; margin: 10px 0; font-size: 11px; line-height: 1.6; }
  .footer { margin-top: 30px; padding-top: 10px; border-top: 1px solid #e5e7eb; font-size: 9px; color: #999; }
</style>
</head>
<body>
<div class="page">
  <h1>Dependency Risk Radar — Analysis Report</h1>
  <p class="meta">
    Project: <strong>{{ report.project_name }}</strong> v{{ report.project_version }} &nbsp;·&nbsp;
    Generated: {{ report.analyzed_at[:19] }} &nbsp;·&nbsp;
    Report ID: {{ report.report_id }}
  </p>

  <h2>Global Risk Score</h2>
  <div class="score-box score-{{ risk_class }}">{{ report.global_risk_score }}/100 — {{ risk_label }}</div>

  <div class="stats-grid">
    <div class="stat-card"><div class="val">{{ summary.total_components }}</div><div class="lbl">Total</div></div>
    <div class="stat-card"><div class="val" style="color:#dc2626">{{ summary.vulnerable_components }}</div><div class="lbl">Vulnerable</div></div>
    <div class="stat-card"><div class="val">{{ summary.total_cves }}</div><div class="lbl">CVEs</div></div>
    <div class="stat-card"><div class="val" style="color:#ca8a04">{{ summary.copyleft_components }}</div><div class="lbl">Copyleft</div></div>
    <div class="stat-card"><div class="val" style="color:#7c3aed">{{ summary.tracker_components }}</div><div class="lbl">Trackers</div></div>
  </div>

  {% if update_plan and update_plan.executive_summary %}
  <h2>Executive Summary (AI)</h2>
  <div class="summary-box">{{ update_plan.executive_summary }}</div>
  {% endif %}

  <h2>Critical & High Risk Components</h2>
  <table>
    <tr>
      <th>Component</th><th>Version</th><th>Latest</th><th>Score</th>
      <th>CVEs</th><th>Licence</th><th>Level</th>
    </tr>
    {% for c in critical_components %}
    <tr>
      <td><strong>{{ c.name }}</strong><br><small style="color:#888">{{ 'Direct' if c.is_direct else 'Transitive (depth ' + c.depth|string + ')' }}</small></td>
      <td style="font-family:monospace">{{ c.version }}</td>
      <td style="font-family:monospace;color:{% if c.latest_version and c.latest_version != c.version %}#ea580c{% else %}#16a34a{% endif %}">{{ c.latest_version or '?' }}</td>
      <td><strong>{{ c.scores.global }}</strong></td>
      <td>{{ c.vulnerabilities|length }}</td>
      <td>{{ c.license.spdx_id if c.license else 'Unknown' }}</td>
      <td><span class="badge badge-{{ c.scores.risk_level|lower }}">{{ c.scores.risk_level }}</span></td>
    </tr>
    {% endfor %}
    {% if not critical_components %}
    <tr><td colspan="7" style="text-align:center;color:#16a34a;padding:12px">✓ No critical or high-risk components detected</td></tr>
    {% endif %}
  </table>

  {% if update_plan and update_plan.updates %}
  <h2>AI Update Plan</h2>
  {% for u in update_plan.updates[:15] %}
  <div class="plan-item">
    <div>
      <span class="badge badge-{{ u.priority|lower }}">{{ u.priority }}</span>
      <strong style="margin-left:8px">{{ u.name }}</strong>
      <span style="font-family:monospace;font-size:10px;color:#888;margin-left:8px">{{ u.current_version }} → {{ u.recommended_version }}</span>
      <span class="badge" style="background:#e5e7eb;color:#374151;margin-left:8px">{{ u.action }}</span>
    </div>
    <div class="reason">{{ u.main_reason }}</div>
    <div class="meta">Breaking risk: {{ u.breaking_risk }} · Effort: {{ u.migration_effort }}</div>
    {% if u.notes %}
    <div class="meta" style="color:#444;margin-top:3px">📝 {{ u.notes }}</div>
    {% endif %}
  </div>
  {% endfor %}
  {% endif %}

  <h2>Full Component List</h2>
  <table>
    <tr><th>Component</th><th>Version</th><th>Scope</th><th>Score</th><th>CVEs</th><th>Licence</th><th>Level</th></tr>
    {% for c in all_components %}
    <tr>
      <td>{{ c.name }}</td>
      <td style="font-family:monospace">{{ c.version }}</td>
      <td style="color:#888">{{ c.scope }}</td>
      <td>{{ c.scores.global }}</td>
      <td>{{ c.vulnerabilities|length }}</td>
      <td>{{ c.license.spdx_id if c.license else '?' }}</td>
      <td><span class="badge badge-{{ c.scores.risk_level|lower }}">{{ c.scores.risk_level }}</span></td>
    </tr>
    {% endfor %}
  </table>

  <div class="footer">
    Generated by Dependency Risk Radar v1.0 · {{ report.analyzed_at[:10] }} ·
    Scores: CVE×0.45 + Obsolescence×0.25 + Licence×0.20 + Tracker×0.10
  </div>
</div>
</body>
</html>
"""


def _risk_class_label(score: float) -> tuple[str, str]:
    if score >= 90: return "blocking",  "BLOCKING"
    if score >= 75: return "critical",  "CRITICAL"
    if score >= 50: return "high",      "HIGH"
    if score >= 20: return "moderate",  "MODERATE"
    return "low", "LOW"


def export_pdf(report: AnalysisReport, output_path: Path) -> Path:
    """Render the HTML template and convert to PDF via WeasyPrint."""
    try:
        from weasyprint import HTML as WeasyprintHTML
    except ImportError:
        raise RuntimeError("WeasyPrint is not installed. Run: pip install weasyprint")

    from app.scoring.engine import compute_project_summary

    summary      = compute_project_summary(report.components)
    risk_cls, risk_lbl = _risk_class_label(report.global_risk_score)
    update_plan  = report.update_plan or {}

    critical_comps = sorted(
        [c for c in report.components if c.scores.global_score >= 50],
        key=lambda c: -c.scores.global_score,
    )

    all_comps = sorted(report.components, key=lambda c: -c.scores.global_score)

    # We pass component dicts (not objects) so Jinja can access nested keys
    tpl = Template(HTML_TEMPLATE)
    html = tpl.render(
        report=report,
        summary=summary,
        risk_class=risk_cls,
        risk_label=risk_lbl,
        update_plan=update_plan,
        critical_components=[_comp_to_tpl(c) for c in critical_comps],
        all_components=[_comp_to_tpl(c) for c in all_comps],
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    WeasyprintHTML(string=html).write_pdf(str(output_path))
    return output_path


def _comp_to_tpl(c):
    """Lightweight view object for the Jinja template."""
    class _V:
        pass
    v = _V()
    v.name       = c.name
    v.version    = c.version
    v.scope      = c.scope.value
    v.is_direct  = c.is_direct
    v.depth      = c.depth
    v.latest_version = c.latest_version
    v.license    = c.license
    v.vulnerabilities = c.vulnerabilities
    v.scores     = c.scores
    return v


# ─────────────────────────────────────────────
# CSV exporter
# ─────────────────────────────────────────────

import csv


def export_csv(report: AnalysisReport, output_path: Path) -> Path:
    """Export component list to CSV for spreadsheet analysis."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "purl", "name", "group", "artifact", "version", "latest_version",
        "scope", "is_direct", "depth",
        "score_global", "score_cve", "score_obsolescence", "score_licence", "score_tracker",
        "risk_level", "cve_count", "max_cvss",
        "license_spdx", "license_is_copyleft",
        "tracker_count", "tracker_names",
        "direct_ancestor", "transitive_risk_score",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for c in sorted(report.components, key=lambda x: -x.scores.global_score):
            writer.writerow({
                "purl":                c.purl,
                "name":                c.name,
                "group":               c.group,
                "artifact":            c.artifact,
                "version":             c.version,
                "latest_version":      c.latest_version or "",
                "scope":               c.scope.value,
                "is_direct":           c.is_direct,
                "depth":               c.depth,
                "score_global":        c.scores.global_score,
                "score_cve":           c.scores.cve_score,
                "score_obsolescence":  c.scores.obsolescence_score,
                "score_licence":       c.scores.licence_score,
                "score_tracker":       c.scores.tracker_score,
                "risk_level":          c.scores.risk_level.value,
                "cve_count":           c.cve_count,
                "max_cvss":            c.max_cvss or "",
                "license_spdx":        c.license.spdx_id if c.license else "",
                "license_is_copyleft": c.license.is_copyleft if c.license else False,
                "tracker_count":       len(c.trackers),
                "tracker_names":       "|".join(t.name for t in c.trackers),
                "direct_ancestor":     c.direct_ancestor or "",
                "transitive_risk_score": c.transitive_risk_score,
            })

    return output_path
