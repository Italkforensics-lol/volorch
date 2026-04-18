"""
html_reporter.py
Generates a standalone HTML threat report with Chart.js visualizations.
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict

from volorch.correlator import ProcessThreatReport

SEVERITY_COLORS_HEX = {
    "CRITICAL": "#dc3545",
    "HIGH":     "#fd7e14",
    "MEDIUM":   "#ffc107",
    "LOW":      "#17a2b8",
    "INFO":     "#6c757d",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def generate_html(reports: Dict[int, ProcessThreatReport],
                  dump_path: str,
                  output_path: str = "reports/report.html") -> str:
    """Generate a standalone HTML threat report."""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    sorted_reports = sorted(
        reports.values(), key=lambda r: r.score, reverse=True
    )

    # Severity counts for pie chart
    counts = {}
    for r in sorted_reports:
        counts[r.severity] = counts.get(r.severity, 0) + 1

    pie_labels  = [s for s in SEVERITY_ORDER if counts.get(s, 0) > 0]
    pie_data    = [counts.get(s, 0) for s in pie_labels]
    pie_colors  = [SEVERITY_COLORS_HEX[s] for s in pie_labels]

    # Bar chart — top 10 by score
    top10       = sorted_reports[:10]
    bar_labels  = [f"PID {r.pid} ({r.name})" for r in top10]
    bar_data    = [r.score for r in top10]
    bar_colors  = [SEVERITY_COLORS_HEX[r.severity] for r in top10]

    # Process cards HTML
    cards_html = _build_cards(sorted_reports)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VolOrch Threat Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0d1117;
    color: #e6edf3;
    padding: 24px;
  }}
  .header {{
    border-bottom: 1px solid #21262d;
    padding-bottom: 20px;
    margin-bottom: 28px;
  }}
  .header h1 {{
    font-size: 1.8rem;
    color: #58a6ff;
    letter-spacing: 1px;
  }}
  .header .sub {{
    color: #8b949e;
    font-size: 0.85rem;
    margin-top: 4px;
  }}
  .meta-bar {{
    display: flex;
    gap: 24px;
    margin-bottom: 28px;
    flex-wrap: wrap;
  }}
  .meta-item {{
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 12px 20px;
    min-width: 140px;
  }}
  .meta-item .label {{
    font-size: 0.72rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
  }}
  .meta-item .value {{
    font-size: 1.4rem;
    font-weight: bold;
    color: #e6edf3;
    margin-top: 4px;
  }}
  .charts-row {{
    display: grid;
    grid-template-columns: 300px 1fr;
    gap: 20px;
    margin-bottom: 28px;
  }}
  .chart-box {{
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 20px;
  }}
  .chart-box h3 {{
    font-size: 0.85rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 14px;
  }}
  .section-title {{
    font-size: 0.85rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid #21262d;
  }}
  .card {{
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    margin-bottom: 14px;
    overflow: hidden;
  }}
  .card-header {{
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border-bottom: 1px solid #21262d;
  }}
  .badge {{
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: bold;
    letter-spacing: 1px;
  }}
  .card-title {{
    font-weight: bold;
    font-size: 0.95rem;
    flex: 1;
  }}
  .score-pill {{
    background: #21262d;
    border-radius: 20px;
    padding: 2px 12px;
    font-size: 0.8rem;
    color: #8b949e;
  }}
  .score-bar-wrap {{
    height: 4px;
    background: #21262d;
    border-radius: 2px;
    margin: 0 16px 0 16px;
    overflow: hidden;
  }}
  .score-bar-fill {{
    height: 100%;
    border-radius: 2px;
    transition: width 0.6s ease;
  }}
  .signals {{
    padding: 10px 16px 14px;
  }}
  .signal-row {{
    display: flex;
    gap: 10px;
    padding: 6px 0;
    border-bottom: 1px solid #0d1117;
    align-items: flex-start;
  }}
  .signal-row:last-child {{ border-bottom: none; }}
  .signal-pts {{
    background: #21262d;
    border-radius: 4px;
    padding: 1px 6px;
    font-size: 0.72rem;
    color: #8b949e;
    white-space: nowrap;
    margin-top: 2px;
  }}
  .signal-name {{
    font-size: 0.8rem;
    color: #58a6ff;
    font-weight: 600;
    white-space: nowrap;
  }}
  .signal-desc {{
    font-size: 0.78rem;
    color: #8b949e;
    margin-top: 2px;
  }}
  .signal-info {{ flex: 1; }}
</style>
</head>
<body>

<div class="header">
  <h1>VolOrch &mdash; Memory Forensics Threat Report</h1>
  <div class="sub">
    Dump: {os.path.basename(dump_path)} &nbsp;|&nbsp;
    Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp;
    by @italkforensics
  </div>
</div>

<div class="meta-bar">
  <div class="meta-item">
    <div class="label">Flagged PIDs</div>
    <div class="value">{len(sorted_reports)}</div>
  </div>
  {''.join(f'''
  <div class="meta-item">
    <div class="label">{sev}</div>
    <div class="value" style="color:{SEVERITY_COLORS_HEX[sev]}">{counts.get(sev, 0)}</div>
  </div>''' for sev in SEVERITY_ORDER if counts.get(sev, 0) > 0)}
</div>

<div class="charts-row">
  <div class="chart-box">
    <h3>Severity Distribution</h3>
    <canvas id="pieChart" height="220"></canvas>
  </div>
  <div class="chart-box">
    <h3>Top Processes by Threat Score</h3>
    <canvas id="barChart" height="220"></canvas>
  </div>
</div>

<div class="section-title">Threat Reports</div>
{cards_html}

<script>
// Pie chart
new Chart(document.getElementById('pieChart'), {{
  type: 'doughnut',
  data: {{
    labels: {json.dumps(pie_labels)},
    datasets: [{{
      data: {json.dumps(pie_data)},
      backgroundColor: {json.dumps(pie_colors)},
      borderWidth: 0
    }}]
  }},
  options: {{
    plugins: {{
      legend: {{
        labels: {{ color: '#8b949e', font: {{ size: 11 }} }}
      }}
    }}
  }}
}});

// Bar chart
new Chart(document.getElementById('barChart'), {{
  type: 'bar',
  data: {{
    labels: {json.dumps(bar_labels)},
    datasets: [{{
      label: 'Threat Score',
      data: {json.dumps(bar_data)},
      backgroundColor: {json.dumps(bar_colors)},
      borderRadius: 4,
      borderWidth: 0
    }}]
  }},
  options: {{
    indexAxis: 'y',
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{
        ticks: {{ color: '#8b949e' }},
        grid:  {{ color: '#21262d' }}
      }},
      y: {{
        ticks: {{ color: '#8b949e', font: {{ size: 10 }} }},
        grid:  {{ color: '#21262d' }}
      }}
    }}
  }}
}});
</script>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)

    print(f"[+] HTML report saved -> {output_path}")
    return output_path


# ── Helpers ──────────────────────────────────────────────────────────────────

def _build_cards(sorted_reports) -> str:
    cards = []
    for r in sorted_reports:
        color     = SEVERITY_COLORS_HEX[r.severity]
        score_pct = min(r.score, 100)

        signals_html = ""
        for s in r.signals:
            signals_html += f"""
        <div class="signal-row">
          <div class="signal-pts">+{s.weight}</div>
          <div class="signal-info">
            <div class="signal-name">{s.name.replace("_", " ")}</div>
            <div class="signal-desc">{s.description[:120]}</div>
          </div>
        </div>"""

        card = f"""
<div class="card">
  <div class="card-header">
    <span class="badge" style="background:{color};color:{'#000' if r.severity == 'MEDIUM' else '#fff'}">{r.severity}</span>
    <span class="card-title">PID {r.pid} &mdash; {r.name}</span>
    <span class="score-pill">Score: {r.score}</span>
  </div>
  <div class="score-bar-wrap">
    <div class="score-bar-fill" style="width:{score_pct}%;background:{color}"></div>
  </div>
  <div class="signals">{signals_html}
  </div>
</div>"""
        cards.append(card)

    return "\n".join(cards)