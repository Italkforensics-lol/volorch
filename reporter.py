"""
reporter.py
Generates structured JSON and PDF threat reports from correlator output.
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict, List

from fpdf import FPDF

from volorch.correlator import ProcessThreatReport


# ── Severity colours (for PDF) ───────────────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": (220, 53,  69),
    "HIGH":     (255, 140,  0),
    "MEDIUM":   (255, 193,  7),
    "LOW":      (23,  162, 184),
    "INFO":     (108, 117, 125),
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ── JSON Report ──────────────────────────────────────────────────────────────

def generate_json(reports: Dict[int, ProcessThreatReport],
                  dump_path: str,
                  output_path: str = "reports/report.json") -> str:
    """Serialize threat reports to a structured JSON file."""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    sorted_reports = sorted(
        reports.values(), key=lambda r: r.score, reverse=True
    )

    payload = {
        "meta": {
            "tool":       "VolOrch — Volatility Plugin Orchestrator",
            "version":    "1.0.0",
            "dump":       os.path.abspath(dump_path),
            "generated":  datetime.now(timezone.utc).isoformat(),
            "total_flagged": len(reports),
            "severity_counts": _severity_counts(sorted_reports),
        },
        "reports": [r.to_dict() for r in sorted_reports]
    }

    with open(output_path, "w") as f:
        json.dump(payload, f, indent=2)

    print(f"[+] JSON report saved → {output_path}")
    return output_path


# ── PDF Report ───────────────────────────────────────────────────────────────

class VolOrchPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(30, 30, 30)
        self.cell(0, 10, "VolOrch Memory Forensics Threat Report", align="L")
        self.set_font("Helvetica", "", 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, datetime.now().strftime("%Y-%m-%d %H:%M UTC"), align="R")
        self.ln(4)
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()} | VolOrch v1.0.0", align="C")


def generate_pdf(reports: Dict[int, ProcessThreatReport],
                 dump_path: str,
                 output_path: str = "reports/report.pdf") -> str:
    """Generate a formatted PDF threat report."""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    sorted_reports = sorted(
        reports.values(), key=lambda r: r.score, reverse=True
    )

    pdf = VolOrchPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()
    pdf.set_margins(10, 10, 10)

    # ── Cover summary ────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, "Analysis Summary", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 6, f"Dump file  : {os.path.basename(dump_path)}", ln=True)
    pdf.cell(0, 6, f"Processes flagged : {len(reports)}", ln=True)

    counts = _severity_counts(sorted_reports)
    summary_line = "  ".join(
        f"{sev}: {counts.get(sev, 0)}" for sev in SEVERITY_ORDER if counts.get(sev, 0) > 0
    )
    pdf.cell(0, 6, f"Severity breakdown: {summary_line}", ln=True)
    pdf.ln(4)

    # ── Severity legend ──────────────────────────────────────────────────────
    _draw_legend(pdf)
    pdf.ln(6)

    # ── Per-process threat cards ─────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, "Threat Reports", ln=True)
    pdf.ln(2)

    for r in sorted_reports:
        _draw_process_card(pdf, r)
        pdf.ln(3)

    pdf.output(output_path)
    print(f"[+] PDF report saved → {output_path}")
    return output_path


# ── PDF Helpers ──────────────────────────────────────────────────────────────
def _safe(text: str) -> str:
    """Replace unicode characters that latin-1 can't encode."""
    return (text
        .replace("\u2014", "-")   # em dash
        .replace("\u2013", "-")   # en dash
        .replace("\u2018", "'")   # left single quote
        .replace("\u2019", "'")   # right single quote
        .replace("\u201c", '"')   # left double quote
        .replace("\u201d", '"')   # right double quote
        .encode("latin-1", errors="replace")
        .decode("latin-1")
    )

def _draw_legend(pdf: FPDF):
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 5, "Severity Scale:", ln=True)
    pdf.set_font("Helvetica", "", 8)
    x_start = pdf.get_x()
    for sev in SEVERITY_ORDER:
        r, g, b = SEVERITY_COLORS[sev]
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(22, 5, sev, fill=True, align="C")
        pdf.set_x(pdf.get_x() + 2)
    pdf.ln(7)


def _draw_process_card(pdf: FPDF, r: ProcessThreatReport):
    color = SEVERITY_COLORS.get(r.severity, (108, 117, 125))

    # Card header bar
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(0, 7,
             _safe(f"  [{r.severity}]  PID {r.pid} — {r.name}   |   Score: {r.score}"),
             fill=True, ln=True)

    # Signal rows
    pdf.set_fill_color(245, 245, 245)
    pdf.set_text_color(40, 40, 40)
    pdf.set_font("Helvetica", "", 8)

    for s in r.signals:
        # Signal name row
        pdf.set_fill_color(230, 230, 230)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(0, 5, _safe(f"  [{s.weight:>3} pts]  {s.name}"), fill=True, ln=True)

        # Description row
        pdf.set_fill_color(248, 248, 248)
        pdf.set_font("Helvetica", "", 8)
        # Wrap long descriptions
        desc = s.description if len(s.description) <= 110 else s.description[:107] + "..."
        pdf.cell(0, 5, _safe(f"           {desc}"), fill=True, ln=True)

    pdf.set_draw_color(200, 200, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())


# ── Combined Report Generator ────────────────────────────────────────────────

def generate_report(reports: Dict[int, ProcessThreatReport],
                    dump_path: str,
                    output_dir: str = "reports") -> dict:
    """Generate both JSON and PDF reports. Returns paths to both files."""
    base = os.path.splitext(os.path.basename(dump_path))[0]
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(output_dir, f"{base}_{ts}.json")
    pdf_path  = os.path.join(output_dir, f"{base}_{ts}.pdf")

    json_out = generate_json(reports, dump_path, json_path)
    pdf_out  = generate_pdf(reports, dump_path, pdf_path)

    return {"json": json_out, "pdf": pdf_out}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _severity_counts(reports: List[ProcessThreatReport]) -> dict:
    counts = {}
    for r in reports:
        counts[r.severity] = counts.get(r.severity, 0) + 1
    return counts


# ── CLI test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from volorch.runner import orchestrate
    from volorch.extractor import extract
    from volorch.correlator import correlate

    if len(sys.argv) < 2:
        print("Usage: python reporter.py <dump_path>")
        sys.exit(1)

    print("[*] Running plugins...")
    raw     = orchestrate(sys.argv[1])
    data    = extract(raw)

    print("[*] Correlating...")
    reports = correlate(data)

    print("[*] Generating reports...")
    paths   = generate_report(reports, sys.argv[1])

    print(f"\n[+] Reports ready:")
    print(f"    JSON → {paths['json']}")
    print(f"    PDF  → {paths['pdf']}")

