"""
main.py
VolOrch - Volatility Plugin Orchestrator
Entry point for the full memory forensics analysis pipeline.

Usage:
    python main.py <dump_path> [options]
"""

import argparse
import os
import sys
import time
import datetime

def banner():
    print("""
__     __    _  ___             _
\ \   / /__ | |/ _ \ _ __ ___| |__
 \ \ / / _ \| | | | | '__/ __| '_ \\
  \ V / (_) | | |_| | | | (__| | | |
   \_/ \___/|_|\___/|_|  \___|_| |_|

  Volatility Plugin Orchestrator v1.0.0
  Memory Forensics Threat Correlation Engine
  by Adarsh V P @italkforensics
    """)

def parse_args():
    parser = argparse.ArgumentParser(
        description="VolOrch - Automated Volatility Plugin Orchestrator"
    )
    parser.add_argument(
        "dump",
        help="Path to memory dump file (.raw, .vmem, .dmp, .elf)"
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="reports",
        help="Directory to save reports (default: reports/)"
    )
    parser.add_argument(
        "--symbol-dirs", "-s",
        default=None,
        help="Additional symbol directory path"
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=0,
        help="Only report processes with score >= this value (default: 0)"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    from volorch.visualizer import (
        console, render_banner, render_progress,
        render_plugin_row, render_threat_table,
        render_severity_chart, render_top_threats,
        render_final_summary
    )

    render_banner()

    # ── Validate dump ────────────────────────────────────────────────────────
    if not os.path.isfile(args.dump):
        console.print(f"[bold red][!] Dump file not found:[/] {args.dump}")
        sys.exit(1)

    symbol_dirs = [os.path.abspath(args.symbol_dirs)] if args.symbol_dirs else None
    total_start = time.time()

    # ── Step 1: Run plugins ──────────────────────────────────────────────────
    render_progress(1, 3, "Running Volatility Plugins")

    from volorch.runner import orchestrate, PLUGINS
    raw = orchestrate(args.dump, symbol_dirs)

    console.print()
    for name, rows in raw.items():
        render_plugin_row(name, len(rows))
    console.print()

    # ── Step 2: Extract + Correlate ──────────────────────────────────────────
    render_progress(2, 3, "Extracting & Correlating")

    from volorch.extractor import extract
    from volorch.correlator import correlate

    data    = extract(raw)
    reports = correlate(data)

    # Apply min score filter
    if args.min_score > 0:
        reports = {
            pid: r for pid, r in reports.items()
            if r.score >= args.min_score
        }

    # Render terminal visuals
    render_threat_table(reports)
    render_severity_chart(reports)
    render_top_threats(reports, top_n=3)

    # ── Step 3: Generate Reports ─────────────────────────────────────────────
    render_progress(3, 3, "Generating Reports")

    from volorch.reporter import generate_json, generate_pdf
    from volorch.html_reporter import generate_html

    base      = os.path.splitext(os.path.basename(args.dump))[0]
    ts        = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir   = args.output_dir
    os.makedirs(out_dir, exist_ok=True)

    paths = {}
    paths["json"] = generate_json(reports, args.dump,
                                  os.path.join(out_dir, f"{base}_{ts}.json"))
    paths["pdf"]  = generate_pdf(reports, args.dump,
                                 os.path.join(out_dir, f"{base}_{ts}.pdf"))
    paths["html"] = generate_html(reports, args.dump,
                                  os.path.join(out_dir, f"{base}_{ts}.html"))

    # ── Final summary ────────────────────────────────────────────────────────
    elapsed = time.time() - total_start
    render_final_summary(reports, args.dump, elapsed, paths)


if __name__ == "__main__":
    main()
