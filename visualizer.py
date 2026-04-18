"""
visualizer.py
Terminal-based threat visualization using Rich.
Renders threat summary tables and score distribution charts.
"""

from typing import Dict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich.rule import Rule
from rich import box

from volorch.correlator import ProcessThreatReport

console = Console()

SEVERITY_STYLES = {
    "CRITICAL": "bold white on red",
    "HIGH":     "bold white on dark_orange",
    "MEDIUM":   "bold black on yellow",
    "LOW":      "bold white on cyan",
    "INFO":     "bold white on grey50",
}

SEVERITY_DOTS = {
    "CRITICAL": "[bold red]●[/]",
    "HIGH":     "[bold dark_orange]●[/]",
    "MEDIUM":   "[bold yellow]●[/]",
    "LOW":      "[bold cyan]●[/]",
    "INFO":     "[bold grey50]●[/]",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
BAR_CHAR       = "█"
EMPTY_CHAR     = "░"
BAR_WIDTH      = 20


def render_banner():
    """Render the VolOrch banner."""
    banner = Text(justify="center")
    banner.append("\n")
    banner.append("  VolOrch  ", style="bold white on dark_blue")
    banner.append("  v1.0.0\n", style="bold cyan")
    banner.append("  Volatility Plugin Orchestrator\n", style="white")
    banner.append("  Memory Forensics Threat Correlation Engine\n", style="dim white")
    banner.append("  by @italkforensics\n", style="bold magenta")

    console.print(Panel(banner, border_style="dark_blue", padding=(0, 4)))
    console.print()


def render_progress(step: int, total: int, label: str):
    """Render a step progress indicator."""
    console.print(Rule(
        f"[bold cyan]STEP {step}/{total}[/] [white]{label}[/]",
        style="dim cyan"
    ))
    console.print()


def render_plugin_row(name: str, count: int):
    """Print a single plugin result row."""
    bar_len  = min(count // 10, 30)
    bar      = f"[green]{BAR_CHAR * bar_len}[/]"
    console.print(f"  [cyan]{name:<12}[/] {bar} [dim]{count} rows[/]")


def render_threat_table(reports: Dict[int, ProcessThreatReport]):
    """Render the main threat summary table."""
    console.print()
    console.print(Rule("[bold white]Threat Summary[/]", style="dim white"))
    console.print()

    table = Table(
        box=box.ROUNDED,
        border_style="dim white",
        header_style="bold white on grey23",
        show_lines=True,
        expand=False
    )

    table.add_column("PID",      style="bold cyan",  width=7,  justify="right")
    table.add_column("Process",  style="white",       width=20)
    table.add_column("Score",    style="bold white",  width=7,  justify="center")
    table.add_column("Severity", width=12,            justify="center")
    table.add_column("Signals",  style="dim white",   width=50)

    sorted_reports = sorted(
        reports.values(), key=lambda r: r.score, reverse=True
    )

    for r in sorted_reports:
        sev_style = SEVERITY_STYLES.get(r.severity, "white")
        sev_cell  = Text(f" {r.severity} ", style=sev_style, justify="center")

        signal_names = ", ".join(s.name.replace("_", " ") for s in r.signals)
        if len(signal_names) > 48:
            signal_names = signal_names[:45] + "..."

        # Score bar (mini)
        score_bar = _mini_score_bar(r.score)

        table.add_row(
            str(r.pid),
            r.name,
            f"{r.score}  {score_bar}",
            sev_cell,
            signal_names
        )

    console.print(table)
    console.print()


def render_severity_chart(reports: Dict[int, ProcessThreatReport]):
    """Render severity distribution bar chart."""
    counts = {}
    for r in reports.values():
        counts[r.severity] = counts.get(r.severity, 0) + 1

    total = sum(counts.values()) or 1

    console.print(Rule("[bold white]Severity Distribution[/]", style="dim white"))
    console.print()

    for sev in SEVERITY_ORDER:
        count    = counts.get(sev, 0)
        filled   = int((count / total) * BAR_WIDTH)
        empty    = BAR_WIDTH - filled
        dot      = SEVERITY_DOTS[sev]
        bar      = f"[bold {'red' if sev == 'CRITICAL' else 'dark_orange' if sev == 'HIGH' else 'yellow' if sev == 'MEDIUM' else 'cyan' if sev == 'LOW' else 'grey50'}]{BAR_CHAR * filled}[/][dim]{EMPTY_CHAR * empty}[/]"
        console.print(f"  {dot} [bold]{sev:<10}[/] {bar}  [bold]{count}[/]")

    console.print()


def render_top_threats(reports: Dict[int, ProcessThreatReport], top_n: int = 3):
    """Render detailed signal breakdown for top N threats."""
    sorted_reports = sorted(
        reports.values(), key=lambda r: r.score, reverse=True
    )[:top_n]

    console.print(Rule(f"[bold white]Top {top_n} Threats — Signal Detail[/]", style="dim white"))
    console.print()

    for r in sorted_reports:
        sev_style = SEVERITY_STYLES.get(r.severity, "white")
        header    = Text()
        header.append(f" {r.severity} ", style=sev_style)
        header.append(f"  PID {r.pid} — {r.name}", style="bold white")
        header.append(f"  (score: {r.score})", style="dim white")

        signal_lines = []
        for s in r.signals:
            signal_lines.append(
                f"  [bold red]✗[/] [[bold]{s.weight:>3} pts[/]]  "
                f"[cyan]{s.name}[/]\n"
                f"        [dim]{s.description[:90]}[/]"
            )

        body = "\n".join(signal_lines)
        console.print(Panel(
            header.__str__() + "\n\n" + body,
            border_style="dim white",
            padding=(0, 2)
        ))
        console.print()


def render_final_summary(reports: Dict[int, ProcessThreatReport],
                         dump_path: str,
                         elapsed: float,
                         output_paths: dict):
    """Render the final completion summary."""
    import os

    console.print(Rule("[bold green]Analysis Complete[/]", style="green"))
    console.print()

    lines = [
        f"[dim]Dump         :[/] [white]{os.path.basename(dump_path)}[/]",
        f"[dim]Time elapsed :[/] [white]{elapsed:.1f}s[/]",
        f"[dim]Flagged PIDs :[/] [bold white]{len(reports)}[/]",
    ]
    for fmt, path in output_paths.items():
        lines.append(f"[dim]{fmt.upper():<5} report  :[/] [bold cyan]{path}[/]")

    console.print("\n".join(lines))
    console.print()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mini_score_bar(score: int) -> str:
    """Return a tiny inline score bar."""
    filled = min(score // 10, 10)
    empty  = 10 - filled
    if score >= 75:
        color = "red"
    elif score >= 50:
        color = "dark_orange"
    elif score >= 25:
        color = "yellow"
    else:
        color = "cyan"
    return f"[{color}]{BAR_CHAR * filled}[/][dim]{EMPTY_CHAR * empty}[/]"