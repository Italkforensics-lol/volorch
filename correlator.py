"""
correlator.py
Cross-plugin correlation engine.
Scores each process based on signals detected across all plugins.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from volorch.extractor import ExtractedData


# ── Scoring Weights (mirrors config/weights.yaml) ────────────────────────────

WEIGHTS = {
    "malfind_executable_memory":   30,  # RWX/RX region found by malfind
    "malfind_hit":                 15,  # Any malfind hit (non-executable)
    "external_network_connection": 20,  # Active outbound connection
    "suspicious_cmdline":          20,  # Encoded/LOLBin command line
    "suspicious_dll_path":         15,  # DLL loaded from temp/appdata
    "malfind_and_network_overlap": 25,  # Same PID in both malfind + netscan
    "no_parent_process":           10,  # PPID not found in process list
    "unusual_process_name":        10,  # Known-bad or spoofed process names
}

# Severity thresholds
SEVERITY = [
    (75, "CRITICAL"),
    (50, "HIGH"),
    (25, "MEDIUM"),
    (10, "LOW"),
    (0,  "INFO"),
]


# ── Result Models ────────────────────────────────────────────────────────────

@dataclass
class Signal:
    """A single correlated finding for a process."""
    name:        str
    description: str
    weight:      int


@dataclass
class ProcessThreatReport:
    """Threat report for a single process."""
    pid:       int
    name:      str
    score:     int                  = 0
    severity:  str                  = "INFO"
    signals:   List[Signal]         = field(default_factory=list)

    def add_signal(self, name: str, description: str, weight: int):
        self.signals.append(Signal(name, description, weight))
        self.score += weight
        self.severity = _score_to_severity(self.score)

    def to_dict(self) -> dict:
        return {
            "pid":      self.pid,
            "name":     self.name,
            "score":    self.score,
            "severity": self.severity,
            "signals":  [
                {"name": s.name, "description": s.description, "weight": s.weight}
                for s in self.signals
            ]
        }


# ── Correlator ───────────────────────────────────────────────────────────────

def correlate(data: ExtractedData) -> Dict[int, ProcessThreatReport]:
    """
    Run all correlation checks across extracted plugin data.
    Returns a dict of { pid: ProcessThreatReport } for processes with score > 0.
    """
    reports: Dict[int, ProcessThreatReport] = {}

    all_pids = set(data.processes.keys())

    for pid, proc in data.processes.items():
        report = ProcessThreatReport(pid=pid, name=proc.name)

        # ── Check 1: Malfind hits ────────────────────────────────────────────
        malfind_hits = data.malfind.get(pid, [])
        executable_hits = [h for h in malfind_hits if h.is_executable]

        if executable_hits:
            report.add_signal(
                "malfind_executable_memory",
                f"{len(executable_hits)} executable memory region(s) with "
                f"protection: {', '.join(set(h.protection for h in executable_hits))}",
                WEIGHTS["malfind_executable_memory"]
            )
        elif malfind_hits:
            report.add_signal(
                "malfind_hit",
                f"{len(malfind_hits)} suspicious memory region(s) flagged by malfind",
                WEIGHTS["malfind_hit"]
            )

        # ── Check 2: External network connections ────────────────────────────
        net_conns = data.network.get(pid, [])
        external  = [c for c in net_conns if c.is_external]

        if external:
            destinations = list(set(
                f"{c.foreign_addr}:{c.foreign_port}" for c in external
            ))[:5]  # cap display at 5
            report.add_signal(
                "external_network_connection",
                f"{len(external)} external connection(s) → {', '.join(destinations)}",
                WEIGHTS["external_network_connection"]
            )

        # ── Check 3: Malfind + network overlap (bonus signal) ────────────────
        if malfind_hits and external:
            report.add_signal(
                "malfind_and_network_overlap",
                f"Process has both injected memory AND active external connections - "
                f"strong C2 indicator",
                WEIGHTS["malfind_and_network_overlap"]
            )

        # ── Check 4: Suspicious command line ────────────────────────────────
        cmd = data.cmdlines.get(pid)
        if cmd and cmd.is_suspicious:
            report.add_signal(
                "suspicious_cmdline",
                f"Suspicious args detected: {cmd.args[:100]}",
                WEIGHTS["suspicious_cmdline"]
            )

        # ── Check 5: DLLs loaded from suspicious paths ───────────────────────
        dlls = data.dlls.get(pid, [])
        suspicious_dlls = [d for d in dlls if d.is_suspicious_path]
        if suspicious_dlls:
            paths = list(set(d.path for d in suspicious_dlls))[:3]
            report.add_signal(
                "suspicious_dll_path",
                f"{len(suspicious_dlls)} DLL(s) from suspicious path(s): "
                f"{', '.join(paths)}",
                WEIGHTS["suspicious_dll_path"]
            )

        # ── Check 6: Orphan process (PPID not in process list) ───────────────
        if proc.ppid not in all_pids and proc.ppid != 0:
            report.add_signal(
                "no_parent_process",
                f"Parent PID {proc.ppid} not found in process list — "
                f"possible process hiding",
                WEIGHTS["no_parent_process"]
            )

        # ── Check 7: Unusual process names ───────────────────────────────────
        if _is_unusual_process(proc.name):
            report.add_signal(
                "unusual_process_name",
                f"Process name '{proc.name}' matches known suspicious pattern",
                WEIGHTS["unusual_process_name"]
            )

        # Only include processes with at least one signal
        if report.signals:
            reports[pid] = report

    return reports


# ── Helpers ──────────────────────────────────────────────────────────────────

# Processes that are unusual in normal Windows environments
UNUSUAL_PROCESSES = {
    "mspaint.exe", "notepad.exe", "calc.exe", "wordpad.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "certutil.exe", "bitsadmin.exe",
}

def _is_unusual_process(name: str) -> bool:
    return name.lower() in UNUSUAL_PROCESSES


def _score_to_severity(score: int) -> str:
    if score >= 75: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    if score >= 10: return "LOW"
    return "INFO"


# ── CLI test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import json
    sys.path.insert(0, ".")
    from volorch.runner import orchestrate
    from volorch.extractor import extract

    if len(sys.argv) < 2:
        print("Usage: python correlator.py <dump_path>")
        sys.exit(1)

    print("[*] Running plugins...")
    raw  = orchestrate(sys.argv[1])
    data = extract(raw)

    print("[*] Correlating...\n")
    reports = correlate(data)

    # Sort by score descending
    sorted_reports = sorted(reports.values(), key=lambda r: r.score, reverse=True)

    print(f"── Threat Reports ({len(sorted_reports)} processes flagged) ──────────")
    for r in sorted_reports:
        print(f"\n  [{r.severity}] PID {r.pid} — {r.name} (score: {r.score})")
        for s in r.signals:
            print(f"    ✗ [{s.weight:>3}] {s.name}")
            print(f"          {s.description}")