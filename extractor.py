"""
extractor.py
Converts raw Volatility plugin rows into normalized, PID-keyed objects
ready for cross-plugin correlation.
"""

from typing import Dict, List


# ── Data Models ──────────────────────────────────────────────────────────────

class Process:
    """Represents a process from pstree."""
    def __init__(self, row: dict):
        self.pid        = _int(row.get("PID"))
        self.ppid       = _int(row.get("PPID"))
        self.name       = row.get("ImageFileName", "").strip()
        self.offset     = row.get("Offset(V)", "")
        self.threads    = _int(row.get("Threads"))
        self.handles    = _int(row.get("Handles"))
        self.session    = row.get("SessionId", "")
        self.wow64      = row.get("Wow64", "False") == "True"
        self.create_time = row.get("CreateTime", "")
        self.exit_time  = row.get("ExitTime", "")
        self.path       = row.get("Path", "")
        self.cmd        = row.get("Cmd", "")

    def __repr__(self):
        return f"<Process pid={self.pid} name={self.name}>"


class NetworkConnection:
    """Represents a network connection from netscan."""
    def __init__(self, row: dict):
        self.pid          = _int(row.get("PID"))
        self.owner        = row.get("Owner", "").strip()
        self.proto        = row.get("Proto", "")
        self.local_addr   = row.get("LocalAddr", "")
        self.local_port   = row.get("LocalPort", "")
        self.foreign_addr = row.get("ForeignAddr", "")
        self.foreign_port = row.get("ForeignPort", "")
        self.state        = row.get("State", "")
        self.created      = row.get("Created", "")

    @property
    def is_external(self) -> bool:
        """True if the foreign address is not loopback or empty."""
        addr = self.foreign_addr
        return bool(addr) and not addr.startswith("127.") and addr not in ("0.0.0.0", "::", "")

    def __repr__(self):
        return f"<NetConn pid={self.pid} {self.local_addr}:{self.local_port} → {self.foreign_addr}:{self.foreign_port}>"


class MalfindHit:
    """Represents a suspicious memory region from malfind."""
    def __init__(self, row: dict):
        self.pid            = _int(row.get("PID"))
        self.process        = row.get("Process", "").strip()
        self.start_vpn      = row.get("Start VPN", "")
        self.end_vpn        = row.get("End VPN", "")
        self.tag            = row.get("Tag", "")
        self.protection     = row.get("Protection", "")
        self.commit_charge  = row.get("CommitCharge", "")
        self.private_memory = row.get("PrivateMemory", "")
        self.notes          = row.get("Notes", "")
        self.hexdump        = row.get("Hexdump", "")
        self.disasm         = row.get("Disasm", "")

    @property
    def is_executable(self) -> bool:
        """True if memory region has executable protection flags."""
        p = self.protection.upper()
        return any(flag in p for flag in ["EXECUTE", "PAGE_EXEC", "RX", "RWX", "WX"])

    def __repr__(self):
        return f"<MalfindHit pid={self.pid} proc={self.process} prot={self.protection}>"


class CommandLine:
    """Represents a process command line from cmdline."""
    def __init__(self, row: dict):
        self.pid     = _int(row.get("PID"))
        self.process = row.get("Process", "").strip()
        self.args    = row.get("Args", "").strip()

    @property
    def is_suspicious(self) -> bool:
        """Flag common suspicious command line patterns."""
        args_lower = self.args.lower()
        indicators = [
            "powershell", "cmd.exe", "wscript", "cscript",
            "base64", "encodedcommand", "-enc", "bypass",
            "hidden", "rundll32", "regsvr32", "mshta",
            "certutil", "bitsadmin", "wmic", "frombase64"
        ]
        return any(ind in args_lower for ind in indicators)

    def __repr__(self):
        return f"<CmdLine pid={self.pid} proc={self.process}>"


class DllEntry:
    """Represents a loaded DLL from dlllist."""
    def __init__(self, row: dict):
        self.pid        = _int(row.get("PID"))
        self.process    = row.get("Process", "").strip()
        self.base       = row.get("Base", "")
        self.size       = row.get("Size", "")
        self.name       = row.get("Name", "").strip()
        self.path       = row.get("Path", "").strip()
        self.load_count = row.get("LoadCount", "")
        self.load_time  = row.get("LoadTime", "")

    @property
    def is_suspicious_path(self) -> bool:
        """Flag DLLs loaded from unusual paths."""
        path_lower = self.path.lower()
        suspicious_paths = [
            "\\temp\\", "\\tmp\\", "\\appdata\\",
            "\\downloads\\", "\\public\\", "\\desktop\\",
            "\\recycle", "%temp%", "%appdata%"
        ]
        return any(p in path_lower for p in suspicious_paths)

    def __repr__(self):
        return f"<DllEntry pid={self.pid} name={self.name}>"


# ── Extracted Result Container ───────────────────────────────────────────────

class ExtractedData:
    """Holds all normalized plugin data, indexed by PID where applicable."""

    def __init__(self):
        self.processes:   Dict[int, Process]              = {}
        self.network:     Dict[int, List[NetworkConnection]] = {}
        self.malfind:     Dict[int, List[MalfindHit]]     = {}
        self.cmdlines:    Dict[int, CommandLine]           = {}
        self.dlls:        Dict[int, List[DllEntry]]        = {}

    def summary(self):
        print(f"  Processes   : {len(self.processes)}")
        print(f"  Net conns   : {sum(len(v) for v in self.network.values())}")
        print(f"  Malfind hits: {sum(len(v) for v in self.malfind.values())}")
        print(f"  Cmdlines    : {len(self.cmdlines)}")
        print(f"  DLL entries : {sum(len(v) for v in self.dlls.values())}")


# ── Extractor Functions ──────────────────────────────────────────────────────

def extract(raw: Dict[str, list]) -> ExtractedData:
    """
    Takes the raw orchestrate() output and returns a populated ExtractedData.
    """
    data = ExtractedData()

    # pstree → processes dict keyed by PID
    for row in raw.get("pstree", []):
        p = Process(row)
        if p.pid is not None:
            data.processes[p.pid] = p

    # netscan → network dict keyed by PID
    for row in raw.get("netscan", []):
        conn = NetworkConnection(row)
        if conn.pid is not None:
            data.network.setdefault(conn.pid, []).append(conn)

    # malfind → malfind dict keyed by PID
    for row in raw.get("malfind", []):
        hit = MalfindHit(row)
        if hit.pid is not None:
            data.malfind.setdefault(hit.pid, []).append(hit)

    # cmdline → cmdlines dict keyed by PID
    for row in raw.get("cmdline", []):
        cmd = CommandLine(row)
        if cmd.pid is not None:
            data.cmdlines[cmd.pid] = cmd

    # dlllist → dlls dict keyed by PID
    for row in raw.get("dlllist", []):
        dll = DllEntry(row)
        if dll.pid is not None:
            data.dlls.setdefault(dll.pid, []).append(dll)

    return data


# ── Helpers ──────────────────────────────────────────────────────────────────

def _int(val) -> int:
    """Safely convert a value to int, return None on failure."""
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


# ── CLI test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from volorch.runner import orchestrate

    if len(sys.argv) < 2:
        print("Usage: python extractor.py <dump_path>")
        sys.exit(1)

    raw  = orchestrate(sys.argv[1])
    data = extract(raw)

    print("\n── Extraction Summary ──────────────────────")
    data.summary()

    print("\n── Sample: first 3 processes ───────────────")
    for pid, proc in list(data.processes.items())[:3]:
        print(f"  {proc}")

    print("\n── Suspicious cmdlines ─────────────────────")
    for pid, cmd in data.cmdlines.items():
        if cmd.is_suspicious:
            print(f"  {cmd} → {cmd.args[:80]}")

    print("\n── Malfind hits with executable memory ─────")
    for pid, hits in data.malfind.items():
        for hit in hits:
            if hit.is_executable:
                print(f"  {hit}")

    print("\n── Processes with external network conns ───")
    for pid, conns in data.network.items():
        external = [c for c in conns if c.is_external]
        if external:
            proc_name = data.processes.get(pid, {})
            name = proc_name.name if proc_name else "unknown"
            print(f"  PID {pid} ({name}): {len(external)} external connection(s)")