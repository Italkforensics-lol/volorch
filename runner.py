import os
import logging
from typing import Dict, List, Optional

from volatility3.framework import contexts, automagic, constants
from volatility3.plugins.windows import pstree, netscan, malfind, cmdline, dlllist

logging.basicConfig(level=logging.WARNING)

# ── Plugin registry (direct class references) ────────────────────────────────
PLUGINS = {
    "pstree":  pstree.PsTree,
    "netscan": netscan.NetScan,
    "malfind": malfind.Malfind,
    "cmdline": cmdline.CmdLine,
    "dlllist":  dlllist.DllList,
}


def _bridge_config(ctx, config_path: str, class_name: str):
    """
    Automagic writes to {config_path}.{ClassName}.*
    but the plugin reads from {config_path}.*
    This copies keys across to bridge the gap.
    """
    prefix_src = f"{config_path}.{class_name}."
    prefix_dst = f"{config_path}."

    for key, val in list(ctx.config.items()):
        if key.startswith(prefix_src):
            new_key = prefix_dst + key[len(prefix_src):]
            if new_key not in ctx.config:
                ctx.config[new_key] = val


def _collect_rows(treegrid) -> List[dict]:
    """Walk a TreeGrid and return all rows as a list of dicts."""
    results = []
    columns = [col.name for col in treegrid.columns]

    def _visitor(node, _):
        row = {}
        for i, col in enumerate(columns):
            try:
                val = node.values[i]
                row[col] = str(val) if val is not None else ""
            except Exception:
                row[col] = ""
        results.append(row)

    treegrid.visit(None, _visitor, {})
    return results


def run_plugin(plugin_name: str,
               plugin_class,
               dump_path: str,
               symbol_dirs: Optional[List[str]] = None) -> List[dict]:
    """
    Build a fresh Volatility context, run automagic, bridge the config gap,
    execute the plugin, and return all rows as a list of dicts.
    """
    try:
        # 1. Fresh context for every plugin
        ctx = contexts.Context()

        # 2. Merge extra symbol dirs without losing venv-bundled ones
        if symbol_dirs:
            existing = list(constants.SYMBOL_BASEPATHS)
            constants.SYMBOL_BASEPATHS = symbol_dirs + existing

        # 3. Point Volatility at the memory dump
        ctx.config["automagic.LayerStacker.single_location"] = (
            f"file://{os.path.abspath(dump_path)}"
        )

        # 4. Choose and run automagic
        config_path = f"plugins.{plugin_name}"
        available   = automagic.available(ctx)
        chosen      = automagic.choose_automagic(available, plugin_class)
        automagic.run(chosen, ctx, plugin_class, config_path,
                      progress_callback=None)

        # 5. Bridge config gap (automagic writes to ClassName.* not directly)
        _bridge_config(ctx, config_path, plugin_class.__name__)

        # 6. Validate
        unsatisfied = plugin_class.unsatisfied(ctx, config_path)
        if unsatisfied:
            logging.warning(f"[{plugin_name}] unsatisfied requirements: {list(unsatisfied.keys())}")
            return []

        # 7. Construct and execute
        constructed = plugin_class(ctx, config_path)
        treegrid    = constructed.run()

        # 8. Collect and return rows
        return _collect_rows(treegrid)

    except Exception as e:
        logging.warning(f"[{plugin_name}] failed: {e}")
        return []


def orchestrate(dump_path: str,
                symbol_dirs: Optional[List[str]] = None) -> Dict[str, List[dict]]:
    """
    Run all registered plugins against the dump.
    Returns { plugin_name: [row, ...] }.
    """
    print(f"[*] Loading dump : {dump_path}")
    print(f"[*] Symbol dirs  : {symbol_dirs or 'venv default'}\n")

    all_results: Dict[str, List[dict]] = {}

    for name, plugin_class in PLUGINS.items():
        print(f"[*] Running plugin : {name}")
        rows = run_plugin(name, plugin_class, dump_path, symbol_dirs)
        all_results[name] = rows
        print(f"    → {len(rows)} rows collected")

    print(f"\n[+] Done. Total plugins run: {len(all_results)}")
    return all_results


# ── CLI entry point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python runner.py <dump_path> [symbol_dir]")
        sys.exit(1)

    dump_path   = sys.argv[1]
    symbol_dirs = [os.path.abspath(sys.argv[2])] if len(sys.argv) > 2 else None

    results = orchestrate(dump_path, symbol_dirs)

    print("\n── Row counts ──────────────────────────────")
    for plugin, rows in results.items():
        print(f"  {plugin:<12} {len(rows)} rows")