import os
import sys
import uuid
import json
import re
import threading
import subprocess
import shutil
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify, render_template, send_from_directory


APP_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = APP_ROOT / "data"
CASES_DIR = DATA_DIR / "cases"
CASES_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(
    __name__,
    template_folder=str(APP_ROOT / "frontend" / "templates"),
    static_folder=str(APP_ROOT / "frontend" / "static"),
)

# -----------------------------------------------------------------------------
# Job model (single active job)
# -----------------------------------------------------------------------------
_job_lock = threading.Lock()
_current_job = None  # {case_id,status,progress,started_at,finished_at,error,profile,options}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(cmd, cwd=None, timeout=None):
    p = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )
    return p.returncode, p.stdout, p.stderr


def _vol_cmd(mem_path: Path, plugin: str, plugin_args=None, global_args=None):
    """Build a robust Volatility 3 command.

    IMPORTANT: Volatility has GLOBAL args (like -o/--output-dir) that must appear
    BEFORE the plugin name. This helper supports both.

    Prefer the CLI entrypoint if available:
      - Windows venv: .venv\\Scripts\\vol.exe
      - POSIX venv:   .venv/bin/vol

    Fallback to module execution:
      python -m volatility3.cli
    """
    plugin_args = plugin_args or []
    global_args = global_args or []

    exe_dir = Path(sys.executable).parent
    vol_exe = exe_dir / ("vol.exe" if os.name == "nt" else "vol")

    if vol_exe.exists():
        return [
            str(vol_exe),
            "-f",
            str(mem_path),
            "-r",
            "json",
            *global_args,
            plugin,
            *plugin_args,
        ]

    return [
        sys.executable,
        "-m",
        "volatility3.cli",
        "-f",
        str(mem_path),
        "-r",
        "json",
        *global_args,
        plugin,
        *plugin_args,
    ]


# -----------------------------------------------------------------------------
# Volatility JSON parsing helpers
# -----------------------------------------------------------------------------
def _safe_json_loads(s: str):
    s = (s or "").strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        # Attempt to find JSON object/array inside noisy output
        for start in ("[", "{"):
            idx = s.find(start)
            if idx == -1:
                continue
            tail = s[idx:]
            for cut in range(0, min(8000, len(tail))):
                candidate = tail[: len(tail) - cut].strip()
                try:
                    return json.loads(candidate)
                except Exception:
                    continue
        return None


def _parse_volatility_json(stdout_text: str):
    """Return list[dict] rows for a Volatility plugin run.

    Handles common shapes:
      A) list[dict]
      B) dict with {"columns":..., "rows":...}
      C) dict with {"data":{"columns":...,"rows":...}} or {"result":{...}}
      D) dict with {"data": list[dict]}
    """
    vol_json = _safe_json_loads(stdout_text)
    if vol_json is None:
        return [], {"shape": "none"}

    if isinstance(vol_json, list):
        rows = [r for r in vol_json if isinstance(r, dict)]
        return rows, {"shape": "list[dict]"}

    def cols_rows_to_dicts(columns, rows):
        if not columns or not rows:
            return []
        col_names = []
        for c in columns:
            if isinstance(c, str):
                col_names.append(c)
            elif isinstance(c, dict):
                col_names.append(c.get("name") or c.get("Name") or "col")
            else:
                col_names.append("col")

        out = []
        for r in rows:
            if isinstance(r, dict):
                out.append(r)
            elif isinstance(r, list):
                d = {}
                for i, v in enumerate(r):
                    key = col_names[i] if i < len(col_names) else f"col{i}"
                    d[key] = v
                out.append(d)
        return out

    if isinstance(vol_json, dict) and "columns" in vol_json and "rows" in vol_json:
        return cols_rows_to_dicts(vol_json.get("columns"), vol_json.get("rows")), {"shape": "dict(columns,rows)"}

    if isinstance(vol_json, dict):
        for key in ("data", "result"):
            inner = vol_json.get(key)
            if isinstance(inner, dict) and "columns" in inner and "rows" in inner:
                return (
                    cols_rows_to_dicts(inner.get("columns"), inner.get("rows")),
                    {"shape": f"dict({key}.columns,{key}.rows)"},
                )

        inner = vol_json.get("data")
        if isinstance(inner, list):
            rows = [r for r in inner if isinstance(r, dict)]
            return rows, {"shape": "dict(data=list[dict])"}

    return [], {"shape": f"unknown:{type(vol_json).__name__}"}


def _parse_info_summary(info_rows):
    """Parse windows.info.Info rows into a stable summary."""
    summary = {}
    for r in info_rows or []:
        if not isinstance(r, dict):
            continue
        k = (
            r.get("Variable")
            or r.get("Key")
            or r.get("Field")
            or r.get("Name")
            or r.get("variable")
        )
        v = r.get("Value") or r.get("Data") or r.get("value")
        if k is not None:
            summary[str(k)] = v

    return {
        "raw": summary,
        "KernelBase": summary.get("Kernel Base") or summary.get("KernelBase"),
        "DTB": summary.get("DTB") or summary.get("DirectoryTableBase"),
        "Is64Bit": summary.get("Is64Bit"),
        "NTBuildLab": summary.get("NTBuildLab"),
        "MajorMinor": summary.get("Major/Minor") or summary.get("MajorMinor"),
        "MachineName": summary.get("MachineName") or summary.get("ComputerName"),
        "SystemTime": summary.get("SystemTime"),
        "SystemRoot": summary.get("NtSystemRoot") or summary.get("SystemRoot"),
    }


def _parse_envars_map(envars_rows):
    """
    Volatility windows.envars output varies by version. We normalize to:
      { pid: { VAR: VALUE, ... }, ... }
    """
    by_pid = {}
    for r in envars_rows or []:
        if not isinstance(r, dict):
            continue
        pid = r.get("PID") or r.get("Pid") or r.get("pid")
        try:
            pid = int(pid)
        except Exception:
            continue
        var = (
            r.get("Variable")
            or r.get("Name")
            or r.get("Var")
            or r.get("Key")
            or r.get("variable")
        )
        val = r.get("Value") or r.get("Data") or r.get("value")
        if not var:
            continue
        by_pid.setdefault(pid, {})[str(var).upper()] = "" if val is None else str(val)
    return by_pid


def _enrich_os_summary_from_envars(os_summary: dict, envars_by_pid: dict):
    """
    Use env vars as a best-effort enrichment for OS artifacts when windows.info is incomplete.

    Priority: pick a PID that looks like a core system process (csrss/wininit/services/lsass/explorer),
    else use the first PID we have.
    """
    if not isinstance(os_summary, dict):
        os_summary = {}

    candidate_pids = list(envars_by_pid.keys())

    # Preferred PIDs: common always-present Windows processes
    # (We can’t reliably map PID->name without pslist, so this is purely opportunistic.)
    preferred = []
    for pid in candidate_pids:
        preferred.append(pid)

    pid = preferred[0] if preferred else None
    if pid is None:
        return os_summary

    env = envars_by_pid.get(pid) or {}

    # Keep the full env map so you can see key artifacts in UI
    os_summary["Envars"] = {"pid": pid, "vars": env}

    # Fill commonly missing OS summary fields
    if not os_summary.get("SystemRoot"):
        os_summary["SystemRoot"] = env.get("SYSTEMROOT") or env.get("WINDIR")

    if not os_summary.get("MachineName"):
        os_summary["MachineName"] = env.get("COMPUTERNAME")

    if not os_summary.get("Is64Bit"):
        arch = (env.get("PROCESSOR_ARCHITECTURE") or "").lower()
        if arch:
            os_summary["Is64Bit"] = "64" in arch

    # Helpful extra OS context fields (non-breaking additions)
    os_summary.setdefault("UserDomain", env.get("USERDOMAIN"))
    os_summary.setdefault("OsEnv", env.get("OS"))
    os_summary.setdefault("ComSpec", env.get("COMSPEC"))

    return os_summary


# -----------------------------------------------------------------------------
# Malfind -> Memmap dump -> Strings extraction
# -----------------------------------------------------------------------------
_ASCII_RE = re.compile(rb"[ -~]{6,}")  # printable ASCII >= 6 chars


def _extract_strings_from_file(path: Path, max_bytes: int = 64 * 1024 * 1024):
    """
    Extract ASCII and UTF-16LE strings from a binary file.
    Limits read per file to max_bytes to avoid runaway memory usage.
    Returns a set[str].
    """
    out = set()
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
    except Exception:
        return out

    # ASCII
    for m in _ASCII_RE.finditer(data):
        try:
            s = m.group(0).decode("ascii", errors="ignore").strip()
            if s:
                out.add(s)
        except Exception:
            pass

    # UTF-16LE: decode best-effort and grab printable runs
    try:
        u = data.decode("utf-16le", errors="ignore")
        # Find printable runs
        for m in re.finditer(r"[\x20-\x7E]{6,}", u):
            s = m.group(0).strip()
            if s:
                out.add(s)
    except Exception:
        pass

    return out


def _extract_strings_from_dir(d: Path, per_file_max_bytes: int = 64 * 1024 * 1024, limit_total: int = 5000):
    """
    Extract strings from all files in directory.
    Returns list[dict] rows like: {"File": "...", "String": "..."}.
    """
    rows = []
    if not d.exists():
        return rows

    # Only consider files
    files = [p for p in d.rglob("*") if p.is_file()]
    files.sort(key=lambda p: p.stat().st_size if p.exists() else 0, reverse=True)

    seen = set()
    for fp in files:
        strings = _extract_strings_from_file(fp, max_bytes=per_file_max_bytes)
        for s in strings:
            if s in seen:
                continue
            seen.add(s)
            rows.append({"File": str(fp.relative_to(d)), "String": s})
            if len(rows) >= limit_total:
                return rows
    return rows


def _malfind_pids(malfind_rows):
    pids = set()
    for r in malfind_rows or []:
        if not isinstance(r, dict):
            continue
        pid = r.get("PID") or r.get("Pid") or r.get("pid")
        try:
            pids.add(int(pid))
        except Exception:
            continue
    return sorted(pids)


# -----------------------------------------------------------------------------
# Normalization + scoring helpers
# -----------------------------------------------------------------------------
def _get_pid(d):
    pid = d.get("PID") or d.get("Pid") or d.get("pid")
    if isinstance(pid, str) and pid.isdigit():
        return int(pid)
    return pid


def _get_ppid(d):
    ppid = d.get("PPID") or d.get("Ppid") or d.get("ppid")
    if isinstance(ppid, str) and ppid.isdigit():
        return int(ppid)
    return ppid


USER_WRITABLE_PATHS = ("\\users\\", "\\appdata\\", "\\temp\\", "\\programdata\\")


def _score_process(pid, proc_name, malfind_hits, nets, dlls_by_pid, cmdline_by_pid, handles_by_pid, privs_by_pid):
    """Triage scoring (0-100) with explainable reasons."""
    score = 0
    reasons = []

    mf = [r for r in malfind_hits if _get_pid(r) == pid]
    if mf:
        score += 45
        reasons.append(f"malfind: {len(mf)} suspicious region(s) / injected-memory indicators")

    conns = [
        c
        for c in nets
        if _get_pid(c) == pid and (c.get("ForeignAddr") or c.get("Foreign Address") or c.get("RemoteAddr"))
    ]
    if conns:
        score += 10
        reasons.append(f"network: {len(conns)} connection(s) observed (netscan)")

    name_l = (proc_name or "").lower()
    if name_l in ("powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"):
        score += 8
        reasons.append(f"lolbin: {proc_name} is commonly abused")

    dlls = dlls_by_pid.get(pid, [])
    suspicious_modules = 0
    for m in dlls:
        path = (m.get("Path") or m.get("FullDllName") or m.get("DllName") or "")
        p = str(path).lower()
        if any(x in p for x in USER_WRITABLE_PATHS):
            suspicious_modules += 1
    if suspicious_modules:
        score += min(12, 3 * suspicious_modules)
        reasons.append(f"modules: {suspicious_modules} module(s) loaded from user-writable path(s)")

    hlist = handles_by_pid.get(pid, [])
    risky = 0
    for h in hlist:
        typ = str(h.get("Type") or h.get("type") or "").lower()
        name = str(h.get("Name") or h.get("name") or "").lower()
        access = str(h.get("GrantedAccess") or h.get("Access") or h.get("access") or "")
        if ("process" in typ or "token" in typ) and "lsass" in name:
            risky += 1
        if "sam" in name or "security" in name:
            risky += 1
        if "services" in name or "scmanager" in name:
            risky += 1
        if access and any(x in access.lower() for x in ("0x1f0fff", "0x001f0fff")):
            risky += 1
    if risky:
        score += min(15, 5 * risky)
        reasons.append(f"handles: {risky} potentially high-risk handle indicator(s)")

    # Privileges (if available)
    privs = privs_by_pid.get(pid, [])
    if privs:
        key_privs = 0
        for pr in privs:
            pname = str(pr.get("Privilege") or pr.get("Name") or "").lower()
            if any(x in pname for x in ("sedebug", "setcb", "seimpersonate", "seassignprimarytoken", "sebackup", "serestore")):
                key_privs += 1
        if key_privs:
            score += min(10, 3 * key_privs)
            reasons.append(f"privileges: {key_privs} high-value privilege indicator(s)")

    score = max(0, min(100, score))
    return score, reasons, cmdline_by_pid.get(pid, "")


# -----------------------------------------------------------------------------
# Volatility plugin registry (all windows.* items provided)
# -----------------------------------------------------------------------------
WINDOWS_PLUGINS = {
    "core": [
        "windows.info.Info",
        "windows.pslist.PsList",
        "windows.pstree.PsTree",
        "windows.cmdline.CmdLine",
        "windows.dlllist.DllList",
        "windows.handles.Handles",
        "windows.netscan.NetScan",
        "windows.malfind.Malfind",
        "windows.getsids.GetSIDs",
        "windows.getservicesids.GetServiceSIDs",
        "windows.privileges.Privs",
        "windows.sessions.Sessions",
        "windows.envars.Envars",  # ensure envars always runs in default
    ],
    "kernel": [
        "windows.bigpools.BigPools",
        "windows.callbacks.Callbacks",
        "windows.devicetree.DeviceTree",
        "windows.driverirp.DriverIrp",
        "windows.drivermodule.DriverModule",
        "windows.driverscan.DriverScan",
        "windows.mbrscan.MBRScan",
        "windows.modscan.ModScan",
        "windows.modules.Modules",
        "windows.poolscanner.PoolScanner",
        "windows.ssdt.SSDT",
        "windows.crashinfo.Crashinfo",
    ],
    "process_deep": [
        "windows.psscan.PsScan",
        "windows.ldrmodules.LdrModules",
        "windows.joblinks.JobLinks",
        "windows.verinfo.VerInfo",
    ],
    "memory_deep": [
        "windows.memmap.Memmap",
        "windows.vadinfo.VadInfo",
        "windows.vadwalk.VadWalk",
        "windows.virtmap.VirtMap",
        "windows.strings.Strings",
    ],
    "objects": [
        "windows.filescan.FileScan",
        "windows.dumpfiles.DumpFiles",
        "windows.mutantscan.MutantScan",
        "windows.symlinkscan.SymlinkScan",
        "windows.statistics.Statistics",
    ],
    "network": [
        "windows.netstat.NetStat",
    ],
    "registry": [
        "windows.registry.hivelist.HiveList",
        "windows.registry.hivescan.HiveScan",
        "windows.registry.userassist.UserAssist",
        "windows.registry.certificates.Certificates",
        "windows.registry.printkey.PrintKey",  # requires args
    ],
    "special_detection": [
        "windows.skeleton_key_check.Skeleton_Key_Check",
    ],
}

HEAVY_PLUGINS = {
    "windows.filescan.FileScan",
    "windows.dumpfiles.DumpFiles",
    "windows.strings.Strings",
}

PRINTKEY_TASKS = [
    ("Services", r"SYSTEM\\CurrentControlSet\\Services"),
    ("Run", r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("RunOnce", r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
]


def _all_windows_plugins():
    out = []
    for group in WINDOWS_PLUGINS.values():
        out.extend(group)
    # de-dupe while preserving order
    seen = set()
    uniq = []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def _plugins_for_profile(profile: str, include_heavy: bool, include_dumpfiles: bool):
    """Profiles:

    - default: core + registry + network (non-heavy)
    - deep: default + kernel + process_deep + memory_deep (non-heavy unless include_heavy)
    - full: all windows plugins (heavy optional)

    include_dumpfiles:
      - governs windows.dumpfiles.DumpFiles specifically (even if heavy)
    """
    profile = (profile or "deep").lower().strip()

    if profile == "default":
        base = WINDOWS_PLUGINS["core"] + WINDOWS_PLUGINS["registry"] + WINDOWS_PLUGINS["network"]
    elif profile == "deep":
        base = (
            WINDOWS_PLUGINS["core"]
            + WINDOWS_PLUGINS["registry"]
            + WINDOWS_PLUGINS["network"]
            + WINDOWS_PLUGINS["kernel"]
            + WINDOWS_PLUGINS["process_deep"]
            + WINDOWS_PLUGINS["memory_deep"]
            + WINDOWS_PLUGINS["special_detection"]
        )
    else:  # full
        base = _all_windows_plugins()

    # de-dupe
    seen = set()
    out = []
    for p in base:
        if p in seen:
            continue
        seen.add(p)
        out.append(p)

    # Heavy gating
    if not include_heavy:
        out = [p for p in out if p not in HEAVY_PLUGINS]

    # Dumpfiles gating (explicit opt-in)
    if not include_dumpfiles:
        out = [p for p in out if p != "windows.dumpfiles.DumpFiles"]

    return out


# -----------------------------------------------------------------------------
# Registry-derived Services normalization (since svcscan is not in your plugin set)
# -----------------------------------------------------------------------------
def _extract_services_from_printkey_rows(rows):
    services = {}
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        key = str(r.get("Key") or r.get("key") or r.get("HiveKey") or "")
        name = str(r.get("Name") or r.get("name") or r.get("ValueName") or "")
        data = r.get("Data") or r.get("data") or r.get("Value") or ""

        if r"CurrentControlSet\\Services\\" not in key:
            continue
        svc_name = key.split("\\")[-1] if "\\" in key else key
        svc = services.setdefault(svc_name, {"Service": svc_name})
        if name:
            svc[name] = data

    return list(services.values())


def _normalize(case_id: str, raw: dict) -> dict:
    plugins = raw.get("plugins") or {}

    def rows_of(pid):
        return (plugins.get(pid) or {}).get("rows") or []

    out = {
        "case_id": case_id,
        "created_at": raw.get("created_at"),
        "memory_filename": raw.get("memory_filename"),
        "profile": raw.get("profile"),
        "options": raw.get("options") or {},
        "summary": {"os": {}},
        "errors": raw.get("errors", []),
        "plugins": list(plugins.keys()),

        # Curated UI panels
        "processes": rows_of("windows.pslist.PsList"),
        "pstree": rows_of("windows.pstree.PsTree"),
        "nets": rows_of("windows.netscan.NetScan"),
        "malfind_hits": rows_of("windows.malfind.Malfind"),
        "dlls": rows_of("windows.dlllist.DllList"),
        "cmdlines": rows_of("windows.cmdline.CmdLine"),
        "handles": rows_of("windows.handles.Handles"),
        "services": [],

        # Memmap dump + strings results
        "memmap_dumps": [],      # summary objects per PID
        "memmap_strings": {},    # pid -> list of string rows

        # Extra artifacts (exposed in the "All plugin outputs" explorer)
        "extras": {},

        "scores": [],
        "graph": {"nodes": [], "edges": []},
    }

    # OS summary from windows.info
    info = plugins.get("windows.info.Info") or {}
    out["summary"]["os"] = info.get("parsed_summary") or {}

    # Envars enrichment
    envars_rows = rows_of("windows.envars.Envars")
    envars_by_pid = _parse_envars_map(envars_rows)
    out["summary"]["os"] = _enrich_os_summary_from_envars(out["summary"]["os"], envars_by_pid)

    # Services (PrintKey->Services)
    svc_pk = plugins.get("windows.registry.printkey.Services") or {}
    out["services"] = _extract_services_from_printkey_rows(svc_pk.get("rows") or [])

    # Keep all plugin rows in extras for a universal explorer
    for pid, pobj in plugins.items():
        out["extras"][pid] = {
            "rows": pobj.get("rows") or [],
            "invocation": pobj.get("invocation") or {},
            "parse_shape": pobj.get("parse_shape") or (pobj.get("parse_meta") or {}).get("shape"),
        }

    # Bring memmap dump outputs into top-level structured fields (if present)
    for pid_key, pobj in plugins.items():
        if pid_key.startswith("windows.memmap.dump.pid_"):
            try:
                pid = int(pid_key.split("_")[-1])
            except Exception:
                continue
            out["memmap_dumps"].append({
                "pid": pid,
                "rows": pobj.get("rows") or [],
                "output_dir": (pobj.get("meta") or {}).get("output_dir"),
            })

        if pid_key.startswith("windows.memmap.strings.pid_"):
            try:
                pid = int(pid_key.split("_")[-1])
            except Exception:
                continue
            out["memmap_strings"][str(pid)] = pobj.get("rows") or []

    # Build lookups for scoring
    dlls_by_pid = {}
    for r in out["dlls"]:
        pid = _get_pid(r)
        if isinstance(pid, int):
            dlls_by_pid.setdefault(pid, []).append(r)

    cmdline_by_pid = {}
    for r in out["cmdlines"]:
        pid = _get_pid(r)
        if isinstance(pid, int):
            cmd = (
                r.get("CommandLine")
                or r.get("CmdLine")
                or r.get("cmdline")
                or r.get("command_line")
                or r.get("Args")
                or r.get("Arguments")
                or ""
            )
            cmdline_by_pid[pid] = str(cmd)

    handles_by_pid = {}
    for r in out["handles"]:
        pid = _get_pid(r)
        if isinstance(pid, int):
            handles_by_pid.setdefault(pid, []).append(r)

    privs_by_pid = {}
    for r in rows_of("windows.privileges.Privs"):
        pid = _get_pid(r)
        if isinstance(pid, int):
            privs_by_pid.setdefault(pid, []).append(r)

    # Score processes
    scores = []
    for p in out["processes"]:
        pid = _get_pid(p)
        if not isinstance(pid, int):
            continue
        name = p.get("ImageFileName") or p.get("Name") or p.get("Process") or "process"
        s, reasons, cmd = _score_process(
            pid=pid,
            proc_name=str(name),
            malfind_hits=out["malfind_hits"],
            nets=out["nets"],
            dlls_by_pid=dlls_by_pid,
            cmdline_by_pid=cmdline_by_pid,
            handles_by_pid=handles_by_pid,
            privs_by_pid=privs_by_pid,
        )
        scores.append({"pid": pid, "name": str(name), "score": s, "reasons": reasons, "cmdline": cmd})
    scores.sort(key=lambda x: x["score"], reverse=True)
    out["scores"] = scores

    # Build graph
    suspicious_pids = {s["pid"] for s in scores if s["score"] >= 60}
    for r in out["malfind_hits"]:
        pid = _get_pid(r)
        if isinstance(pid, int):
            suspicious_pids.add(pid)

    proc_nodes = []
    for p in out["processes"]:
        pid = _get_pid(p)
        ppid = _get_ppid(p)
        name = p.get("ImageFileName") or p.get("Name") or p.get("Process") or "process"
        proc_nodes.append(
            {
                "id": f"p:{pid}",
                "label": f"{name} ({pid})",
                "type": "process",
                "pid": pid,
                "ppid": ppid,
                "suspicious": bool(isinstance(pid, int) and pid in suspicious_pids),
            }
        )

    edges = []
    pid_to = {n["pid"]: n for n in proc_nodes if isinstance(n.get("pid"), int)}
    for n in proc_nodes:
        pid = n.get("pid")
        ppid = n.get("ppid")
        if isinstance(pid, int) and isinstance(ppid, int) and ppid in pid_to:
            edges.append({"id": f"e:pp:{ppid}->{pid}", "source": f"p:{ppid}", "target": f"p:{pid}", "type": "parent_of"})

    net_nodes = {}
    for c in out["nets"]:
        pid = _get_pid(c)
        raddr = c.get("ForeignAddr") or c.get("Foreign Address") or c.get("RemoteAddr") or ""
        rport = c.get("ForeignPort") or c.get("RemotePort") or c.get("Foreign Port") or ""
        if not raddr:
            continue
        remote_key = f"{raddr}:{rport}" if rport else str(raddr)
        node_id = f"n:{remote_key}"
        net_nodes[node_id] = {"id": node_id, "label": remote_key, "type": "remote"}
        if isinstance(pid, int):
            edges.append({"id": f"e:net:{pid}->{remote_key}", "source": f"p:{pid}", "target": node_id, "type": "connects_to"})

    out["graph"]["nodes"] = proc_nodes + list(net_nodes.values())
    out["graph"]["edges"] = edges
    return out


# -----------------------------------------------------------------------------
# Analysis runner
# -----------------------------------------------------------------------------
def _case_dir(case_id: str) -> Path:
    d = CASES_DIR / case_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _analyze_case(case_id: str, profile: str, options: dict):
    case_dir = _case_dir(case_id)
    mem_path = case_dir / "memory.img"
    raw_dir = case_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    include_heavy = bool((options or {}).get("include_heavy"))
    include_dumpfiles = bool((options or {}).get("include_dumpfiles"))

    raw = {
        "case_id": case_id,
        "created_at": _utc_now_iso(),
        "memory_filename": "memory.img",
        "profile": profile,
        "options": {"include_heavy": include_heavy, "include_dumpfiles": include_dumpfiles},
        "plugins": {},
        "errors": [],
    }

    plugins_to_run = _plugins_for_profile(profile, include_heavy=include_heavy, include_dumpfiles=include_dumpfiles)

    tasks = []
    for p in plugins_to_run:
        if p == "windows.registry.printkey.PrintKey":
            continue
        tasks.append({"id": p, "plugin": p, "plugin_args": [], "global_args": []})

    # Expand PrintKey tasks
    if "windows.registry.printkey.PrintKey" in plugins_to_run or profile in ("default", "deep", "full"):
        for tag, key_path in PRINTKEY_TASKS:
            tasks.append({
                "id": f"windows.registry.printkey.{tag}",
                "plugin": "windows.registry.printkey.PrintKey",
                "plugin_args": ["--key", key_path],
                "global_args": [],
            })

    total = len(tasks)

    # -------------------------
    # Pass 1: run core tasks
    # -------------------------
    for i, t in enumerate(tasks, start=1):
        plugin_id = t["id"]
        plugin = t["plugin"]
        plugin_args = t["plugin_args"]
        global_args = t["global_args"]

        with _job_lock:
            if _current_job and _current_job.get("case_id") == case_id:
                _current_job["progress"] = {"current": i, "total": total, "plugin": plugin_id}

        cmd = _vol_cmd(mem_path, plugin, plugin_args=plugin_args, global_args=global_args)

        try:
            timeout = 60 * 30
            if plugin in HEAVY_PLUGINS:
                timeout = 60 * 90
            rc, stdout, stderr = _run(cmd, cwd=str(APP_ROOT), timeout=timeout)
        except subprocess.TimeoutExpired:
            raw["errors"].append({"plugin": plugin_id, "error": "timeout"})
            continue
        except Exception as e:
            raw["errors"].append({"plugin": plugin_id, "error": str(e)})
            continue

        safe_name = plugin_id.replace("/", "_")
        (raw_dir / f"{safe_name}.stdout.txt").write_text(stdout or "", encoding="utf-8", errors="ignore")
        (raw_dir / f"{safe_name}.stderr.txt").write_text(stderr or "", encoding="utf-8", errors="ignore")

        if rc != 0:
            raw["errors"].append({"plugin": plugin_id, "error": f"rc={rc}", "stderr": (stderr or "")[-4000:]})
            continue

        rows, meta = _parse_volatility_json(stdout or "")
        pobj = {
            "rc": rc,
            "rows": rows,
            "parse_meta": meta,
            "parse_shape": meta.get("shape"),
            "invocation": {"plugin": plugin, "args": plugin_args, "global_args": global_args},
        }
        if plugin == "windows.info.Info":
            pobj["parsed_summary"] = _parse_info_summary(rows)

        raw["plugins"][plugin_id] = pobj

    # -------------------------
    # Pass 2: malfind -> memmap dump -> extract strings
    # -------------------------
    malfind_rows = (raw["plugins"].get("windows.malfind.Malfind") or {}).get("rows") or []
    pids = _malfind_pids(malfind_rows)

    # Safety cap to avoid runaway output on pathological images.
    # You can raise/remove this if you want truly unbounded behavior.
    MAX_PIDS_TO_DUMP = 30
    pids = pids[:MAX_PIDS_TO_DUMP]

    dumps_root = case_dir / "dumps"
    dumps_root.mkdir(parents=True, exist_ok=True)

    # We don’t change the case's "main" progress counters here, but we do log plugin ids + raw files.
    for pid in pids:
        dump_dir = dumps_root / f"memmap_pid_{pid}"
        dump_dir.mkdir(parents=True, exist_ok=True)

        plugin_id = f"windows.memmap.dump.pid_{pid}"
        safe_name = plugin_id.replace("/", "_")

        # Global output directory MUST be set as a global arg (before the plugin)
        # Volatility uses: -o / --output-dir
        memmap_cmd = _vol_cmd(
            mem_path,
            "windows.memmap.Memmap",
            plugin_args=["--dump", "--pid", str(pid)],
            global_args=["-o", str(dump_dir)],
        )

        try:
            rc, stdout, stderr = _run(memmap_cmd, cwd=str(APP_ROOT), timeout=60 * 90)
        except subprocess.TimeoutExpired:
            raw["errors"].append({"plugin": plugin_id, "error": "timeout"})
            continue
        except Exception as e:
            raw["errors"].append({"plugin": plugin_id, "error": str(e)})
            continue

        (raw_dir / f"{safe_name}.stdout.txt").write_text(stdout or "", encoding="utf-8", errors="ignore")
        (raw_dir / f"{safe_name}.stderr.txt").write_text(stderr or "", encoding="utf-8", errors="ignore")

        if rc != 0:
            raw["errors"].append({"plugin": plugin_id, "error": f"rc={rc}", "stderr": (stderr or "")[-4000:]})
            continue

        rows, meta = _parse_volatility_json(stdout or "")
        raw["plugins"][plugin_id] = {
            "rc": rc,
            "rows": rows,
            "parse_meta": meta,
            "parse_shape": meta.get("shape"),
            "invocation": {"plugin": "windows.memmap.Memmap", "args": ["--dump", "--pid", str(pid)], "global_args": ["-o", str(dump_dir)]},
            "meta": {"output_dir": str(dump_dir)},
        }

        # Extract strings from dumped files
        strings_id = f"windows.memmap.strings.pid_{pid}"
        safe_strings = strings_id.replace("/", "_")

        srows = _extract_strings_from_dir(dump_dir, per_file_max_bytes=64 * 1024 * 1024, limit_total=5000)
        raw["plugins"][strings_id] = {
            "rc": 0,
            "rows": srows,
            "parse_meta": {"shape": "internal(strings)"},
            "parse_shape": "internal(strings)",
            "invocation": {"plugin": "internal.memmap_strings", "args": ["pid", str(pid)], "global_args": []},
            "meta": {"output_dir": str(dump_dir), "string_count": len(srows)},
        }

        # Persist as raw artifacts too (handy for triage)
        (raw_dir / f"{safe_strings}.json").write_text(json.dumps(srows, indent=2), encoding="utf-8")

    # Normalize + persist
    normalized = _normalize(case_id, raw)
    (case_dir / "case_raw.json").write_text(json.dumps(raw, indent=2), encoding="utf-8")
    (case_dir / "case.json").write_text(json.dumps(normalized, indent=2), encoding="utf-8")


def _start_analysis(case_id: str, profile: str, options: dict):
    global _current_job
    with _job_lock:
        if _current_job and _current_job.get("status") in ("running", "queued"):
            raise RuntimeError("Another analysis is currently running. This prototype supports one job at a time.")
        _current_job = {
            "case_id": case_id,
            "status": "queued",
            "progress": {"current": 0, "total": 0, "plugin": None},
            "started_at": None,
            "finished_at": None,
            "error": None,
            "profile": profile,
            "options": options or {},
        }

    def worker():
        global _current_job
        with _job_lock:
            _current_job["status"] = "running"
            _current_job["started_at"] = _utc_now_iso()
        try:
            _analyze_case(case_id, profile=profile, options=options or {})
            with _job_lock:
                _current_job["status"] = "finished"
                _current_job["finished_at"] = _utc_now_iso()
        except Exception as e:
            with _job_lock:
                _current_job["status"] = "error"
                _current_job["error"] = str(e)
                _current_job["finished_at"] = _utc_now_iso()

    threading.Thread(target=worker, daemon=True).start()


# -----------------------------------------------------------------------------
# Upload subsystem (chunked)
# -----------------------------------------------------------------------------
UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
CHUNK_SIZE_DEFAULT = 64 * 1024 * 1024  # 64MB


def _upload_state_path(case_id: str) -> Path:
    return UPLOAD_DIR / f"{case_id}.json"


def _upload_part_path(case_id: str) -> Path:
    return UPLOAD_DIR / f"{case_id}.part"


def _load_upload_state(case_id: str) -> dict:
    p = _upload_state_path(case_id)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _save_upload_state(case_id: str, state: dict):
    _upload_state_path(case_id).write_text(json.dumps(state, indent=2), encoding="utf-8")


def _finalize_upload(case_id: str, filename: str, profile: str, options: dict):
    part = _upload_part_path(case_id)
    if not part.exists():
        raise RuntimeError("Upload part file missing; cannot finalize.")
    case_dir = CASES_DIR / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    dst = case_dir / "memory.img"
    if dst.exists():
        dst.unlink()
    shutil.move(str(part), str(dst))

    (case_dir / "upload_meta.json").write_text(
        json.dumps(
            {
                "original_filename": filename,
                "finalized_at": _utc_now_iso(),
                "profile": profile,
                "options": options or {},
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    st = _upload_state_path(case_id)
    if st.exists():
        st.unlink(missing_ok=True)

    _start_analysis(case_id, profile=profile, options=options)


# -----------------------------------------------------------------------------
# Desktop-only local import
# -----------------------------------------------------------------------------
def _is_safe_local_path(p: Path) -> bool:
    try:
        if not p.exists() or not p.is_file():
            return False
        s = str(p)
        if s.startswith("\\\\"):
            return False
        return True
    except Exception:
        return False


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.get("/")
def home():
    return render_template("index.html")


@app.get("/case/<case_id>")
def case_view(case_id):
    return render_template("case.html", case_id=case_id)


@app.get("/api/profiles")
def api_profiles():
    return jsonify(
        {
            "profiles": [
                {
                    "id": "default",
                    "name": "Default (fast triage)",
                    "description": "Core triage + registry persistence. No heavy scanners.",
                },
                {
                    "id": "deep",
                    "name": "Deep (recommended)",
                    "description": "Expanded triage: kernel, VAD/memory maps, sessions/privileges, registry.",
                },
                {
                    "id": "full",
                    "name": "Full (all Windows plugins)",
                    "description": "Runs all available Windows plugins. Heavy scanners optional.",
                },
            ]
        }
    )


@app.get("/api/job")
def api_job():
    with _job_lock:
        return jsonify(_current_job)


@app.get("/api/cases")
def api_cases():
    cases = []
    for d in sorted(CASES_DIR.glob("*")):
        if not d.is_dir():
            continue
        cj = d / "case.json"
        if cj.exists():
            meta = json.loads(cj.read_text(encoding="utf-8"))
            cases.append(
                {
                    "case_id": meta.get("case_id"),
                    "created_at": meta.get("created_at"),
                    "memory_filename": meta.get("memory_filename"),
                    "profile": meta.get("profile"),
                    "errors": meta.get("errors", []),
                }
            )
        else:
            cases.append({"case_id": d.name})
    return jsonify({"cases": cases})


@app.get("/api/case/<case_id>")
def api_case(case_id):
    case_dir = CASES_DIR / case_id
    cj = case_dir / "case.json"
    if not cj.exists():
        return jsonify({"error": "case not found"}), 404
    data = json.loads(cj.read_text(encoding="utf-8"))
    include_raw = str(request.args.get("include_raw") or "0").lower() in ("1", "true", "yes")
    if include_raw:
        crj = case_dir / "case_raw.json"
        if crj.exists():
            try:
                data["_raw"] = json.loads(crj.read_text(encoding="utf-8"))
            except Exception:
                data["_raw"] = {"error": "failed to parse case_raw.json"}
    return jsonify(data)


@app.post("/api/upload")
def api_upload():
    # Single-shot upload (small files)
    if "memory" not in request.files:
        return jsonify({"error": "missing form field 'memory'"}), 400
    f = request.files["memory"]
    if not f.filename:
        return jsonify({"error": "missing filename"}), 400

    profile = (request.form.get("profile") or "deep").lower()
    include_heavy = str(request.form.get("include_heavy") or "false").lower() in ("1", "true", "yes")
    include_dumpfiles = str(request.form.get("include_dumpfiles") or "false").lower() in ("1", "true", "yes")
    options = {"include_heavy": include_heavy, "include_dumpfiles": include_dumpfiles}

    case_id = uuid.uuid4().hex[:12]
    case_dir = CASES_DIR / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    mem_path = case_dir / "memory.img"
    f.save(mem_path)

    try:
        _start_analysis(case_id, profile=profile, options=options)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 409

    return jsonify({"case_id": case_id})


@app.post("/api/upload/init")
def api_upload_init():
    body = request.get_json(force=True, silent=True) or {}
    filename = body.get("filename") or "memory.img"
    total_size = int(body.get("total_size") or 0)
    chunk_size = int(body.get("chunk_size") or CHUNK_SIZE_DEFAULT)

    profile = (body.get("profile") or "deep").lower()
    include_heavy = bool(body.get("include_heavy")) or bool((body.get("options") or {}).get("include_heavy"))
    include_dumpfiles = bool((body.get("options") or {}).get("include_dumpfiles"))
    options = {"include_heavy": include_heavy, "include_dumpfiles": include_dumpfiles}

    case_id = uuid.uuid4().hex[:12]
    part = _upload_part_path(case_id)
    if part.exists():
        part.unlink()

    state = {
        "case_id": case_id,
        "filename": filename,
        "total_size": total_size,
        "chunk_size": chunk_size,
        "received_bytes": 0,
        "received_chunks": [],
        "created_at": _utc_now_iso(),
        "profile": profile,
        "options": options,
    }
    _save_upload_state(case_id, state)
    return jsonify({"case_id": case_id, "chunk_size": chunk_size})


@app.post("/api/upload/chunk/<case_id>")
def api_upload_chunk(case_id):
    state = _load_upload_state(case_id)
    if not state:
        return jsonify({"error": "unknown upload session"}), 404

    try:
        index = int(request.form.get("index"))
        offset = int(request.form.get("offset"))
        total = int(request.form.get("total"))
    except Exception:
        return jsonify({"error": "missing/invalid chunk metadata (index/offset/total)"}), 400

    if "chunk" not in request.files:
        return jsonify({"error": "missing file field 'chunk'"}), 400

    expected_offset = int(state.get("received_bytes") or 0)
    if offset != expected_offset:
        return jsonify({"error": "unexpected offset", "expected_offset": expected_offset, "got_offset": offset}), 409

    blob = request.files["chunk"]
    part = _upload_part_path(case_id)
    part.parent.mkdir(parents=True, exist_ok=True)

    with open(part, "ab") as fp:
        shutil.copyfileobj(blob.stream, fp)

    received = part.stat().st_size
    state["received_bytes"] = received
    if index not in state.get("received_chunks", []):
        state.setdefault("received_chunks", []).append(index)
    _save_upload_state(case_id, state)

    done = received >= total
    return jsonify({"received_bytes": received, "done": done})


@app.post("/api/upload/complete/<case_id>")
def api_upload_complete(case_id):
    state = _load_upload_state(case_id)
    if not state:
        return jsonify({"error": "unknown upload session"}), 404

    part = _upload_part_path(case_id)
    if not part.exists():
        return jsonify({"error": "missing uploaded data"}), 400

    total = int(state.get("total_size") or 0)
    if total and part.stat().st_size != total:
        return jsonify({"error": "size mismatch", "expected": total, "got": part.stat().st_size}), 409

    profile = state.get("profile") or "deep"
    options = state.get("options") or {"include_heavy": False, "include_dumpfiles": False}
    try:
        _finalize_upload(case_id, state.get("filename") or "memory.img", profile=profile, options=options)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 409

    return jsonify({"case_id": case_id})


@app.post("/api/import_local")
def api_import_local():
    body = request.get_json(force=True, silent=True) or {}
    path = body.get("path")
    if not path:
        return jsonify({"error": "missing 'path'"}), 400
    src = Path(path)
    if not _is_safe_local_path(src):
        return jsonify({"error": "unsafe or missing path"}), 400

    profile = (body.get("profile") or "deep").lower()
    include_heavy = bool(body.get("include_heavy"))
    include_dumpfiles = bool(body.get("include_dumpfiles"))
    options = {"include_heavy": include_heavy, "include_dumpfiles": include_dumpfiles}

    case_id = uuid.uuid4().hex[:12]
    case_dir = CASES_DIR / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    dst = case_dir / "memory.img"
    shutil.copy2(str(src), str(dst))

    try:
        _start_analysis(case_id, profile=profile, options=options)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 409

    return jsonify({"case_id": case_id})


@app.get("/download/<case_id>/<path:filename>")
def download_case_file(case_id, filename):
    case_dir = CASES_DIR / case_id
    return send_from_directory(case_dir, filename, as_attachment=True)


def create_app():
    return app
