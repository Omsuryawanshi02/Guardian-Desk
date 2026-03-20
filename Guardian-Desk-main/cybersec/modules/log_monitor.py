import os
import re
import sys
import hashlib
import json
import stat
import subprocess
import datetime
import threading
import time
 
IS_WINDOWS = sys.platform == "win32"
MAX_LINES  = 2000
HASH_STORE_FILE = "log_monitor_hashes.json"
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTOGRAPHIC HASH ENGINE
# ══════════════════════════════════════════════════════════════════════════════
 
def _sha256(filepath):
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None
 
 
def _file_meta(filepath):
    try:
        s = os.stat(filepath)
        return {
            "size":     s.st_size,
            "modified": datetime.datetime.fromtimestamp(s.st_mtime).isoformat(),
            "mode":     oct(stat.S_IMODE(s.st_mode)),
        }
    except (OSError, PermissionError):
        return {}
 
 
def _collect_files(path, recursive=True):
    if os.path.isfile(path):
        return [path]
    files = []
    if os.path.isdir(path):
        if recursive:
            for root, _, fnames in os.walk(path):
                for f in fnames:
                    files.append(os.path.join(root, f))
        else:
            for f in os.listdir(path):
                fp = os.path.join(path, f)
                if os.path.isfile(fp):
                    files.append(fp)
    return sorted(files)
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  HASH STORE
# ══════════════════════════════════════════════════════════════════════════════
 
class HashStore:
    def __init__(self, path=HASH_STORE_FILE):
        self.path    = path
        self.hashes  = {}
        self.meta    = {}
        self.added   = {}
        self.history = []
        self._load()
 
    def _load(self):
        if os.path.isfile(self.path):
            try:
                d = json.load(open(self.path))
                self.hashes  = d.get("hashes",  {})
                self.meta    = d.get("meta",    {})
                self.added   = d.get("added",   {})
                self.history = d.get("history", [])
            except (json.JSONDecodeError, OSError):
                pass
 
    def save(self):
        try:
            with open(self.path, "w") as f:
                json.dump({
                    "hashes":   self.hashes,
                    "meta":     self.meta,
                    "added":    self.added,
                    "history":  self.history[-200:],
                    "saved_at": datetime.datetime.now().isoformat(),
                }, f, indent=2)
        except OSError:
            pass
 
    def baseline(self, filepath):
        h = _sha256(filepath)
        if h is None:
            return {"success": False, "error": f"Cannot read: {filepath}"}
        self.hashes[filepath] = h
        self.meta[filepath]   = _file_meta(filepath)
        if filepath not in self.added:
            self.added[filepath] = datetime.datetime.now().isoformat()
        self.save()
        return {"success": True, "path": filepath, "hash": h, "meta": self.meta[filepath]}
 
    def remove(self, filepath):
        self.hashes.pop(filepath, None)
        self.meta.pop(filepath, None)
        self.added.pop(filepath, None)
        self.save()
 
    def log_event(self, event):
        self.history.append(event)
        self.history = self.history[-200:]
        self.save()
 
    @property
    def monitored(self):
        return list(self.hashes.keys())
 
 
_store          = HashStore()
_watch_thread   = None
_watching       = False
_watch_interval = 60
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  FILE MONITORING API
# ══════════════════════════════════════════════════════════════════════════════
 
def add_monitored_path(path, recursive=True):
    files = _collect_files(path, recursive)
    if not files:
        return {"success": False, "error": f"No files found at: {path}"}
    added = []; errors = []
    for fp in files:
        r = _store.baseline(fp)
        if r["success"]: added.append(fp)
        else: errors.append({"path": fp, "error": r["error"]})
    return {
        "success":   len(added) > 0,
        "path":      path,
        "added":     len(added),
        "errors":    len(errors),
        "files":     added,
        "timestamp": datetime.datetime.now().isoformat(),
    }
 
 
def remove_monitored_path(path):
    removed = []
    for fp in list(_store.monitored):
        if fp == path or fp.startswith(path + os.sep):
            _store.remove(fp)
            removed.append(fp)
    return {"success": True, "removed": len(removed), "files": removed}
 
 
def run_integrity_check():
    ok = []; modified = []; missing = []
    now = datetime.datetime.now().isoformat()
 
    for filepath in list(_store.monitored):
        if not os.path.exists(filepath):
            missing.append({
                "path": filepath,
                "baseline": _store.hashes.get(filepath, ""),
                "added_at": _store.added.get(filepath, ""),
                "detected_at": now,
            })
            _store.log_event({"type": "missing", "path": filepath, "timestamp": now})
            continue
 
        current_hash = _sha256(filepath)
        if current_hash is None:
            missing.append({"path": filepath, "error": "unreadable", "detected_at": now})
            continue
 
        if current_hash == _store.hashes.get(filepath):
            ok.append(filepath)
        else:
            old_meta   = _store.meta.get(filepath, {})
            new_meta   = _file_meta(filepath)
            size_delta = new_meta.get("size", 0) - old_meta.get("size", 0)
            event = {
                "path":          filepath,
                "baseline_hash": _store.hashes.get(filepath, ""),
                "current_hash":  current_hash,
                "size_delta":    size_delta,
                "old_meta":      old_meta,
                "new_meta":      new_meta,
                "added_at":      _store.added.get(filepath, ""),
                "detected_at":   now,
            }
            modified.append(event)
            _store.log_event({"type": "modified", **event})
 
    return {
        "total_monitored": len(_store.monitored),
        "ok_count":        len(ok),
        "modified_count":  len(modified),
        "missing_count":   len(missing),
        "ok":              ok,
        "modified":        modified,
        "missing":         missing,
        "history":         _store.history[-20:],
        "checked_at":      now,
    }
 
 
def get_monitored_status():
    files_info = []
    for fp in _store.monitored:
        files_info.append({
            "path":      fp,
            "hash":      _store.hashes.get(fp, "")[:16] + "…",
            "full_hash": _store.hashes.get(fp, ""),
            "size":      _store.meta.get(fp, {}).get("size", 0),
            "modified":  _store.meta.get(fp, {}).get("modified", ""),
            "added_at":  _store.added.get(fp, ""),
            "exists":    os.path.exists(fp),
        })
    return {
        "total_monitored": len(_store.monitored),
        "watching":        _watching,
        "watch_interval":  _watch_interval,
        "store_file":      _store.path,
        "files":           files_info,
        "history":         _store.history[-20:],
    }
 
 
def rebaseline_path(filepath):
    if filepath not in _store.hashes:
        return {"success": False, "error": "File not monitored"}
    return _store.baseline(filepath)
 
 
def start_watching(interval=60):
    global _watch_thread, _watching, _watch_interval
    if _watching:
        return {"success": False, "message": "Already watching"}
    _watching = True
    _watch_interval = interval
    def _loop():
        while _watching:
            run_integrity_check()
            time.sleep(interval)
    _watch_thread = threading.Thread(target=_loop, daemon=True)
    _watch_thread.start()
    return {"success": True, "interval": interval}
 
 
def stop_watching():
    global _watching
    _watching = False
    return {"success": True}
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  WINDOWS EVENT LOG READER
# ══════════════════════════════════════════════════════════════════════════════
 
def _run_cmd(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        if r.stdout.strip():
            return r.stdout.strip().splitlines()
    except Exception:
        pass
    return []
 
 
def _win_failed_logins():
    """Event ID 4625 = Failed logon."""
    lines = _run_cmd([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-WinEvent -LogName Security -MaxEvents 200 -ErrorAction SilentlyContinue "
        "| Where-Object {$_.Id -eq 4625} "
        "| Select-Object TimeCreated, Message "
        "| ForEach-Object { $_.TimeCreated.ToString() + ' | ' + $_.Message.Split([Environment]::NewLine)[0] }"
    ], timeout=15)
 
    failed_ips = {}
    recent = []
    for line in lines:
        if len(recent) < 10:
            recent.append(line.strip())
        m = re.search(r'Source Network Address[:\s]+([\d.]+)', line)
        if m:
            ip = m.group(1)
            if ip not in ("127.0.0.1", "-", "::1"):
                failed_ips[ip] = failed_ips.get(ip, 0) + 1
 
    return len(lines), recent, failed_ips
 
 
def _win_success_logins():
    """Event ID 4624 = Successful logon (type 2=interactive, 10=remote)."""
    lines = _run_cmd([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-WinEvent -LogName Security -MaxEvents 100 -ErrorAction SilentlyContinue "
        "| Where-Object {$_.Id -eq 4624} "
        "| Select-Object TimeCreated "
        "| ForEach-Object { $_.TimeCreated.ToString() }"
    ], timeout=15)
    return len(lines), [l.strip() for l in lines[:10]]
 
 
def _win_system_errors():
    """Level 2=Error, Level 3=Warning from Windows System log."""
    err_lines = _run_cmd([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-WinEvent -LogName System -MaxEvents 200 -ErrorAction SilentlyContinue "
        "| Where-Object {$_.Level -eq 2} "
        "| Select-Object TimeCreated, Message "
        "| ForEach-Object { $_.TimeCreated.ToString() + ' | ' + $_.Message.Split([Environment]::NewLine)[0] }"
    ], timeout=15)
 
    warn_lines = _run_cmd([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-WinEvent -LogName System -MaxEvents 200 -ErrorAction SilentlyContinue "
        "| Where-Object {$_.Level -eq 3} "
        "| ForEach-Object { $_.TimeCreated.ToString() }"
    ], timeout=15)
 
    recent_errors = [l.strip() for l in err_lines[:10]]
    return len(err_lines), len(warn_lines), recent_errors
 
 
def _win_ssh_events():
    lines = _run_cmd([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 50 "
        "-ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"
    ], timeout=10)
    try:
        return int(lines[0]) if lines else 0
    except (ValueError, IndexError):
        return 0
 
 
def _win_active_sessions():
    import psutil
    sessions = []
    try:
        for u in psutil.users():
            sessions.append({
                "user":     u.name,
                "terminal": u.terminal or "console",
                "host":     u.host or "local",
                "started":  datetime.datetime.fromtimestamp(u.started).isoformat(),
            })
    except Exception:
        pass
    return sessions
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  LINUX LOG READER
# ══════════════════════════════════════════════════════════════════════════════
 
AUTH_LOG_CANDIDATES = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/system.log",
]
SYSLOG_CANDIDATES = [
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/dpkg.log",
]
 
 
def _tail(filepath, n=MAX_LINES):
    try:
        with open(filepath, "r", errors="replace") as f:
            return f.readlines()[-n:]
    except (OSError, PermissionError):
        return []
 
 
def _find_log(candidates):
    for path in candidates:
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            return path
    return None
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  MAIN analyze_logs()
# ══════════════════════════════════════════════════════════════════════════════
 
def analyze_logs():
    """
    Cross-platform log analysis + file integrity check.
    Windows  → reads Security & System Event Logs via PowerShell
    Linux    → reads /var/log/auth.log, syslog, journalctl
    Always   → runs SHA-256 integrity check on monitored files
    """
    integrity = run_integrity_check()
 
    # ── WINDOWS ───────────────────────────────────────────────────────────────
    if IS_WINDOWS:
        failed_logins,  recent_failed,  failed_ips     = _win_failed_logins()
        success_logins, recent_success                 = _win_success_logins()
        syslog_errors,  syslog_warnings, recent_errors = _win_system_errors()
        ssh_events      = _win_ssh_events()
        active_sessions = _win_active_sessions()
        sudo_events     = 0
        recent_sudo     = []
 
        suspicious_ips = [
            {"ip": ip, "count": c}
            for ip, c in sorted(failed_ips.items(), key=lambda x: -x[1])
            if c >= 3
        ]
 
        return {
            "auth_log":        "Windows Security Event Log",
            "syslog":          "Windows System Event Log",
            "log_sources":     ["Windows Security Event Log", "Windows System Event Log"],
            "platform":        "windows",
            "failed_logins":   failed_logins,
            "success_logins":  success_logins,
            "sudo_events":     sudo_events,
            "ssh_events":      ssh_events,
            "syslog_errors":   syslog_errors,
            "syslog_warnings": syslog_warnings,
            "suspicious_ips":  suspicious_ips,
            "recent_failed":   recent_failed,
            "recent_success":  recent_success,
            "recent_sudo":     recent_sudo,
            "recent_errors":   recent_errors,
            "active_sessions": active_sessions,
            "integrity":       integrity,
            "analyzed_at":     datetime.datetime.now().isoformat(),
        }
 
    # ── LINUX / macOS ─────────────────────────────────────────────────────────
    auth_log    = _find_log(AUTH_LOG_CANDIDATES)
    syslog      = _find_log(SYSLOG_CANDIDATES)
    auth_lines  = []
    log_sources = []
 
    if auth_log:
        auth_lines = _tail(auth_log)
        log_sources.append(auth_log)
    else:
        journal = _run_cmd(
            ["journalctl", "-n", str(MAX_LINES), "--no-pager", "-o", "short"], timeout=5
        )
        if journal:
            auth_lines = journal
            log_sources.append("journalctl")
 
    if syslog:
        log_sources.append(syslog)
 
    failed_logins = success_logins = sudo_events = ssh_events = 0
    failed_ips = {}
    recent_failed = []; recent_success = []; recent_sudo = []
 
    for line in auth_lines:
        lo = line.lower()
        if "failed password" in lo or "authentication failure" in lo or "invalid user" in lo:
            failed_logins += 1
            m = re.search(r'from\s+([\d.]+)', line)
            if m:
                ip = m.group(1)
                failed_ips[ip] = failed_ips.get(ip, 0) + 1
            if len(recent_failed) < 10: recent_failed.append(line.strip())
        elif "accepted password" in lo or "accepted publickey" in lo or "session opened" in lo:
            success_logins += 1
            if len(recent_success) < 10: recent_success.append(line.strip())
        if "sudo:" in lo:
            sudo_events += 1
            if len(recent_sudo) < 10: recent_sudo.append(line.strip())
        if "sshd" in lo:
            ssh_events += 1
 
    syslog_errors = syslog_warnings = 0
    recent_errors = []
    for line in (_tail(syslog) if syslog else []):
        lo = line.lower()
        if " error" in lo or "err:" in lo:
            syslog_errors += 1
            if len(recent_errors) < 10: recent_errors.append(line.strip())
        elif "warn" in lo:
            syslog_warnings += 1
 
    suspicious_ips = [
        {"ip": ip, "count": c}
        for ip, c in sorted(failed_ips.items(), key=lambda x: -x[1]) if c >= 5
    ]
 
    return {
        "auth_log":        auth_log,
        "syslog":          syslog,
        "log_sources":     log_sources,
        "platform":        "linux",
        "failed_logins":   failed_logins,
        "success_logins":  success_logins,
        "sudo_events":     sudo_events,
        "ssh_events":      ssh_events,
        "syslog_errors":   syslog_errors,
        "syslog_warnings": syslog_warnings,
        "suspicious_ips":  suspicious_ips,
        "recent_failed":   recent_failed,
        "recent_success":  recent_success,
        "recent_sudo":     recent_sudo,
        "recent_errors":   recent_errors,
        "active_sessions": [],
        "integrity":       integrity,
        "analyzed_at":     datetime.datetime.now().isoformat(),
    }
 