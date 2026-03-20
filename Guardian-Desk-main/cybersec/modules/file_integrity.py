import os
import sys
import hashlib
import json
import datetime

BASELINE_FILE = "fim_baseline.json"
IS_WINDOWS    = sys.platform == "win32"

# ── Default paths per platform ────────────────────────────────────────────────
if IS_WINDOWS:
    DEFAULT_PATHS = [
        r"C:\Windows\System32\drivers\etc\hosts",
        r"C:\Windows\System32\drivers\etc\networks",
        r"C:\Windows\System32\drivers\etc\services",
        r"C:\Windows\System32\drivers\etc\protocol",
        r"C:\Windows\win.ini",
        r"C:\Windows\system.ini",
        r"C:\Windows\System32\config\SAM",
    ]
else:
    DEFAULT_PATHS = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/ssh/sshd_config",
        "/etc/sudoers",
        "/etc/crontab",
        "/etc/fstab",
    ]


def _hash_file(filepath):
    """Return SHA-256 hex digest of a file, or None if unreadable."""
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, PermissionError):
        return None


def _collect_files(path, recursive=True):
    """Return all files under a path (file or directory)."""
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


class FileIntegrityMonitor:
    def __init__(self, baseline_path=BASELINE_FILE):
        self.baseline_path  = baseline_path
        self.monitored_paths = []
        self.baseline        = {}
        self.added_at        = {}   # filepath -> when it was first added
        self.history         = []   # last 100 change events
        self._load_baseline()

        # Auto-baseline default system paths on startup
        self._auto_scan_defaults()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load_baseline(self):
        if os.path.isfile(self.baseline_path):
            try:
                with open(self.baseline_path) as f:
                    data = json.load(f)
                    self.monitored_paths = data.get("paths",    [])
                    self.baseline        = data.get("hashes",   {})
                    self.added_at        = data.get("added_at", {})
                    self.history         = data.get("history",  [])
            except (json.JSONDecodeError, OSError):
                self.monitored_paths = []
                self.baseline        = {}

    def _save_baseline(self):
        try:
            with open(self.baseline_path, "w") as f:
                json.dump({
                    "paths":    self.monitored_paths,
                    "hashes":   self.baseline,
                    "added_at": self.added_at,
                    "history":  self.history[-100:],
                    "updated":  datetime.datetime.now().isoformat(),
                }, f, indent=2)
        except OSError:
            pass

    # ── Auto scan ─────────────────────────────────────────────────────────────

    def _auto_scan_defaults(self):
        """Baseline all default system paths. Skip already-monitored files."""
        added = 0
        for path in DEFAULT_PATHS:
            try:
                files = _collect_files(path, recursive=False)
                for fp in files:
                    if fp not in self.monitored_paths:
                        result = self.add_path(fp)
                        if result.get("success"):
                            added += 1
            except Exception:
                pass
        if added:
            print(f"[FIM] Auto-scanned {added} default system file(s)")

    # ── Public API ────────────────────────────────────────────────────────────

    def add_path(self, filepath, recursive=True):
        """Add a file or directory to monitoring and baseline it."""
        files = _collect_files(filepath, recursive=recursive)
        if not files:
            return {"success": False, "error": f"No files found at: {filepath}"}

        added  = []
        errors = []
        now    = datetime.datetime.now().isoformat()

        for fp in files:
            h = _hash_file(fp)
            if h is None:
                errors.append(fp)
                continue
            if fp not in self.monitored_paths:
                self.monitored_paths.append(fp)
            self.baseline[fp] = h
            if fp not in self.added_at:
                self.added_at[fp] = now
            added.append(fp)

        self._save_baseline()
        return {
            "success":   len(added) > 0,
            "path":      filepath,
            "added":     len(added),
            "errors":    len(errors),
            "files":     added,
            "timestamp": datetime.datetime.now().isoformat(),
        }

    def remove_path(self, filepath):
        """Remove a file or directory from monitoring."""
        removed = []
        for fp in list(self.monitored_paths):
            if fp == filepath or fp.startswith(filepath + os.sep):
                self.monitored_paths.remove(fp)
                self.baseline.pop(fp, None)
                self.added_at.pop(fp, None)
                removed.append(fp)
        self._save_baseline()
        return {"success": True, "removed": len(removed), "files": removed}

    def rebaseline(self, filepath):
        """Accept current state of a file as the new trusted baseline."""
        if filepath not in self.monitored_paths:
            return {"success": False, "error": "File not monitored"}
        h = _hash_file(filepath)
        if h is None:
            return {"success": False, "error": "Cannot read file"}
        self.baseline[filepath] = h
        self._save_baseline()
        return {"success": True, "path": filepath, "hash": h}

    def get_status(self):
        files_info = []
        for fp in self.monitored_paths:
            files_info.append({
                "path":      fp,
                "hash":      self.baseline.get(fp, "")[:16] + "...",
                "full_hash": self.baseline.get(fp, ""),
                "added_at":  self.added_at.get(fp, ""),
                "exists":    os.path.exists(fp),
                "size":      os.path.getsize(fp) if os.path.exists(fp) else 0,
            })
        return {
            "total_monitored": len(self.monitored_paths),
            "monitored_paths": self.monitored_paths,
            "files_info":      files_info,
            "baseline_file":   self.baseline_path,
            "platform":        "windows" if IS_WINDOWS else "linux",
            "history":         self.history[-20:],
            "last_checked":    datetime.datetime.now().isoformat(),
        }

    def check_integrity(self):
        """
        Recompute SHA-256 for every monitored file.
        Detect modifications and missing files.
        """
        ok       = []
        modified = []
        missing  = []
        now      = datetime.datetime.now().isoformat()

        for path in self.monitored_paths:
            if not os.path.exists(path):
                missing.append(path)
                self.history.append({
                    "type":      "missing",
                    "path":      path,
                    "timestamp": now,
                })
                continue

            current_hash = _hash_file(path)
            if current_hash is None:
                missing.append(path)
                continue

            if current_hash == self.baseline.get(path):
                ok.append(path)
            else:
                event = {
                    "path":         path,
                    "expected":     self.baseline.get(path, ""),
                    "actual":       current_hash,
                    "detected_at":  now,
                    "size":         os.path.getsize(path) if os.path.exists(path) else 0,
                }
                modified.append(event)
                self.history.append({
                    "type":      "modified",
                    "path":      path,
                    "timestamp": now,
                })

        # Keep history trimmed
        self.history = self.history[-100:]
        self._save_baseline()

        return {
            "total_monitored": len(self.monitored_paths),
            "ok":              ok,
            "modified":        modified,
            "missing":         missing,
            "ok_count":        len(ok),
            "modified_count":  len(modified),
            "missing_count":   len(missing),
            "history":         self.history[-20:],
            "checked_at":      now,
        }
