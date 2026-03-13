import os
import hashlib
import json
import datetime


BASELINE_FILE = "fim_baseline.json"

# Default paths to monitor (cross-platform safe defaults)
DEFAULT_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
]


def _hash_file(filepath: str) -> str | None:
    """Return SHA-256 hex digest of a file, or None if unreadable."""
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, PermissionError):
        return None


class FileIntegrityMonitor:
    def __init__(self, baseline_path: str = BASELINE_FILE):
        self.baseline_path = baseline_path
        self.monitored_paths: list[str] = []
        self.baseline: dict = {}
        self._load_baseline()

        # Seed with default paths that exist on this system
        for p in DEFAULT_PATHS:
            if os.path.isfile(p):
                self.add_path(p)

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load_baseline(self):
        if os.path.isfile(self.baseline_path):
            try:
                with open(self.baseline_path) as f:
                    data = json.load(f)
                    self.monitored_paths = data.get("paths", [])
                    self.baseline        = data.get("hashes", {})
            except (json.JSONDecodeError, OSError):
                self.monitored_paths = []
                self.baseline        = {}

    def _save_baseline(self):
        try:
            with open(self.baseline_path, "w") as f:
                json.dump({
                    "paths":   self.monitored_paths,
                    "hashes":  self.baseline,
                    "updated": datetime.datetime.now().isoformat(),
                }, f, indent=2)
        except OSError:
            pass

    # ── Public API ────────────────────────────────────────────────────────────

    def add_path(self, filepath: str) -> dict:
        """Add a file to the monitored set and baseline its current hash."""
        if not os.path.isfile(filepath):
            return {"success": False, "error": f"File not found: {filepath}"}

        h = _hash_file(filepath)
        if h is None:
            return {"success": False, "error": f"Cannot read: {filepath}"}

        if filepath not in self.monitored_paths:
            self.monitored_paths.append(filepath)
        self.baseline[filepath] = h
        self._save_baseline()
        return {"success": True, "path": filepath, "hash": h}

    def get_status(self) -> dict:
        return {
            "total_monitored": len(self.monitored_paths),
            "monitored_paths": self.monitored_paths,
            "baseline_file":   self.baseline_path,
            "last_checked":    datetime.datetime.now().isoformat(),
        }

    def check_integrity(self) -> dict:
        """
        Compare current file hashes against the stored baseline.
        Returns lists of: ok, modified, missing files.
        """
        ok       = []
        modified = []
        missing  = []

        for path in self.monitored_paths:
            if not os.path.isfile(path):
                missing.append(path)
                continue
            current_hash = _hash_file(path)
            if current_hash is None:
                missing.append(path)
            elif current_hash == self.baseline.get(path):
                ok.append(path)
            else:
                modified.append({
                    "path":         path,
                    "expected":     self.baseline.get(path),
                    "actual":       current_hash,
                    "detected_at":  datetime.datetime.now().isoformat(),
                })

        return {
            "total_monitored": len(self.monitored_paths),
            "ok":              ok,
            "modified":        modified,
            "missing":         missing,
            "checked_at":      datetime.datetime.now().isoformat(),
        }
