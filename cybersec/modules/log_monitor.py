import os
import re
import datetime
from pathlib import Path


# Platform log file candidates (first found is used)
AUTH_LOG_CANDIDATES = [
    "/var/log/auth.log",        # Debian/Ubuntu
    "/var/log/secure",          # RHEL/CentOS/Fedora
    "/var/log/system.log",      # macOS
]

SYSLOG_CANDIDATES = [
    "/var/log/syslog",
    "/var/log/messages",
]

MAX_LINES = 2000  # read last N lines to keep it fast


def _tail(filepath: str, n: int = MAX_LINES) -> list[str]:
    """Return the last n lines of a file."""
    try:
        with open(filepath, "r", errors="replace") as f:
            lines = f.readlines()
        return lines[-n:]
    except (OSError, PermissionError):
        return []


def _find_log(candidates: list[str]) -> str | None:
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def analyze_logs() -> dict:
    """
    Parse system auth and syslog files for security-relevant events.
    Returns counts and recent samples of:
      - failed login attempts
      - successful logins
      - sudo usage
      - SSH connections
      - suspicious patterns (e.g., repeated failures from same IP)
    """
    auth_log   = _find_log(AUTH_LOG_CANDIDATES)
    syslog     = _find_log(SYSLOG_CANDIDATES)

    failed_logins    = 0
    success_logins   = 0
    sudo_events      = 0
    ssh_events       = 0
    failed_ips: dict = {}   # ip -> count

    recent_failed   = []
    recent_success  = []
    recent_sudo     = []

    # ── Auth Log Parsing ──────────────────────────────────────────────────────
    if auth_log:
        for line in _tail(auth_log):
            lower = line.lower()

            # Failed logins
            if "failed password" in lower or "authentication failure" in lower or "invalid user" in lower:
                failed_logins += 1
                # Extract IP
                ip_match = re.search(r'from\s+([\d.]+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    failed_ips[ip] = failed_ips.get(ip, 0) + 1
                if len(recent_failed) < 10:
                    recent_failed.append(line.strip())

            # Successful logins
            elif "accepted password" in lower or "accepted publickey" in lower or "session opened" in lower:
                success_logins += 1
                if len(recent_success) < 10:
                    recent_success.append(line.strip())

            # Sudo
            if "sudo:" in lower:
                sudo_events += 1
                if len(recent_sudo) < 10:
                    recent_sudo.append(line.strip())

            # SSH
            if "sshd" in lower:
                ssh_events += 1

    # ── Syslog Parsing ────────────────────────────────────────────────────────
    syslog_errors = 0
    syslog_warnings = 0
    recent_errors = []

    if syslog:
        for line in _tail(syslog):
            lower = line.lower()
            if " error" in lower or "err:" in lower:
                syslog_errors += 1
                if len(recent_errors) < 10:
                    recent_errors.append(line.strip())
            elif "warn" in lower:
                syslog_warnings += 1

    # ── Suspicious IPs (≥5 failures) ─────────────────────────────────────────
    suspicious_ips = [
        {"ip": ip, "count": count}
        for ip, count in sorted(failed_ips.items(), key=lambda x: -x[1])
        if count >= 5
    ]

    return {
        "auth_log":          auth_log,
        "syslog":            syslog,
        "failed_logins":     failed_logins,
        "success_logins":    success_logins,
        "sudo_events":       sudo_events,
        "ssh_events":        ssh_events,
        "syslog_errors":     syslog_errors,
        "syslog_warnings":   syslog_warnings,
        "suspicious_ips":    suspicious_ips,
        "recent_failed":     recent_failed,
        "recent_success":    recent_success,
        "recent_sudo":       recent_sudo,
        "recent_errors":     recent_errors,
        "analyzed_at":       datetime.datetime.now().isoformat(),
    }
