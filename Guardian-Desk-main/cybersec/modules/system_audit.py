import os
import sys
import subprocess
import psutil
import socket
import platform
import datetime

IS_WINDOWS = sys.platform == "win32"
IS_LINUX   = sys.platform.startswith("linux")

def _run(cmd, timeout=6):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception:
        return -1, "", ""



# ══════════════════════════════════════════════════════════════
#  FIREWALL STATUS
# ══════════════════════════════════════════════════════════════

def get_firewall_status():
    fw = {"enabled": False, "tool": "unknown", "profiles": {}, "rules": [], "rules_count": 0, "warning": None}

    if IS_WINDOWS:
        fw["tool"] = "Windows Defender Firewall"
        rc, out, _ = _run(["netsh", "advfirewall", "show", "allprofiles"], timeout=8)
        if rc == 0 and out:
            current = None
            for line in out.splitlines():
                line = line.strip()
                if "Profile Settings" in line:
                    current = line.replace(" Profile Settings:", "").strip()
                    fw["profiles"][current] = {"enabled": False}
                if current and "State" in line:
                    on = "ON" in line.upper()
                    fw["profiles"][current]["enabled"] = on
                    if on:
                        fw["enabled"] = True
            rc2, out2, _ = _run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], timeout=10)
            if rc2 == 0:
                fw["rules_count"] = out2.count("Rule Name:")
        else:
            fw["warning"] = "Could not query Windows Firewall — try running as Administrator"

    elif IS_LINUX:
        # Try ufw
        rc, out, _ = _run(["ufw", "status", "verbose"], timeout=5)
        if rc != -1:
            fw["tool"] = "ufw"
            fw["enabled"] = "active" in out.lower()
            fw["rules"] = [l.strip() for l in out.splitlines() if "ALLOW" in l or "DENY" in l][:10]
        else:
            # Try firewalld
            rc2, out2, _ = _run(["firewall-cmd", "--state"], timeout=5)
            if rc2 != -1:
                fw["tool"] = "firewalld"
                fw["enabled"] = "running" in out2.lower()
            else:
                # Try iptables
                rc3, out3, _ = _run(["iptables", "-L", "-n"], timeout=5)
                if rc3 != -1:
                    fw["tool"] = "iptables"
                    rules = [l for l in out3.splitlines() if l and not l.startswith("Chain") and not l.startswith("target")]
                    fw["rules"] = rules[:10]
                    fw["enabled"] = len(rules) > 0
                else:
                    # Try nftables
                    rc4, out4, _ = _run(["nft", "list", "ruleset"], timeout=5)
                    if rc4 != -1:
                        fw["tool"] = "nftables"
                        fw["enabled"] = bool(out4.strip())
                    else:
                        fw["warning"] = "No firewall found (ufw/firewalld/iptables/nftables not available)"
    else:
        # macOS
        rc, out, _ = _run(["pfctl", "-s", "info"], timeout=5)
        if rc != -1:
            fw["tool"] = "pf (macOS)"
            fw["enabled"] = "enabled" in out.lower()
        else:
            fw["warning"] = "Could not query macOS firewall"

    if not fw["enabled"] and not fw["warning"]:
        fw["warning"] = f"⚠️ Firewall ({fw['tool']}) is INACTIVE — system is exposed"

    return fw


# ══════════════════════════════════════════════════════════════
#  ANTIVIRUS / ENDPOINT PROTECTION
# ══════════════════════════════════════════════════════════════

def get_antivirus_status():
    products = []

    if IS_WINDOWS:
        import json as _json
        # Windows Security Center
        rc, out, _ = _run([
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
            "| Select-Object displayName,productState | ConvertTo-Json"
        ], timeout=10)
        if rc == 0 and out:
            try:
                raw = _json.loads(out)
                if isinstance(raw, dict): raw = [raw]
                for item in raw:
                    state = int(item.get("productState", 0))
                    products.append({
                        "name":    item.get("displayName", "Unknown"),
                        "enabled": ((state >> 12) & 0xF) == 1,
                    })
            except Exception:
                pass

        # Windows Defender specifically
        rc2, out2, _ = _run([
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AMRunningMode,"
            "AntivirusSignatureLastUpdated | ConvertTo-Json"
        ], timeout=10)
        if rc2 == 0 and out2:
            try:
                d = _json.loads(out2)
                defender = {
                    "name":         "Windows Defender",
                    "enabled":      bool(d.get("RealTimeProtectionEnabled")),
                    "mode":         d.get("AMRunningMode", ""),
                    "last_updated": str(d.get("AntivirusSignatureLastUpdated", ""))[:10],
                }
                if not any(p["name"] == "Windows Defender" for p in products):
                    products.append(defender)
                else:
                    for p in products:
                        if p["name"] == "Windows Defender":
                            p.update(defender)
            except Exception:
                pass

    else:
        for binary, service, display in [
            ("clamav",   "clamav-daemon", "ClamAV"),
            ("fail2ban", "fail2ban",      "Fail2Ban"),
            ("rkhunter", None,            "RootKit Hunter"),
        ]:
            rc_b, _, _ = _run(["which", binary], timeout=3)
            installed = rc_b == 0
            active = None
            if service:
                rc_s, out_s, _ = _run(["systemctl", "is-active", service], timeout=3)
                if rc_s != -1:
                    active = out_s == "active"
            if installed or active:
                products.append({"name": display, "installed": installed, "enabled": active if active is not None else installed})

    return {"products": products, "any_active": any(p.get("enabled") for p in products)}


# ══════════════════════════════════════════════════════════════
#  HARDENING CHECKS
# ══════════════════════════════════════════════════════════════

def get_hardening_status():
    checks = []

    if IS_WINDOWS:
        import json as _json

        # UAC
        rc, out, _ = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
            "(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System).EnableLUA"
        ], timeout=6)
        uac = rc == 0 and out.strip() == "1"
        checks.append({"check": "UAC Enabled", "status": "pass" if uac else "fail", "severity": "high"})

        # RDP disabled
        rc2, out2, _ = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
            "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections"
        ], timeout=6)
        rdp_off = rc2 == 0 and out2.strip() == "1"
        checks.append({"check": "RDP Disabled", "status": "pass" if rdp_off else "warn", "severity": "medium"})

        # SMBv1
        rc3, out3, _ = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
            "(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State"
        ], timeout=12)
        smb1_off = rc3 != 0 or "Disabled" in out3
        checks.append({"check": "SMBv1 Disabled (WannaCry)", "status": "pass" if smb1_off else "fail", "severity": "critical"})

        # Guest account
        rc4, out4, _ = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
            "(Get-LocalUser -Name Guest).Enabled"
        ], timeout=6)
        guest_off = rc4 == 0 and "False" in out4
        checks.append({"check": "Guest Account Disabled", "status": "pass" if guest_off else "warn", "severity": "medium"})

    else:
        # SELinux
        rc, out, _ = _run(["getenforce"], timeout=3)
        if rc != -1:
            checks.append({"check": "SELinux", "status": "pass" if out == "Enforcing" else "warn",
                            "mode": out or "disabled", "severity": "high"})

        # AppArmor
        rc2, _, _ = _run(["aa-status", "--enabled"], timeout=3)
        if rc2 != -1:
            checks.append({"check": "AppArmor", "status": "pass" if rc2 == 0 else "warn",
                            "enabled": rc2 == 0, "severity": "high"})

        # SSH config
        ssh_conf = "/etc/ssh/sshd_config"
        if os.path.isfile(ssh_conf):
            try:
                content = open(ssh_conf).read()
                root_no = "PermitRootLogin no" in content
                pw_no   = "PasswordAuthentication no" in content
                checks.append({"check": "SSH Root Login Disabled", "status": "pass" if root_no else "fail", "severity": "critical"})
                checks.append({"check": "SSH Password Auth Disabled", "status": "pass" if pw_no else "warn", "severity": "medium"})
            except Exception:
                pass

        # /tmp noexec
        rc3, out3, _ = _run(["findmnt", "-n", "-o", "OPTIONS", "/tmp"], timeout=3)
        if rc3 == 0:
            checks.append({"check": "/tmp noexec", "status": "pass" if "noexec" in out3 else "warn", "severity": "medium"})

    passed   = sum(1 for c in checks if c["status"] == "pass")
    failed   = sum(1 for c in checks if c["status"] == "fail")
    warnings = sum(1 for c in checks if c["status"] == "warn")
    score    = int((passed / len(checks)) * 100) if checks else 0
    grade    = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return {"checks": checks, "passed": passed, "failed": failed, "warnings": warnings, "score": score, "grade": grade}


def run_system_audit():
    """
    Collect system-level security audit data:
    - OS info
    - CPU / memory / disk usage
    - Running processes count
    - Open listening ports
    - Boot time
    """
    # ── OS Info ───────────────────────────────────────────────────────────────
    os_info = {
        "system":    platform.system(),
        "release":   platform.release(),
        "version":   platform.version(),
        "machine":   platform.machine(),
        "processor": platform.processor(),
        "hostname":  socket.gethostname(),
    }

    # ── Resource Usage ────────────────────────────────────────────────────────
    cpu_percent  = psutil.cpu_percent(interval=1)
    mem          = psutil.virtual_memory()
    disk         = psutil.disk_usage('/')

    resources = {
        "cpu_percent":  cpu_percent,
        "memory": {
            "total":     mem.total,
            "available": mem.available,
            "percent":   mem.percent,
        },
        "disk": {
            "total":   disk.total,
            "used":    disk.used,
            "free":    disk.free,
            "percent": disk.percent,
        },
    }

    # ── Processes ─────────────────────────────────────────────────────────────
    process_count = len(list(psutil.process_iter()))

    # ── Open Ports ────────────────────────────────────────────────────────────
    open_ports = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                try:
                    service = socket.getservbyport(conn.laddr.port)
                except Exception:
                    service = "unknown"
                open_ports.append({
                    "port":    conn.laddr.port,
                    "address": conn.laddr.ip,
                    "service": service,
                })
        # deduplicate by port
        seen = set()
        unique_ports = []
        for p in open_ports:
            if p['port'] not in seen:
                seen.add(p['port'])
                unique_ports.append(p)
        open_ports = sorted(unique_ports, key=lambda x: x['port'])
    except (psutil.AccessDenied, PermissionError):
        open_ports = []

    # ── Boot Time ─────────────────────────────────────────────────────────────
    boot_ts   = psutil.boot_time()
    boot_time = datetime.datetime.fromtimestamp(boot_ts).isoformat()

    # ── Firewall / AV / Hardening ─────────────────────────────────────────────
    firewall  = get_firewall_status()
    antivirus = get_antivirus_status()
    hardening = get_hardening_status()

    return {
        "os_info":       os_info,
        "resources":     resources,
        "process_count": process_count,
        "open_ports":    open_ports,
        "boot_time":     boot_time,
        "firewall":      firewall,
        "antivirus":     antivirus,
        "hardening":     hardening,
        "scan_time":     datetime.datetime.now().isoformat(),
    }
