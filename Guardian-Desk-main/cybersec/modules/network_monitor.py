import socket
import psutil
import datetime
import subprocess
import sys

IS_WINDOWS = sys.platform == "win32"


def _get_local_subnets():
    """Get all local subnet prefixes e.g. 192.168., 10.0., 172.16."""
    subnets = set()
    try:
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                ip = addr.address
                if addr.family.name in ('AF_INET',) or str(addr.family) in ('AddressFamily.AF_INET', '2'):
                    parts = ip.split('.')
                    if len(parts) == 4 and not ip.startswith('127.'):
                        subnets.add(parts[0] + '.' + parts[1] + '.')
    except Exception:
        pass
    return subnets


def _get_lan_devices():
    """
    Get only LOCAL network devices (same subnet).
    Filters out internet IPs, loopback, multicast etc.
    """
    local_subnets = _get_local_subnets()
    lan_ips = set()

    # Method 1: Active ESTABLISHED connections to local IPs only
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr and conn.raddr.ip:
                ip = conn.raddr.ip
                # Only include if it's on the local subnet
                if any(ip.startswith(s) for s in local_subnets):
                    lan_ips.add(ip)
    except (psutil.AccessDenied, PermissionError):
        pass

    # Method 2: ARP cache — only active/reachable local entries
    try:
        if IS_WINDOWS:
            result = subprocess.run(
                ['arp', '-a'], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    state = parts[-1].strip().lower() if len(parts) >= 3 else ''
                    # Only count dynamic entries (actively resolved)
                    if 'dynamic' in state:
                        if any(ip.startswith(s) for s in local_subnets):
                            if not ip.startswith('224.') and not ip.startswith('239.') and not ip.endswith('.255'):
                                lan_ips.add(ip)
        else:
            result = subprocess.run(
                ['arp', '-n'], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[2] != '(incomplete)':
                    ip = parts[0].strip()
                    if any(ip.startswith(s) for s in local_subnets):
                        lan_ips.add(ip)
    except Exception:
        pass

    return sorted(lan_ips)


def scan_network():
    # ── Interfaces ────────────────────────────────────────────────────────────
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        iface = {"name": name, "addresses": []}
        for addr in addrs:
            entry = {"family": str(addr.family), "address": addr.address}
            if addr.netmask:
                entry["netmask"] = addr.netmask
            iface["addresses"].append(entry)
        interfaces.append(iface)

    # ── Connection Summary ────────────────────────────────────────────────────
    connections_summary = {
        "established": 0, "listen": 0,
        "time_wait": 0, "close_wait": 0, "other": 0,
    }
    all_remote_ips = set()
    try:
        for conn in psutil.net_connections(kind='inet'):
            status = (conn.status or "other").lower()
            if status in connections_summary:
                connections_summary[status] += 1
            else:
                connections_summary["other"] += 1
            if conn.raddr and conn.raddr.ip:
                all_remote_ips.add(conn.raddr.ip)
    except (psutil.AccessDenied, PermissionError):
        pass

    # ── I/O Stats ─────────────────────────────────────────────────────────────
    io = psutil.net_io_counters()
    io_stats = {
        "bytes_sent":   io.bytes_sent,
        "bytes_recv":   io.bytes_recv,
        "packets_sent": io.packets_sent,
        "packets_recv": io.packets_recv,
        "errin":        io.errin,
        "errout":       io.errout,
        "dropin":       io.dropin,
        "dropout":      io.dropout,
    }

    # ── Hostname / IP ─────────────────────────────────────────────────────────
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "127.0.0.1"

    # ── LAN devices only (not internet IPs) ──────────────────────────────────
    lan_ips  = _get_lan_devices()
    devices  = [{"ip": ip} for ip in lan_ips]

    return {
        "hostname":            hostname,
        "local_ip":            local_ip,
        "interfaces":          interfaces,
        "connections_summary": connections_summary,
        "io_stats":            io_stats,
        "devices":             devices,
        "scanned_at":          datetime.datetime.now().isoformat(),
    }
