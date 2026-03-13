import socket
import psutil
import datetime


def scan_network() -> dict:
    """
    Gather local network information:
    - Active network interfaces and their IPs
    - Current TCP/UDP connections (summary)
    - Detected local devices via ARP cache (parsed from psutil)
    """

    # ── Network Interfaces ────────────────────────────────────────────────────
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        iface = {"name": name, "addresses": []}
        for addr in addrs:
            entry = {
                "family":  str(addr.family),
                "address": addr.address,
            }
            if addr.netmask:
                entry["netmask"] = addr.netmask
            iface["addresses"].append(entry)
        interfaces.append(iface)

    # ── Connection Summary ────────────────────────────────────────────────────
    connections_summary = {
        "established": 0,
        "listen":      0,
        "time_wait":   0,
        "close_wait":  0,
        "other":       0,
    }
    remote_ips = set()
    try:
        for conn in psutil.net_connections(kind='inet'):
            status = (conn.status or "other").lower()
            if status in connections_summary:
                connections_summary[status] += 1
            else:
                connections_summary["other"] += 1
            if conn.raddr and conn.raddr.ip:
                remote_ips.add(conn.raddr.ip)
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

    # ── Local Hostname / IP ───────────────────────────────────────────────────
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "127.0.0.1"

    # Represent remote IPs as "devices" for dashboard compatibility
    devices = [{"ip": ip} for ip in sorted(remote_ips)]

    return {
        "hostname":            hostname,
        "local_ip":            local_ip,
        "interfaces":          interfaces,
        "connections_summary": connections_summary,
        "io_stats":            io_stats,
        "devices":             devices,
        "scanned_at":          datetime.datetime.now().isoformat(),
    }
