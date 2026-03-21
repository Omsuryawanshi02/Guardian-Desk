import socket
import psutil
import datetime
import subprocess
import sys
import ipaddress
import threading

IS_WINDOWS = sys.platform == "win32"


def _get_local_ip():
    """Get the machine's local WiFi/LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _get_subnet(local_ip):
    """
    Get subnet prefix from local IP.
    e.g. 192.168.1.105 → 192.168.1
    """
    parts = local_ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3])
    return None


def _ping(ip):
    """Ping a single IP. Returns True if alive."""
    try:
        if IS_WINDOWS:
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "300", ip],
                capture_output=True, timeout=2
            )
        else:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True, timeout=2
            )
        return result.returncode == 0
    except Exception:
        return False


def _get_hostname(ip):
    """Try to resolve hostname for an IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _ping_sweep(subnet, local_ip):
    """
    Ping all 254 IPs in the subnet concurrently.
    Returns list of alive devices with IP and hostname.
    """
    alive = []
    lock  = threading.Lock()

    def check(ip):
        if ip == local_ip:
            # Always include our own IP
            hostname = _get_hostname(ip)
            with lock:
                alive.append({
                    "ip":       ip,
                    "hostname": hostname or "This Device",
                    "self":     True,
                })
            return
        if _ping(ip):
            hostname = _get_hostname(ip)
            with lock:
                alive.append({
                    "ip":       ip,
                    "hostname": hostname,
                    "self":     False,
                })

    threads = []
    for i in range(1, 255):
        ip = f"{subnet}.{i}"
        t  = threading.Thread(target=check, args=(ip,), daemon=True)
        threads.append(t)
        t.start()

    # Wait for all threads (max 5 seconds total)
    for t in threads:
        t.join(timeout=5)

    return sorted(alive, key=lambda x: int(x["ip"].split(".")[-1]))


def _arp_devices(subnet, local_ip):
    """
    Fast fallback: read ARP cache for devices on our subnet.
    Only returns dynamic (active) entries.
    """
    devices = []
    seen    = set()

    # Always include self
    devices.append({"ip": local_ip, "hostname": "This Device", "self": True})
    seen.add(local_ip)

    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                ip    = parts[0].strip()
                state = parts[-1].strip().lower() if len(parts) >= 3 else ""

                # Windows: only dynamic entries on our subnet
                if IS_WINDOWS and "dynamic" not in state:
                    continue

                # Must be on same subnet
                if not ip.startswith(subnet + "."):
                    continue

                # Skip broadcast/multicast
                if ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239."):
                    continue

                if ip not in seen:
                    seen.add(ip)
                    hostname = _get_hostname(ip)
                    devices.append({
                        "ip":       ip,
                        "hostname": hostname,
                        "self":     False,
                    })
    except Exception:
        pass

    return sorted(devices, key=lambda x: int(x["ip"].split(".")[-1]))


def _scan_wifi_devices(local_ip):
    """
    Main device discovery:
    1. Try ARP cache first (fast, ~instant)
    2. Enrich with ping sweep results
    Returns all devices found on the local WiFi network.
    """
    subnet = _get_subnet(local_ip)
    if not subnet:
        return [{"ip": local_ip, "hostname": "This Device", "self": True}]

    # Start with ARP cache (instant)
    arp_devices = _arp_devices(subnet, local_ip)

    # Also run a quick ping sweep in parallel to find devices
    # not yet in ARP cache (e.g. phones in sleep mode)
    pinged = _ping_sweep(subnet, local_ip)

    # Merge both lists, deduplicate by IP
    merged = {d["ip"]: d for d in arp_devices}
    for d in pinged:
        if d["ip"] not in merged:
            merged[d["ip"]] = d

    return sorted(merged.values(), key=lambda x: int(x["ip"].split(".")[-1]))


def scan_network():
    """
    Full network scan:
    - All local interfaces
    - Active connection summary
    - I/O statistics
    - WiFi device discovery (ping sweep + ARP)
    """

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
        "time_wait":   0, "close_wait": 0, "other": 0,
    }
    try:
        for conn in psutil.net_connections(kind="inet"):
            status = (conn.status or "other").lower()
            if status in connections_summary:
                connections_summary[status] += 1
            else:
                connections_summary["other"] += 1
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
    local_ip = _get_local_ip()

    # ── WiFi Device Discovery ─────────────────────────────────────────────────
    devices = _scan_wifi_devices(local_ip)

    return {
        "hostname":            hostname,
        "local_ip":            local_ip,
        "interfaces":          interfaces,
        "connections_summary": connections_summary,
        "io_stats":            io_stats,
        "devices":             devices,
        "total_devices":       len(devices),
        "subnet":              _get_subnet(local_ip),
        "scanned_at":          datetime.datetime.now().isoformat(),
    }
