import psutil
import socket
import platform
import datetime


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

    return {
        "os_info":       os_info,
        "resources":     resources,
        "process_count": process_count,
        "open_ports":    open_ports,
        "boot_time":     boot_time,
        "scan_time":     datetime.datetime.now().isoformat(),
    }
