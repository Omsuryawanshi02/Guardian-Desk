from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import os

from modules.system_audit import run_system_audit
from modules.file_integrity import FileIntegrityMonitor
from modules.network_monitor import scan_network
from modules.password_checker import analyze_password
from modules.log_monitor import analyze_logs

app = Flask(__name__, static_folder='frontend')
CORS(app)

fim = FileIntegrityMonitor()

# ─── Serve Frontend ───────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('frontend', 'index.html')

@app.route('/dashboard')
def dashboard_page():
    return send_from_directory('frontend', 'dashboard.html')

@app.route('/audit')
def audit_page():
    return send_from_directory('frontend', 'audit.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('frontend', path)

# ─── API: System Audit ────────────────────────────────────────────────────────

@app.route('/api/audit')
def audit():
    try:
        return jsonify(run_system_audit())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── API: Network ─────────────────────────────────────────────────────────────

@app.route('/api/network')
def network():
    try:
        return jsonify(scan_network())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── API: Logs ────────────────────────────────────────────────────────────────

@app.route('/api/logs')
def logs():
    try:
        return jsonify(analyze_logs())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── API: Password ────────────────────────────────────────────────────────────

@app.route('/api/password/<string:pwd>')
def password(pwd):
    try:
        return jsonify(analyze_password(pwd))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── API: File Integrity Monitor ──────────────────────────────────────────────

@app.route('/api/fim/status')
def fim_status():
    try:
        return jsonify(fim.get_status())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/fim/check')
def fim_check():
    try:
        return jsonify(fim.check_integrity())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/fim/add/<path:filepath>')
def fim_add(filepath):
    try:
        result = fim.add_path('/' + filepath)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── API: Dashboard Summary ───────────────────────────────────────────────────

@app.route('/api/dashboard')
def dashboard():
    try:
        audit_data = run_system_audit()
        log_data   = analyze_logs()
        fim_data   = fim.check_integrity()
        net_data   = scan_network()

        risk_score = 0
        alerts = []

        risky_ports = [21, 23, 3389, 445, 139]
        if audit_data.get('open_ports'):
            risky = [p for p in audit_data['open_ports'] if p['port'] in risky_ports]
            if risky:
                risk_score += 30
                alerts.append({"level": "high", "msg": f"{len(risky)} risky open port(s) detected"})

        if log_data.get('failed_logins', 0) > 5:
            risk_score += 25
            alerts.append({"level": "high", "msg": f"{log_data['failed_logins']} failed login attempts detected"})

        if fim_data.get('modified'):
            risk_score += 20
            alerts.append({"level": "medium", "msg": f"{len(fim_data['modified'])} monitored file(s) modified"})

        if len(net_data.get('devices', [])) > 10:
            risk_score += 10
            alerts.append({"level": "low", "msg": f"{len(net_data['devices'])} devices on network"})

        return jsonify({
            "risk_score": min(risk_score, 100),
            "alerts": alerts,
            "summary": {
                "processes":        audit_data.get('process_count', 0),
                "open_ports":       len(audit_data.get('open_ports', [])),
                "network_devices":  len(net_data.get('devices', [])),
                "failed_logins":    log_data.get('failed_logins', 0),
                "fim_monitored":    fim_data.get('total_monitored', 0),
                "fim_modified":     len(fim_data.get('modified', [])),
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── Run ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("🔐 CyberSec Toolkit running at http://localhost:5000")
    app.run(debug=True, port=5000)
