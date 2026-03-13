from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
import os

from modules.system_audit import run_system_audit
from modules.file_integrity import FileIntegrityMonitor
from modules.network_monitor import scan_network
from modules.password_checker import analyze_password
from modules.log_monitor import analyze_logs

from db.setup import setup_database
from db.operations import (
    save_alert, save_alerts_bulk, get_alerts, resolve_alert, get_alert_stats,
    save_risk_score, get_risk_history, get_risk_summary,
    save_fim_check, get_fim_logs, get_fim_stats
)

app = Flask(__name__, static_folder='frontend')
CORS(app)
fim = FileIntegrityMonitor()

DB_AVAILABLE = False
try:
    DB_AVAILABLE = setup_database()
    if DB_AVAILABLE:
        print("✅ MySQL connected successfully.")
except Exception as e:
    print(f"⚠️  MySQL not available: {e}")

@app.route('/')
def index():
    return send_from_directory('frontend', 'index.html')

@app.route('/api/audit')
def audit():
    try: return jsonify(run_system_audit())
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/network')
def network():
    try: return jsonify(scan_network())
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/logs')
def logs():
    try: return jsonify(analyze_logs())
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/password/<string:pwd>')
def password(pwd):
    try: return jsonify(analyze_password(pwd))
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/fim/status')
def fim_status():
    try: return jsonify(fim.get_status())
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/fim/add/<path:filepath>')
def fim_add(filepath):
    try: return jsonify(fim.add_path('/' + filepath))
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/fim/check')
def fim_check():
    try:
        result = fim.check_integrity()
        if DB_AVAILABLE:
            saved = save_fim_check(result)
            result["db_saved"] = saved
            if result.get("modified") or result.get("deleted"):
                total = len(result.get("modified",[])) + len(result.get("deleted",[]))
                save_alert("high", f"{total} monitored file(s) changed", "file_integrity", 20*total)
        return jsonify(result)
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/dashboard')
def dashboard():
    try:
        audit_data = run_system_audit()
        log_data   = analyze_logs()
        fim_data   = fim.check_integrity()
        net_data   = scan_network()

        risk_score = 0
        alerts = []

        if audit_data.get('open_ports'):
            risky = [p for p in audit_data['open_ports'] if p['port'] in [21,23,3389,445,139]]
            if risky:
                risk_score += 30
                alerts.append({"level":"high","msg":f"{len(risky)} risky open port(s) detected"})

        if log_data.get('failed_logins',0) > 5:
            risk_score += 25
            alerts.append({"level":"high","msg":f"{log_data['failed_logins']} failed login attempts"})

        if fim_data.get('modified'):
            risk_score += 20
            alerts.append({"level":"medium","msg":f"{len(fim_data['modified'])} file(s) modified"})

        if not audit_data.get('firewall',{}).get('enabled'):
            risk_score += 30
            alerts.append({"level":"high","msg":"Firewall is not active"})

        risk_score = min(risk_score, 100)
        summary = {
            "processes":       audit_data.get('process_count',0),
            "open_ports":      len(audit_data.get('open_ports',[])),
            "network_devices": len(net_data.get('devices',[])),
            "failed_logins":   log_data.get('failed_logins',0),
            "fim_monitored":   fim_data.get('total_monitored',0),
            "fim_modified":    len(fim_data.get('modified',[])),
        }

        if DB_AVAILABLE:
            save_risk_score(risk_score, summary["open_ports"], summary["failed_logins"],
                           summary["fim_modified"], summary["network_devices"])
            save_alerts_bulk(alerts, "dashboard", risk_score)

        return jsonify({"risk_score":risk_score,"alerts":alerts,"summary":summary,"db_enabled":DB_AVAILABLE})
    except Exception as e: return jsonify({"error": str(e)}), 500

# ── NEW DATABASE ENDPOINTS ─────────────────────────────────────
@app.route('/api/db/status')
def db_status():
    return jsonify({"connected": DB_AVAILABLE, "host": "localhost", "database": "cybersec_db"})

@app.route('/api/db/alerts')
def db_get_alerts():
    if not DB_AVAILABLE: return jsonify({"error":"Database not connected"}), 503
    return jsonify(get_alerts(limit=int(request.args.get('limit',50)), level=request.args.get('level')))

@app.route('/api/db/alerts/stats')
def db_alert_stats():
    if not DB_AVAILABLE: return jsonify({"error":"Database not connected"}), 503
    return jsonify(get_alert_stats())

@app.route('/api/db/alerts/<int:alert_id>/resolve', methods=['POST'])
def db_resolve_alert(alert_id):
    if not DB_AVAILABLE: return jsonify({"error":"Database not connected"}), 503
    return jsonify({"success": resolve_alert(alert_id), "alert_id": alert_id})

@app.route('/api/db/risk/history')
def db_risk_history():
    if not DB_AVAILABLE: return jsonify({"error":"Database not connected"}), 503
    return jsonify(get_risk_history(limit=int(request.args.get('limit',30))))

@app.route('/api/db/risk/summary')
def db_risk_summary():
    if not DB_AVAILABLE: return jsonify({"error":"Database not connected"}), 503
    return jsonify(get_risk_summary())

@app.route('/api/db/fim/logs')
def db_fim_logs():
    if not DB_AVAILABLE: return jsonify({"error":"Database not connected"}), 503
    return jsonify(get_fim_logs(limit=int(request.args.get('limit',50)), event_type=request.args.get('type')))

@app.route('/api/db/fim/stats')
def db_fim_stats():
    if not DB_AVAILABLE: return jsonify({"error":"Database not connected"}), 503
    return jsonify(get_fim_stats())

if __name__ == '__main__':
    print("🔐 CyberSec Toolkit running at http://localhost:5000")
    app.run(debug=True, port=5000)
