# db/operations.py
# All database read/write functions used by the Flask API

import mysql.connector
from datetime import datetime
from db.config import DB_CONFIG

def get_connection():
    """Get a fresh MySQL connection."""
    return mysql.connector.connect(**DB_CONFIG)


#  SECURITY ALERTS
 

def save_alert(level, message, module_source, risk_score=0):
    """
    Save a new security alert to the database.
    Called whenever any module detects a threat.

    Example:
        save_alert("high", "Port 3389 open (RDP)", "system_audit", 60)
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO security_alerts (alert_level, alert_message, module_source, risk_score)
            VALUES (%s, %s, %s, %s)
        """, (level, message, module_source, risk_score))
        conn.commit()
        inserted_id = cursor.lastrowid
        cursor.close()
        conn.close()
        return inserted_id
    except mysql.connector.Error as e:
        print(f"DB Error (save_alert): {e}")
        return None

def save_alerts_bulk(alerts, module_source, risk_score=0):
    """
    Save multiple alerts at once (used by dashboard aggregator).

    alerts = [{"level": "high", "msg": "..."}, ...]
    """
    saved = []
    for alert in alerts:
        aid = save_alert(
            level=alert.get("level", "info"),
            message=alert.get("msg", ""),
            module_source=module_source,
            risk_score=risk_score
        )
        if aid:
            saved.append(aid)
    return saved

def get_alerts(limit=50, level=None, resolved=False):
    """
    Fetch alerts from DB. Optionally filter by level or resolved status.

    Returns list of dicts.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = "SELECT * FROM security_alerts WHERE is_resolved = %s"
        params = [resolved]

        if level:
            query += " AND alert_level = %s"
            params.append(level)

        query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        # Convert datetime objects to strings for JSON
        for row in rows:
            if row.get("created_at"):
                row["created_at"] = row["created_at"].strftime("%Y-%m-%d %H:%M:%S")
            if row.get("resolved_at"):
                row["resolved_at"] = row["resolved_at"].strftime("%Y-%m-%d %H:%M:%S")
        return rows
    except mysql.connector.Error as e:
        print(f"DB Error (get_alerts): {e}")
        return []

def resolve_alert(alert_id):
    """Mark an alert as resolved."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE security_alerts
            SET is_resolved = TRUE, resolved_at = %s
            WHERE id = %s
        """, (datetime.now(), alert_id))
        conn.commit()
        affected = cursor.rowcount
        cursor.close()
        conn.close()
        return affected > 0
    except mysql.connector.Error as e:
        print(f"DB Error (resolve_alert): {e}")
        return False

def get_alert_stats():
    """Get count of alerts grouped by level (for dashboard summary)."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT alert_level, COUNT(*) as count
            FROM security_alerts
            WHERE is_resolved = FALSE
            GROUP BY alert_level
        """)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return {row["alert_level"]: row["count"] for row in rows}
    except mysql.connector.Error as e:
        print(f"DB Error (get_alert_stats): {e}")
        return {}


#  RISK SCORE HISTORY


def save_risk_score(score, open_ports=0, failed_logins=0, fim_modified=0, network_devices=0):
    """
    Save a risk score snapshot. Called every time /api/dashboard is hit.
    Builds up a history for trend charts.
    """
    if score >= 70:
        label = "HIGH RISK"
    elif score >= 40:
        label = "MODERATE"
    else:
        label = "SECURE"

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO risk_score_history
                (risk_score, risk_label, open_ports, failed_logins, fim_modified, network_devices)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (score, label, open_ports, failed_logins, fim_modified, network_devices))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except mysql.connector.Error as e:
        print(f"DB Error (save_risk_score): {e}")
        return False

def get_risk_history(limit=30):
    """
    Get last N risk score snapshots for trend chart.
    Returns list ordered oldest → newest.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT risk_score, risk_label, open_ports, failed_logins,
                   fim_modified, network_devices, recorded_at
            FROM risk_score_history
            ORDER BY recorded_at DESC
            LIMIT %s
        """, (limit,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        for row in rows:
            if row.get("recorded_at"):
                row["recorded_at"] = row["recorded_at"].strftime("%Y-%m-%d %H:%M:%S")

        return list(reversed(rows))  # oldest first for chart
    except mysql.connector.Error as e:
        print(f"DB Error (get_risk_history): {e}")
        return []

def get_risk_summary():
    """Get min, max, avg risk score from history."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT
                MIN(risk_score) as min_score,
                MAX(risk_score) as max_score,
                ROUND(AVG(risk_score), 1) as avg_score,
                COUNT(*) as total_scans
            FROM risk_score_history
        """)
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return row or {}
    except mysql.connector.Error as e:
        print(f"DB Error (get_risk_summary): {e}")
        return {}


#  FILE INTEGRITY LOGS


def save_fim_result(file_path, event_type, original_hash=None, current_hash=None, size_change=0):
    """
    Save a single file integrity event.

    event_type: 'added' | 'modified' | 'deleted' | 'unchanged'
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO fim_logs (file_path, event_type, original_hash, current_hash, size_change)
            VALUES (%s, %s, %s, %s, %s)
        """, (file_path, event_type, original_hash, current_hash, size_change))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except mysql.connector.Error as e:
        print(f"DB Error (save_fim_result): {e}")
        return False

def save_fim_check(fim_data):
    """
    Save a full FIM check result to DB.
    fim_data = result from FileIntegrityMonitor.check_integrity()
    """
    saved = 0
    for f in fim_data.get("modified", []):
        save_fim_result(
            file_path=f["path"],
            event_type="modified",
            original_hash=f.get("original_hash", ""),
            current_hash=f.get("current_hash", ""),
            size_change=f.get("size_change", 0)
        )
        saved += 1

    for f in fim_data.get("deleted", []):
        save_fim_result(
            file_path=f["path"],
            event_type="deleted",
            original_hash=f.get("original_hash", "")
        )
        saved += 1

    return saved

def get_fim_logs(limit=50, event_type=None):
    """Fetch FIM logs from DB, optionally filter by event type."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = "SELECT * FROM fim_logs"
        params = []

        if event_type:
            query += " WHERE event_type = %s"
            params.append(event_type)

        query += " ORDER BY checked_at DESC LIMIT %s"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        for row in rows:
            if row.get("checked_at"):
                row["checked_at"] = row["checked_at"].strftime("%Y-%m-%d %H:%M:%S")
        return rows
    except mysql.connector.Error as e:
        print(f"DB Error (get_fim_logs): {e}")
        return []

def get_fim_stats():
    """Get count of each FIM event type."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT event_type, COUNT(*) as count
            FROM fim_logs
            GROUP BY event_type
        """)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return {row["event_type"]: row["count"] for row in rows}
    except mysql.connector.Error as e:
        print(f"DB Error (get_fim_stats): {e}")
        return {}
