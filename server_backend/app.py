# app.py (Didi's Server Backend - Day 5, 7, 9, 10 Logic)
from flask import Flask, request, jsonify
# NOTE: We assume 'models.py' exists and defines Incident, Session, and engine.
from models import Incident, Session, engine 
from datetime import datetime
import time 
import requests
import os
import json
from sqlalchemy import func 

# --- Configuration for Webhook/Email (Placeholder values) ---
WEBHOOK_URL = "https://your.slack.webhook.url/..."
EMAIL_SENDER = "didi.alerts@sentinel.com"
EMAIL_RECEIVER = "security_team@corp.com"
# -----------------------------------------------------------

# --- Day 9: Threat Intelligence Configuration ---
# Path to IP blacklist file
BLACKLIST_FILE = os.path.join(os.path.dirname(__file__), '..', 'ip_blacklist.json')

def load_blacklist():
    """Load IP blacklist from file."""
    if os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE, 'r') as f:
                data = json.load(f)
                return set(data.get('ips', []))
        except Exception as e:
            print(f"Warning: Could not load blacklist: {e}")
            return set()
    return set()

def check_ip_threat(ip_address):
    """
    Day 9: Check if IP is in blacklist and return threat intelligence.
    
    Args:
        ip_address: IP address to check
        
    Returns:
        Dictionary with threat intelligence data
    """
    blacklist = load_blacklist()
    is_blacklisted = ip_address in blacklist
    
    threat_info = {
        'is_blacklisted': is_blacklisted,
        'threat_level': 'High' if is_blacklisted else 'Unknown',
        'source': 'Local Blacklist' if is_blacklisted else None,
        'notes': f'IP {ip_address} found in blacklist' if is_blacklisted else None
    }
    
    return threat_info

def enrich_incident_data(incident_data):
    """
    Day 9: Enrich incident data with threat intelligence before saving.
    
    Args:
        incident_data: Original incident data dictionary
        
    Returns:
        Enriched incident data dictionary
    """
    ip = incident_data.get('ip')
    if not ip:
        return incident_data
    
    # Check IP against blacklist
    threat_info = check_ip_threat(ip)
    
    # Enrich incident data
    enriched_data = incident_data.copy()
    
    # If IP is blacklisted, elevate severity
    if threat_info['is_blacklisted']:
        current_severity = enriched_data.get('severity', 'Medium')
        severity_levels = ['Low', 'Medium', 'High', 'Critical']
        current_index = severity_levels.index(current_severity) if current_severity in severity_levels else 1
        
        # Elevate by one level, but don't exceed Critical
        if current_index < len(severity_levels) - 1:
            enriched_data['severity'] = severity_levels[current_index + 1]
        
        # Add threat intelligence note to rule
        original_rule = enriched_data.get('rule', '')
        enriched_data['rule'] = f"{original_rule} [BLACKLISTED IP]"
    
    # Store threat intelligence in a separate field (we'll add this to the model if needed)
    enriched_data['threat_intel'] = threat_info
    
    return enriched_data

# Initialize Flask project structure
app = Flask(__name__)

# Basic route for testing server health
@app.route('/')
def index():
    """Server health check."""
    return "Didi's Server Backend is Running! Ready for alerts at /api/alert"

# --- Day 5 Task: Implement Notification Logic (Didi's Alerting) ---

def send_notification(incident_details):
    """
    Simulates sending an external notification (e.g., Slack Webhook or Email) 
    for high-priority incidents.
    This function completes Didi's Day 5 task (Alerting).
    """
    severity = incident_details.get('severity')
    incident_type = incident_details.get('type')
    ip = incident_details.get('ip')
    
    # Construct the message payload
    message = f"""
    🔥🚨 NEW HIGH-PRIORITY INCIDENT DETECTED 🚨🔥
    Severity: {severity}
    Type: {incident_type}
    Source IP: {ip}
    Timestamp: {incident_details.get('timestamp')}
    Rule Triggered: {incident_details.get('rule')}
    ---
    Action Required: Review the Sentinel Dashboard immediately.
    """
    
    # In this simulation, we print the notification to the server console.
    print("-" * 50)
    print(f"NOTIFICATION SENT (Severity: {severity})")
    print(message)
    print("-" * 50)


@app.route('/api/alert', methods=['POST'])
def receive_alert():
    """
    Receives incident data via a POST request, validates it, and saves it
    to the SQLite database.
    """
    # 1. Input Validation: Check if the request body is valid JSON
    if not request.json:
        return jsonify({"message": "Error: Missing JSON body"}), 400

    incident_data = request.json
    
    # Check for required fields based on the agreed JSON structure
    required_fields = ["ip", "type", "severity", "timestamp"]
    if not all(field in incident_data for field in required_fields):
        print(f"Received incomplete data: {incident_data}")
        return jsonify({"message": "Error: Missing required incident fields (need ip, type, severity, timestamp)"}), 400

    # --- Day 9: Threat Intelligence Enrichment ---
    incident_data = enrich_incident_data(incident_data)
    if incident_data.get('threat_intel', {}).get('is_blacklisted'):
        print(f"⚠️  BLACKLISTED IP DETECTED: {incident_data.get('ip')}")

    # 2. Database Ingestion
    session = Session()
    try:
        # Convert the string timestamp (ISO 8601 format) into a Python datetime object
        timestamp_dt = datetime.fromisoformat(incident_data.get('timestamp'))
        
        # Create a new Incident object
        new_incident = Incident(
            ip=incident_data.get('ip'),
            type=incident_data.get('type'),
            severity=incident_data.get('severity'),
            timestamp=timestamp_dt,
            rule=incident_data.get('rule', f"{incident_data.get('type')} Incident Detected"),
            status="Active", 
            source_log=incident_data.get('source_log'),
            target=incident_data.get('target')
        )

        session.add(new_incident)
        session.commit()
        
        # --- Day 5 Alerting: Trigger notification after successful save ---
        severity_level = new_incident.severity
        if severity_level in ["High", "Critical"]:
            send_notification(incident_data)
        # -----------------------------------------------------------------

        print(f"New incident saved: {new_incident}")
        return jsonify({
            "message": "Incident received and saved successfully!",
            "incident_id": new_incident.id
        }), 201

    except Exception as e:
        session.rollback()
        print(f"Database ingestion error: {e}")
        # Return a 500 error for database issues
        return jsonify({"message": f"Internal server error during ingestion: {e}"}), 500
    finally:
        session.close()

# --- Day 7: Interactive Incident Management ---

@app.route('/api/incident/<int:incident_id>/resolve', methods=['POST'])
def resolve_incident(incident_id):
    """
    Day 7: Resolve or update the status of an incident.
    
    Expected JSON body:
    {
        "status": "Resolved" | "Closed" | "Active",
        "notes": "Optional resolution notes"
    }
    """
    session = Session()
    try:
        incident = session.query(Incident).filter(Incident.id == incident_id).first()
        
        if not incident:
            return jsonify({"message": f"Incident {incident_id} not found"}), 404
        
        # Get status from request body (default to "Resolved")
        data = request.json or {}
        new_status = data.get('status', 'Resolved')
        
        # Validate status
        valid_statuses = ['Active', 'Resolved', 'Closed', 'Containment']
        if new_status not in valid_statuses:
            return jsonify({
                "message": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            }), 400
        
        # Update incident status
        old_status = incident.status
        incident.status = new_status
        
        session.commit()
        
        print(f"Incident {incident_id} status updated: {old_status} -> {new_status}")
        
        return jsonify({
            "message": f"Incident {incident_id} status updated successfully",
            "incident_id": incident_id,
            "old_status": old_status,
            "new_status": new_status
        }), 200
        
    except Exception as e:
        session.rollback()
        print(f"Error resolving incident {incident_id}: {e}")
        return jsonify({"message": f"Internal server error: {e}"}), 500
    finally:
        session.close()

@app.route('/api/incident/<int:incident_id>', methods=['GET'])
def get_incident(incident_id):
    """Get details of a specific incident."""
    session = Session()
    try:
        incident = session.query(Incident).filter(Incident.id == incident_id).first()
        
        if not incident:
            return jsonify({"message": f"Incident {incident_id} not found"}), 404
        
        return jsonify({
            "id": incident.id,
            "ip": incident.ip,
            "type": incident.type,
            "severity": incident.severity,
            "timestamp": incident.timestamp.isoformat(),
            "rule": incident.rule,
            "status": incident.status,
            "source_log": incident.source_log,
            "target": incident.target
        }), 200
        
    except Exception as e:
        print(f"Error fetching incident {incident_id}: {e}")
        return jsonify({"message": f"Internal server error: {e}"}), 500
    finally:
        session.close()

# --- Day 10: System Status Monitoring ---

@app.route('/api/status', methods=['GET'])
def system_status():
    """
    Day 10: Get system status and health metrics.
    """
    session = Session()
    try:
        # Get database status
        try:
            session.execute(func.count(Incident.id))
            db_status = "healthy"
            db_error = None
        except Exception as e:
            db_status = "unhealthy"
            db_error = str(e)
        
        # Get incident statistics
        try:
            total_incidents = session.query(func.count(Incident.id)).scalar()
            active_incidents = session.query(func.count(Incident.id)).filter(
                Incident.status == 'Active'
            ).scalar()
            resolved_incidents = session.query(func.count(Incident.id)).filter(
                Incident.status == 'Resolved'
            ).scalar()
            
            # Get severity breakdown
            severity_counts = session.query(
                Incident.severity,
                func.count(Incident.id)
            ).group_by(Incident.severity).all()
            
            severity_breakdown = {severity: count for severity, count in severity_counts}
            
        except Exception as e:
            total_incidents = 0
            active_incidents = 0
            resolved_incidents = 0
            severity_breakdown = {}
        
        # Check blacklist file
        blacklist_status = "available" if os.path.exists(BLACKLIST_FILE) else "not_found"
        blacklist_ips = len(load_blacklist()) if blacklist_status == "available" else 0
        
        status = {
            "system": "operational",
            "timestamp": datetime.utcnow().isoformat(),
            "components": {
                "database": {
                    "status": db_status,
                    "error": db_error
                },
                "blacklist": {
                    "status": blacklist_status,
                    "ip_count": blacklist_ips
                }
            },
            "statistics": {
                "total_incidents": total_incidents,
                "active_incidents": active_incidents,
                "resolved_incidents": resolved_incidents,
                "severity_breakdown": severity_breakdown
            }
        }
        
        # Determine overall system status
        if db_status != "healthy":
            status["system"] = "degraded"
        
        return jsonify(status), 200
        
    except Exception as e:
        return jsonify({
            "system": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 500
    finally:
        session.close()

# Run the app
if __name__ == '__main__':
    print("Starting Flask API server on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)