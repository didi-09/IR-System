# app.py (Didi's Server Backend - Day 5 Logic: Response & Notification)
from flask import Flask, request, jsonify
# NOTE: We assume 'models.py' exists and defines Incident, Session, and engine.
from models import Incident, Session, engine 
from datetime import datetime
import time 
import requests 

# --- Configuration for Webhook/Email (Placeholder values) ---
WEBHOOK_URL = "https://your.slack.webhook.url/..."
EMAIL_SENDER = "didi.alerts@sentinel.com"
EMAIL_RECEIVER = "security_team@corp.com"
# -----------------------------------------------------------

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

# Run the app
if __name__ == '__main__':
    print("Starting Flask API server on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)