# app.py (Updated for Day 3)
from flask import Flask, request, jsonify
from models import Incident, Session, engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# Initialize Flask project structure
app = Flask(__name__)

# Basic route for testing server
@app.route('/')
def index():
    return "Didi's Server Backend is Running!"

# --- Didi's Day 3 Task: Create API Endpoint ---
@app.route('/api/alert', methods=['POST'])
def receive_alert():
    # Check if the request body is valid JSON
    if not request.json:
        return jsonify({"message": "Error: Missing JSON body"}), 400

    incident_data = request.json
    
    # 1. Check for required fields based on the agreed JSON structure
    required_fields = ["ip", "type", "severity", "timestamp"]
    if not all(field in incident_data for field in required_fields):
        return jsonify({"message": "Error: Missing required incident fields"}), 400

    # 2. Ingest the data into the database (as per Day 3)
    try:
        # Create a new session
        session = Session()

        # We must convert the string timestamp into a Python datetime object
        # Note: Bayoumy's script should send a rule name, but for testing, we set one here.
        new_incident = Incident(
            ip=incident_data.get('ip'),
            type=incident_data.get('type'),
            severity=incident_data.get('severity'),
            timestamp=datetime.fromisoformat(incident_data.get('timestamp')),
            rule=incident_data.get('rule', f"{incident_data.get('type')} Detected"), # Use type if rule is missing
            status="Active" # Default status
        )

        session.add(new_incident)
        session.commit()
        
        # NOTE: Day 5 notification logic would be placed here after commit!

        return jsonify({
            "message": "Incident received and saved successfully!",
            "incident_id": new_incident.id
        }), 201

    except Exception as e:
        session.rollback()
        print(f"Database error: {e}")
        return jsonify({"message": f"Internal server error: {e}"}), 500

# Run the app
if __name__ == '__main__':
    # Ensure the database and table are created (models.py handles this)
    app.run(debug=True, port=5000)