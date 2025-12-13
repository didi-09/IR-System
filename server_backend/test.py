import requests
import json
from datetime import datetime
import random

# --- Configuration ---
# Your Flask server should be running on this address
API_URL = "http://127.0.0.1:5000/api/alert"
# ---------------------

def generate_sample_incident():
    """Generates a single, randomized incident dictionary matching the agreed-upon JSON structure."""
    
    # Define realistic possible values
    incident_types = [
        "Brute Force",
        "SQL Injection Attempt",
        "DDoS Attack",
        "Unauthorized Access",
        "Suspicious File Change"
    ]

    severity_levels = ["Low", "Medium", "High", "Critical"]
    
    # Generate a recent timestamp in ISO 8601 format
    timestamp = datetime.now().isoformat()
    
    # Mock data
    return {
        "ip": f"192.168.1.{random.randint(10, 99)}",
        "type": random.choice(incident_types),
        "severity": random.choice(severity_levels),
        "timestamp": timestamp,
        "source_log": random.choice(["/var/log/auth.log", "/var/log/syslog"]),
        "target": random.choice(["admin_user", "db_service", "web_server_01"]),
        "rule": f"Rule {random.randint(100, 999)} Activated"
    }

def send_test_alert(incident_payload):
    """Sends a POST request with the incident data to the Flask API."""
    print(f"Sending alert to {API_URL}...")
    print(f"Payload: {json.dumps(incident_payload, indent=4)}")
    
    try:
        response = requests.post(
            API_URL, 
            json=incident_payload,
            headers={'Content-Type': 'application/json'}
        )
        
        # Print the API response
        print("-" * 30)
        print(f"Server Status Code: {response.status_code}")
        print(f"Server Response: {response.json()}")
        print("-" * 30)
        
        if response.status_code == 201:
            print("✅ SUCCESS: Incident successfully ingested by Didi's API.")
        else:
            print("❌ FAILURE: Alert failed to save. Check Flask server console for errors.")

    except requests.exceptions.ConnectionError:
        print("🔴 ERROR: Could not connect to the API server.")
        print("Ensure 'python app.py' is running in a separate terminal.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    # Generate a fresh incident for testing
    test_incident = generate_sample_incident()
    
    # Send it to the server
    send_test_alert(test_incident)