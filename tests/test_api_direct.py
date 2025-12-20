#!/usr/bin/env python3
"""
Test script to verify the detection agent is working correctly.
Sends a test incident directly to the API.
"""
import requests
import json
from datetime import datetime

API_URL = "http://127.0.0.1:5000/api/alert"

# Create a test incident
test_incident = {
    "ip": "88.88.88.88",
    "type": "Brute Force",
    "severity": "High",
    "timestamp": datetime.utcnow().isoformat(),
    "rule": "Manual Test - Failed Login Count Exceeded",
    "source_log": "/var/log/auth.log",
    "target": "test_user",
    "status": "Active"
}

print("🧪 Sending test incident to API...")
print(f"   IP: {test_incident['ip']}")
print(f"   Type: {test_incident['type']}")
print(f"   Severity: {test_incident['severity']}")

try:
    response = requests.post(
        API_URL,
        json=test_incident,
        headers={'Content-Type': 'application/json'},
        timeout=5
    )
    
    if response.status_code == 201:
        result = response.json()
        print(f"\n✅ SUCCESS! Incident created with ID: {result.get('incident_id')}")
        print(f"\n📊 Check the dashboard - you should see incident from IP {test_incident['ip']}")
    else:
        print(f"\n❌ FAILED: {response.status_code}")
        print(f"   Response: {response.text}")
        
except requests.exceptions.ConnectionError:
    print("\n❌ ERROR: Cannot connect to API at http://127.0.0.1:5000")
    print("   Make sure the Flask backend is running!")
except Exception as e:
    print(f"\n❌ ERROR: {e}")
