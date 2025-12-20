# test_detection.py
"""
Test script for the detection engine.
Creates sample log events and tests detection rules.
"""
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detection_rules import BruteForceRule, RapidLoginAttemptsRule, DetectionEngine

def create_test_events():
    """Create test events simulating failed login attempts."""
    base_time = datetime.now()
    events = []
    
    # Simulate 5 failed logins from same IP within 60 seconds
    ip = "192.168.1.100"
    target = "admin"
    
    for i in range(5):
        events.append({
            'timestamp': base_time + timedelta(seconds=i * 10),
            'ip': ip,
            'target': target,
            'type': 'failed_login',
            'port': '22',
            'pid': str(1000 + i)
        })
    
    # Simulate 12 rapid attempts from different IP (should trigger rapid rule)
    ip2 = "10.0.0.50"
    for i in range(12):
        events.append({
            'timestamp': base_time + timedelta(seconds=100 + i * 2),
            'ip': ip2,
            'target': 'root',
            'type': 'failed_login',
            'port': '22',
            'pid': str(2000 + i)
        })
    
    return events

def test_detection_rules():
    """Test the detection rules."""
    print("=" * 60)
    print("Testing Detection Rules")
    print("=" * 60)
    
    # Create test events
    events = create_test_events()
    print(f"\nCreated {len(events)} test events")
    
    # Test brute force rule
    print("\n1. Testing BruteForceRule (3 failed logins in 60 seconds)...")
    brute_force_rule = BruteForceRule(threshold=3, time_window_seconds=60)
    incident = brute_force_rule.check(events)
    
    if incident:
        print("✅ Brute force detected!")
        print(f"   IP: {incident['ip']}")
        print(f"   Attempts: {incident['attempt_count']}")
        print(f"   Severity: {incident['severity']}")
    else:
        print("❌ No brute force detected")
    
    # Test rapid login rule
    print("\n2. Testing RapidLoginAttemptsRule (10 attempts in 30 seconds)...")
    rapid_rule = RapidLoginAttemptsRule(threshold=10, time_window_seconds=30)
    incident = rapid_rule.check(events)
    
    if incident:
        print("✅ Rapid login attempts detected!")
        print(f"   IP: {incident['ip']}")
        print(f"   Attempts: {incident['attempt_count']}")
        print(f"   Severity: {incident['severity']}")
    else:
        print("❌ No rapid attempts detected")
    
    # Test full detection engine
    print("\n3. Testing DetectionEngine (all rules)...")
    engine = DetectionEngine()
    incidents = engine.detect_incidents(events)
    
    print(f"✅ Detected {len(incidents)} incident(s):")
    for i, incident in enumerate(incidents, 1):
        print(f"\n   Incident {i}:")
        print(f"   - Type: {incident['type']}")
        print(f"   - IP: {incident['ip']}")
        print(f"   - Severity: {incident['severity']}")
        print(f"   - Rule: {incident['rule']}")
        print(f"   - Attempts: {incident.get('attempt_count', 'N/A')}")
    
    print("\n" + "=" * 60)
    print("Test Complete")
    print("=" * 60)

if __name__ == '__main__':
    test_detection_rules()

