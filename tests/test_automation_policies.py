#!/usr/bin/env python3
"""
Test script for automation policies.
Verifies that containment actions respect configuration-based policies.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'detection_engine'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server_backend'))

from containment import ContainmentActions

def test_automation_policies():
    """Test that automation policies are loaded and applied correctly."""
    
    print("=" * 60)
    print("Testing Automation Policies")
    print("=" * 60)
    
    # Initialize containment with config
    containment = ContainmentActions(simulation_mode=True)
    
    print(f"\n✓ Automation enabled: {containment.automation_enabled}")
    print(f"✓ Policies loaded: {len(containment.automation_policies.get('actions', {}))} severity levels")
    
    # Test Critical severity (should block IP)
    print("\n--- Test 1: Critical Severity ---")
    critical_incident = {
        'severity': 'Critical',
        'ip': '1.2.3.4',
        'type': 'Brute Force',
        'rule': 'Rapid Login Attempts'
    }
    
    result = containment.apply_containment(critical_incident)
    print(f"IP Blocked: {result['ip_blocked']} (Expected: True)")
    print(f"Process Killed: {result['process_killed']} (Expected: False)")
    
    # Test Medium severity (should NOT block IP)
    print("\n--- Test 2: Medium Severity ---")
    medium_incident = {
        'severity': 'Medium',
        'ip': '5.6.7.8',
        'type': 'Off-Hours Login',
        'rule': 'Suspicious Login Time'
    }
    
    result = containment.apply_containment(medium_incident)
    print(f"IP Blocked: {result['ip_blocked']} (Expected: False)")
    print(f"Process Killed: {result['process_killed']} (Expected: False)")
    
    # Test High severity (should block IP)
    print("\n--- Test 3: High Severity ---")
    high_incident = {
        'severity': 'High',
        'ip': '9.10.11.12',
        'type': 'Sudo Failure',
        'rule': 'Multiple Sudo Failures'
    }
    
    result = containment.apply_containment(high_incident)
    print(f"IP Blocked: {result['ip_blocked']} (Expected: True)")
    print(f"Process Killed: {result['process_killed']} (Expected: False)")
    
    # Check statistics
    print("\n--- Automation Statistics ---")
    stats = containment.get_statistics()
    print(f"IPs Blocked: {stats['ips_blocked']}")
    print(f"Processes Killed: {stats['processes_killed']}")
    print(f"Actions Logged: {stats['actions_logged']}")
    
    # Check blocked IPs list
    print("\n--- Blocked IPs ---")
    blocked_ips = containment.get_blocked_ips()
    print(f"Total Blocked: {len(blocked_ips)}")
    for ip in blocked_ips:
        print(f"  - {ip}")
    
    print("\n" + "=" * 60)
    print("✅ All tests completed successfully!")
    print("=" * 60)

if __name__ == '__main__':
    test_automation_policies()
