#!/usr/bin/env python3
"""
Realistic Security Event Generator
Simulates various attack scenarios to test the IR system with realistic data.
"""

import subprocess
import time
import random
from datetime import datetime

# Realistic attacker IPs (known malicious ranges)
ATTACKER_IPS = [
    "185.220.101.45",   # Tor exit node
    "203.0.113.50",     # TEST-NET-3
    "45.142.120.50",    # Known scanner
    "192.168.1.100",    # Internal attacker
    "89.248.174.20",    # Suspicious IP
]

# Common usernames attackers try
ATTACK_USERNAMES = [
    "root", "admin", "administrator", "user", "test", "oracle", 
    "postgres", "mysql", "ubuntu", "centos", "pi", "www-data"
]

# Realistic web attack vectors
SQL_INJECTION_ATTEMPTS = [
    "/login?username=admin' OR '1'='1",
    "/search?q=1' UNION SELECT null,username,password FROM users--",
    "/product?id=1; DROP TABLE users--",
    "/api/data?filter=' AND 1=1--",
]

XSS_ATTEMPTS = [
    "/comment?text=<script>alert(document.cookie)</script>",
    "/search?q=<img src=x onerror=alert(1)>",
    "/profile?name=<svg/onload=alert('XSS')>",
    "/forum?post=<iframe src=javascript:alert(1)>",
]

def send_syslog_event(tag, message):
    """Send event to syslog via logger."""
    subprocess.run(['logger', '-t', tag, message], capture_output=True)

def simulate_brute_force_attack(ip, username, attempts=5):
    """Simulate SSH brute force attack."""
    print(f"\n🔴 Simulating brute force attack...")
    print(f"   Attacker: {ip}")
    print(f"   Target user: {username}")
    print(f"   Attempts: {attempts}")
    
    for i in range(attempts):
        send_syslog_event('sshd', f'Failed password for {username} from {ip} port {random.randint(40000, 65000)} ssh2')
        print(f"   [{i+1}/{attempts}] Failed login attempt")
        time.sleep(0.5)
    
    print(f"   ✓ Brute force simulation complete")
    return attempts

def simulate_user_enumeration(ip, count=8):
    """Simulate user enumeration attack."""
    print(f"\n🔴 Simulating user enumeration...")
    print(f"   Attacker: {ip}")
    print(f"   Testing {count} usernames")
    
    for i in range(count):
        user = random.choice(ATTACK_USERNAMES)
        send_syslog_event('sshd', f'Invalid user {user} from {ip} port {random.randint(40000, 65000)}')
        print(f"   [{i+1}/{count}] Testing user: {user}")
        time.sleep(0.3)
    
    print(f"   ✓ User enumeration complete")
    return count

def simulate_sudo_attack(ip, username="attacker", attempts=4):
    """Simulate sudo privilege escalation attempts."""
    print(f"\n🔴 Simulating sudo privilege escalation...")
    print(f"   Attacker: {username}@{ip}")
    print(f"   Attempts: {attempts}")
    
    for i in range(attempts):
        send_syslog_event('sudo', f'pam_unix(sudo:auth): authentication failure; user={username} from {ip}')
        print(f"   [{i+1}/{attempts}] Sudo authentication failure")
        time.sleep(0.4)
    
    print(f"   ✓ Sudo attack simulation complete")
    return attempts

def simulate_web_attacks(attacker_ip):
    """Simulate web-based attacks (SQLi, XSS)."""
    print(f"\n🔴 Simulating web attacks...")
    print(f"   Attacker: {attacker_ip}")
    
    # Write to Apache access log (if accessible)
    apache_log = "/var/log/apache2/access.log"
    
    total_attacks = 0
    
    # SQL Injection attempts
    print(f"   Generating SQL injection attempts...")
    for uri in SQL_INJECTION_ATTEMPTS[:3]:
        log_entry = f'{attacker_ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET {uri} HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Attack Scanner)"\n'
        try:
            with open(apache_log, 'a') as f:
                f.write(log_entry)
            print(f"   ✓ SQLi: {uri[:50]}...")
            total_attacks += 1
            time.sleep(0.3)
        except PermissionError:
            print(f"   ⚠️  Cannot write to {apache_log} (need sudo)")
            break
    
    # XSS attempts
    print(f"   Generating XSS attempts...")
    for uri in XSS_ATTEMPTS[:2]:
        log_entry = f'{attacker_ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET {uri} HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Attack Scanner)"\n'
        try:
            with open(apache_log, 'a') as f:
                f.write(log_entry)
            print(f"   ✓ XSS: {uri[:50]}...")
            total_attacks += 1
            time.sleep(0.3)
        except PermissionError:
            break
    
    if total_attacks > 0:
        print(f"   ✓ Web attack simulation complete ({total_attacks} requests)")
    else:
        print(f"   ℹ️  Skipped (no write access to Apache logs)")
    
    return total_attacks

def simulate_combined_attack_scenario():
    """Simulate a realistic multi-stage attack scenario."""
    print("=" * 70)
    print("🎯 REALISTIC ATTACK SCENARIO SIMULATION")
    print("=" * 70)
    print("\nThis simulates a multi-stage attack that should trigger multiple")
    print("detection rules in your IR system.")
    print()
    
    # Choose random attacker
    attacker_ip = random.choice(ATTACKER_IPS)
    target_user = "root"
    
    print(f"\n📍 Attack Source: {attacker_ip}")
    print(f"📍 Primary Target: {target_user}")
    print()
    input("Press ENTER to start attack simulation...")
    
    total_events = 0
    
    # Stage 1: User enumeration
    print("\n" + "=" * 70)
    print("STAGE 1: RECONNAISSANCE")
    print("=" * 70)
    events = simulate_user_enumeration(attacker_ip, count=6)
    total_events += events
    time.sleep(2)
    
    # Stage 2: Brute force attack
    print("\n" + "=" * 70)
    print("STAGE 2: BRUTE FORCE ATTACK")
    print("=" * 70)
    events = simulate_brute_force_attack(attacker_ip, target_user, attempts=5)
    total_events += events
    time.sleep(2)
    
    # Stage 3: Sudo privilege escalation
    print("\n" + "=" * 70)
    print("STAGE 3: PRIVILEGE ESCALATION")
    print("=" * 70)
    events = simulate_sudo_attack(attacker_ip, username="www-data", attempts=4)
    total_events += events
    time.sleep(2)
    
    # Stage 4: Web attacks (requires sudo)
    print("\n" + "=" * 70)
    print("STAGE 4: WEB APPLICATION ATTACKS")
    print("=" * 70)
    events = simulate_web_attacks(attacker_ip)
    total_events += events
    
    print("\n" + "=" * 70)
    print("✅ ATTACK SIMULATION COMPLETE")
    print("=" * 70)
    print(f"\nTotal events generated: {total_events}")
    print(f"Attacker IP: {attacker_ip}")
    print()
    print("Expected detections in your IR system:")
    print("  🚨 User Enumeration (Medium)")
    print("  🚨 Brute Force Attack (High)")
    print("  🚨 Multiple Sudo Failures (High)")
    print("  🚨 Rapid Login Attempts (Critical)")
    if events > 0:
        print("  🚨 SQL Injection Attempt (Critical)")
        print("  🚨 XSS Attempt (High)")
    print()
    print("Wait 10-15 seconds, then check:")
    print("  1. Detection agent terminal for incident alerts")
    print("  2. Dashboard: http://localhost:8501")
    print(f"  3. API: curl http://127.0.0.1:5000/api/incidents | jq '.[] | select(.ip==\"{attacker_ip}\")'")
    print("=" * 70)

if __name__ == "__main__":
    simulate_combined_attack_scenario()
