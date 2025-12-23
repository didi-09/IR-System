#!/bin/bash
# generate_realtime_events.sh - Generate events for RUNNING detection agent

echo "================================================================"
echo "GENERATING REAL-TIME EVENTS FOR DETECTION AGENT"
echo "================================================================"
echo ""
echo "Make sure the detection agent is ALREADY RUNNING in another terminal!"
echo ""
read -p "Press ENTER to start generating events, or Ctrl+C to cancel..."

echo""
echo "Generating events in 3... 2... 1..."
sleep 3

echo ""
echo "[1/5] Generating brute force attack (3 failed logins)..."
logger -t sshd "Failed password for hacker from 203.0.113.50 port 22 ssh2"
sleep 0.5
logger -t sshd "Failed password for hacker from 203.0.113.50 port 22 ssh2"
sleep 0.5
logger -t sshd "Failed password for hacker from 203.0.113.50 port 22 ssh2"
echo "       ✓ Sent 3 failed login attempts from 203.0.113.50"
echo "       → Should trigger: Brute Force (High severity)"

sleep 2

echo ""
echo "[2/5] Generating sudo failures..."
logger -t sudo "pam_unix(sudo:auth): authentication failure; user=attacker from 192.168.100.50"
sleep 0.5
logger -t sudo "pam_unix(sudo:auth): authentication failure; user=attacker from 192.168.100.50"
sleep 0.5
logger -t sudo "pam_unix(sudo:auth): authentication failure; user=attacker from 192.168.100.50"
echo "       ✓ Sent 3 sudo failures from 192.168.100.50"
echo "       → Should trigger: Multiple Sudo Failures (High severity)"

sleep 2

echo ""
echo "[3/5] Generating invalid user attempts..."
logger -t sshd "Invalid user admin from 10.20.30.40 port 22"
sleep 0.3
logger -t sshd "Invalid user root from 10.20.30.40 port 22"
sleep 0.3
logger -t sshd "Invalid user test from 10.20.30.40 port 22"
sleep 0.3
logger -t sshd "Invalid user oracle from 10.20.30.40 port 22"
sleep 0.3
logger -t sshd "Invalid user postgres from 10.20.30.40 port 22"
sleep 0.3
logger -t sshd "Invalid user mysql from 10.20.30.40 port 22"
echo "       ✓ Sent 6 invalid user attempts from 10.20.30.40"
echo "       → Should trigger: User Enumeration (Medium severity)"

sleep 2

echo ""
echo "[4/5] Generating rapid login attempts (critical)..."
for i in {1..10}; do
    logger -t sshd "Failed password for victim from 198.51.100.99 port 22 ssh2"
    sleep 0.1
done
echo "       ✓ Sent 10 rapid failed logins from 198.51.100.99"
echo "       → Should trigger: Rapid Login Attempts (Critical severity)"

sleep 2

echo ""
echo "[5/5] Testing web server logs (if Apache is running)..."
if systemctl is-active --quiet apache2; then
    curl -s http://localhost/ > /dev/null 2>&1
    curl -s "http://localhost/search?id=1' OR '1'='1" > /dev/null 2>&1
    curl -s "http://localhost/comment?text=<script>alert(1)</script>" > /dev/null 2>&1
    echo "       ✓ Generated web requests (normal, SQLi, XSS)"
else
    echo "       ⚠ Apache not running, skipping web tests"
fi

echo ""
echo "================================================================"
echo "✅ EVENT GENERATION COMPLETE"
echo "================================================================"
echo ""
echo "Check your detection agent terminal for detected incidents!"
echo ""
echo "Expected detections:"
echo "  1. Brute Force from 203.0.113.50 (High)"
echo "  2. Multiple Sudo Failures from 192.168.100.50 (High)"
echo "  3. User Enumeration from 10.20.30.40 (Medium)"
echo "  4. Rapid Login Attempts from 198.51.100.99 (Critical)"
echo "  5. SQL Injection + XSS from web logs (if Apache running)"
echo ""
echo "To verify events reached journald:"
echo "  journalctl -t sshd -t sudo --since '1 minute ago' --no-pager"
echo ""
echo "To check Flask API incidents:"
echo "  curl http://127.0.0.1:5000/api/incidents | jq"
echo ""
echo "================================================================"
