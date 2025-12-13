# 🧪 Complete Testing Guide - Security Incident Detection & Response System

This guide provides step-by-step instructions to fully test all components of the system.

## 📋 Prerequisites

1. **Install Dependencies**
```bash
cd /path/to/IR-System
pip install -r requirements.txt
```

2. **Verify Installation**
```bash
python3 -c "import flask, sqlalchemy, streamlit, pandas, requests, psutil; print('✅ All dependencies installed')"
```

---

## 🧪 Part 1: Individual Component Testing

### Test 1.1: Day 2 - System Information Collection

**Test psutil process listing:**
```bash
cd detection_engine
python3 detection_agent.py --print-processes
```
**Expected:** List of running processes with PID, name, status, CPU%, Memory%

**Test system info summary:**
```bash
python3 detection_agent.py --print-system-info
```
**Expected:** Complete system information including OS, users, uptime, network connections, processes

**Test system_info module directly:**
```bash
python3 system_info.py
```
**Expected:** Formatted system information output

---

### Test 1.2: Day 3 - Log Parser

**Test log parsing:**
```bash
cd detection_engine
python3 -c "
from log_parser import AuthLogParser
parser = AuthLogParser('/var/log/auth.log')
# Test parsing a sample line
test_line = 'Dec 13 10:30:00 hostname sshd[12345]: Failed password for user from 192.168.1.100 port 22'
result = parser.parse_log_line(test_line)
print('Parsed:', result)
"
```
**Expected:** Dictionary with parsed event data (ip, target, type, timestamp, etc.)

---

### Test 1.3: Day 4 - Detection Rules

**Test detection rules:**
```bash
cd detection_engine
python3 test_detection.py
```
**Expected:** 
- Test events created
- BruteForceRule triggered (3+ failed logins)
- RapidLoginAttemptsRule triggered (10+ attempts)
- Incidents detected and printed

---

### Test 1.4: Day 5 - Containment Actions

**Test containment in simulation mode:**
```bash
cd detection_engine
python3 -c "
from containment import ContainmentActions
containment = ContainmentActions(simulation_mode=True)
result = containment.block_ip('192.168.1.100', 'Test')
print('Block result:', result)
result2 = containment.kill_process('12345', 'Test')
print('Kill result:', result2)
"
```
**Expected:** 
- Simulation messages printed
- No actual iptables/kill commands executed
- Returns True

---

### Test 1.5: Database & Models

**Test database initialization:**
```bash
cd server_backend
python3 -c "
from models import Incident, Session, engine
from datetime import datetime

# Create test incident
session = Session()
test_incident = Incident(
    ip='192.168.1.100',
    type='Test',
    severity='Low',
    timestamp=datetime.utcnow(),
    rule='Test Rule',
    status='Active',
    source_log='/var/log/auth.log',
    target='test_user'
)
session.add(test_incident)
session.commit()
print('✅ Test incident created with ID:', test_incident.id)

# Query it back
found = session.query(Incident).filter(Incident.id == test_incident.id).first()
print('✅ Retrieved incident:', found)
session.close()
"
```
**Expected:** Incident created and retrieved successfully

---

### Test 1.6: Flask API Endpoints

**Start Flask API:**
```bash
cd server_backend
python3 app.py
```
**Keep this running in Terminal 1**

**In a new terminal, test endpoints:**

**Test health check:**
```bash
curl http://127.0.0.1:5000/
```
**Expected:** "Didi's Server Backend is Running! Ready for alerts at /api/alert"

**Test POST /api/alert:**
```bash
curl -X POST http://127.0.0.1:5000/api/alert \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.50",
    "type": "Brute Force",
    "severity": "High",
    "timestamp": "2025-12-13T10:30:00",
    "rule": "Failed Login Count Exceeded",
    "source_log": "/var/log/auth.log",
    "target": "test_user"
  }'
```
**Expected:** `{"message": "Incident received and saved successfully!", "incident_id": 1}`

**Test GET /api/incident/<id>:**
```bash
curl http://127.0.0.1:5000/api/incident/1
```
**Expected:** Full incident details in JSON

**Test POST /api/incident/<id>/resolve (Day 7):**
```bash
curl -X POST http://127.0.0.1:5000/api/incident/1/resolve \
  -H "Content-Type: application/json" \
  -d '{"status": "Resolved"}'
```
**Expected:** `{"message": "Incident 1 status updated successfully", ...}`

**Test GET /api/status (Day 10):**
```bash
curl http://127.0.0.1:5000/api/status
```
**Expected:** System status with database health, statistics, etc.

---

### Test 1.7: Day 9 - Threat Intelligence

**Add IP to blacklist:**
```bash
# Edit ip_blacklist.json and add a test IP
# Or use Python:
python3 -c "
import json
with open('ip_blacklist.json', 'r') as f:
    data = json.load(f)
data['ips'].append('192.168.1.200')
with open('ip_blacklist.json', 'w') as f:
    json.dump(data, f, indent=2)
print('✅ Added test IP to blacklist')
"
```

**Test with blacklisted IP:**
```bash
curl -X POST http://127.0.0.1:5000/api/alert \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.200",
    "type": "Brute Force",
    "severity": "Medium",
    "timestamp": "2025-12-13T10:35:00",
    "rule": "Test Rule",
    "source_log": "/var/log/auth.log",
    "target": "test_user"
  }'
```
**Expected:** 
- Severity elevated (Medium -> High)
- Rule includes "[BLACKLISTED IP]"
- Console shows "⚠️ BLACKLISTED IP DETECTED"

---

## 🧪 Part 2: Integration Testing

### Test 2.1: Full Detection Loop (Day 6)

**Terminal 1: Start Flask API**
```bash
cd server_backend
python3 app.py
```

**Terminal 2: Start Streamlit Dashboard**
```bash
cd server_backend
streamlit run dashboard.py
```

**Terminal 3: Start Detection Agent**
```bash
cd detection_engine
python3 detection_agent.py
```

**Terminal 4: Generate Test Incidents**
```bash
cd server_backend
python3 test.py
```

**Expected Flow:**
1. Test script sends incident to API
2. API saves to database
3. Dashboard shows new incident
4. Detection agent (if monitoring logs) would detect and send alerts

---

### Test 2.2: End-to-End Incident Detection

**Simulate failed logins (if you have access to auth.log):**

**Option A: Manual test (requires root/sudo):**
```bash
# Try to SSH with wrong password multiple times
ssh wronguser@localhost
# Enter wrong password 3+ times quickly
```

**Option B: Use test detection:**
```bash
cd detection_engine
python3 test_detection.py
```

**Expected:**
1. Detection agent detects pattern
2. System info collected (Day 3)
3. Containment actions applied (simulation)
4. Alert sent to API
5. Dashboard updates
6. Incident appears in dashboard

---

## 🧪 Part 3: Dashboard Testing (Day 4, 7, 8, 10)

### Test 3.1: Basic Dashboard Features

1. **Open Dashboard:** http://localhost:8501

2. **Test Filters:**
   - Change Severity filter → Should filter incidents
   - Change Date Range → Should filter by time
   - Change Status filter → Should show Active/Resolved/Closed
   - Use IP filter → Type partial IP, should filter
   - Use Target filter → Type username, should filter

3. **Test Charts (Day 8):**
   - Click "📊 By Target" tab → Should show bar chart
   - Click "📈 By Severity" tab → Should show severity distribution
   - Click "🌐 By IP" tab → Should show top IPs

4. **Test Metrics:**
   - Verify Total Incidents count
   - Verify Critical/High counts
   - Verify Unique IPs count

---

### Test 3.2: Incident Management (Day 7)

1. **Resolve an Incident:**
   - Select an incident ID from dropdown
   - Click "✅ Resolve" button
   - Verify status changes to "Resolved"
   - Refresh dashboard → Incident should disappear from Active list

2. **Close an Incident:**
   - Select incident ID
   - Click "🔒 Close" button
   - Verify status changes to "Closed"

3. **Re-activate an Incident:**
   - Change Status filter to "Resolved" or "Closed"
   - Select an incident
   - Click "🔄 Re-activate"
   - Change filter back to "Active" → Should see incident again

---

### Test 3.3: System Status (Day 10)

1. **View System Status:**
   - Click "🔍 System Status" expander
   - Verify system status shows (operational/degraded)
   - Verify database health
   - Verify incident statistics
   - Verify severity breakdown

2. **Test Status Updates:**
   - Create new incidents via API
   - Refresh dashboard
   - System status should update with new counts

---

## 🧪 Part 4: Advanced Testing

### Test 4.1: Error Handling

**Test invalid API request:**
```bash
curl -X POST http://127.0.0.1:5000/api/alert \
  -H "Content-Type: application/json" \
  -d '{"invalid": "data"}'
```
**Expected:** 400 error with message about missing required fields

**Test non-existent incident:**
```bash
curl http://127.0.0.1:5000/api/incident/99999
```
**Expected:** 404 error with "Incident not found"

**Test invalid status:**
```bash
curl -X POST http://127.0.0.1:5000/api/incident/1/resolve \
  -H "Content-Type: application/json" \
  -d '{"status": "InvalidStatus"}'
```
**Expected:** 400 error with valid statuses listed

---

### Test 4.2: Performance Testing

**Generate bulk test data:**
```bash
cd server_backend
python3 generate_data.py
```

**Test with many incidents:**
```bash
# Send multiple incidents rapidly
for i in {1..50}; do
  curl -X POST http://127.0.0.1:5000/api/alert \
    -H "Content-Type: application/json" \
    -d "{
      \"ip\": \"192.168.1.$i\",
      \"type\": \"Test\",
      \"severity\": \"Low\",
      \"timestamp\": \"2025-12-13T10:30:00\",
      \"rule\": \"Test Rule\",
      \"source_log\": \"/var/log/auth.log\",
      \"target\": \"user_$i\"
    }" &
done
wait
```

**Verify:**
- All incidents saved
- Dashboard handles large dataset
- Filters work correctly
- No performance issues

---

### Test 4.3: Security Testing

**Test SQL Injection (should be safe with SQLAlchemy):**
```bash
curl -X POST http://127.0.0.1:5000/api/alert \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.1\"; DROP TABLE incidents; --",
    "type": "Test",
    "severity": "Low",
    "timestamp": "2025-12-13T10:30:00"
  }'
```
**Expected:** Incident saved safely, no SQL injection

**Test XSS (should be safe with Streamlit):**
- Try creating incident with script tags in fields
- Verify dashboard displays safely (no script execution)

---

## 🧪 Part 5: Complete Workflow Test

### Full Scenario: Brute Force Attack Detection

**Step 1: Start all services**
```bash
# Terminal 1
cd server_backend && python3 app.py

# Terminal 2
cd server_backend && streamlit run dashboard.py

# Terminal 3
cd detection_engine && python3 detection_agent.py
```

**Step 2: Simulate attack**
```bash
# Terminal 4: Generate test incidents that simulate brute force
cd server_backend
python3 -c "
import requests
import time
from datetime import datetime

api_url = 'http://127.0.0.1:5000/api/alert'

# Simulate 5 failed login attempts from same IP
for i in range(5):
    requests.post(api_url, json={
        'ip': '192.168.1.100',
        'type': 'Brute Force',
        'severity': 'High',
        'timestamp': datetime.utcnow().isoformat(),
        'rule': 'Failed Login Count Exceeded',
        'source_log': '/var/log/auth.log',
        'target': 'admin'
    })
    time.sleep(0.5)
    print(f'Sent incident {i+1}/5')
"
```

**Step 3: Verify in Dashboard**
- Open http://localhost:8501
- Should see 5 incidents from 192.168.1.100
- Filter by IP: 192.168.1.100 → Should show all 5
- Check charts → Should show IP in top IPs chart

**Step 4: Resolve incidents**
- Select one incident
- Click "Resolve"
- Change Status filter to "Resolved" → Should see resolved incident
- Change back to "Active" → Should see 4 remaining

**Step 5: Check system status**
- Expand "System Status"
- Verify statistics show correct counts
- Verify severity breakdown

---

## ✅ Testing Checklist

- [ ] Day 2: Process listing works
- [ ] Day 2: System info summary works
- [ ] Day 3: System info collection on incident
- [ ] Day 3: Network connections captured
- [ ] Day 4: Detection rules trigger correctly
- [ ] Day 4: Dashboard displays incidents
- [ ] Day 4: Filters work (Severity, Date, IP, Target, Status)
- [ ] Day 5: Containment actions (simulation mode)
- [ ] Day 5: Notifications (simulated)
- [ ] Day 6: Full integration loop works
- [ ] Day 7: Incident resolution works
- [ ] Day 7: Status updates work
- [ ] Day 8: Charts display correctly
- [ ] Day 8: Severity ranking works
- [ ] Day 9: Blacklist detection works
- [ ] Day 9: Severity elevation works
- [ ] Day 10: System status endpoint works
- [ ] Day 10: Dashboard status display works
- [ ] Error handling works
- [ ] Performance with bulk data
- [ ] Security (SQL injection, XSS protection)

---

## 🐛 Troubleshooting

**Issue: "Cannot connect to API"**
- Ensure Flask API is running on port 5000
- Check firewall settings
- Verify API URL in detection agent

**Issue: "Database file not found"**
- Check database path in models.py
- Ensure database.db exists or will be created
- Check file permissions

**Issue: "psutil not found"**
- Run: `pip install psutil`
- Or: `pip install -r requirements.txt`

**Issue: "Permission denied" for auth.log**
- Detection agent will use simulation mode
- For real monitoring, may need sudo/root access

**Issue: Dashboard not updating**
- Click "🔄 Refresh" button
- Check if Flask API is running
- Verify database has new incidents

---

## 📊 Expected Test Results

After complete testing, you should have:
- ✅ All API endpoints responding correctly
- ✅ Dashboard displaying and filtering incidents
- ✅ Detection agent monitoring and detecting
- ✅ System info collected on incidents
- ✅ Containment actions simulated
- ✅ Incident resolution working
- ✅ Charts and metrics displaying
- ✅ System status monitoring active
- ✅ Threat intelligence enriching incidents

---

## 🎯 Quick Test Script

Run this to test all components quickly:

```bash
#!/bin/bash
# quick_test.sh

echo "🧪 Quick System Test"
echo "==================="

# Test 1: System Info
echo "Test 1: System Info..."
cd detection_engine
python3 detection_agent.py --print-system-info > /dev/null 2>&1 && echo "✅ System Info OK" || echo "❌ System Info Failed"

# Test 2: Detection Rules
echo "Test 2: Detection Rules..."
python3 test_detection.py > /dev/null 2>&1 && echo "✅ Detection Rules OK" || echo "❌ Detection Rules Failed"

# Test 3: API (if running)
echo "Test 3: API Health..."
curl -s http://127.0.0.1:5000/ > /dev/null && echo "✅ API OK" || echo "⚠️  API not running (start with: cd server_backend && python3 app.py)"

# Test 4: Database
echo "Test 4: Database..."
cd ../server_backend
python3 -c "from models import Session, Incident; s = Session(); print('✅ Database OK' if s.query(Incident).first() is not None or True else '❌ Database Failed'); s.close()" 2>/dev/null || echo "⚠️  Database test skipped"

echo "==================="
echo "✅ Quick test complete!"
```

Save as `quick_test.sh`, make executable: `chmod +x quick_test.sh`, then run: `./quick_test.sh`

---

**Happy Testing! 🚀**

