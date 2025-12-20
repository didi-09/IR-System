# Two-VM Deployment Guide

## 🎯 Overview

Deploy the IR System across two Kali Linux VMs for realistic attack simulation and testing.

**Setup:**
- **VM1 (Defender)**: 192.168.100.20 - Runs IR System
- **VM2 (Attacker)**: 192.168.100.10 - Simulates attacks
- **Host (Laptop)**: Access dashboard and monitor

---

## 📋 Prerequisites

### Both VMs:
- Kali Linux (or Debian-based)
- Python 3.8+
- Network connectivity between VMs
- Static IP addresses configured

### VM2 (Attacker) Additional:
- `sshpass` (for SSH attacks)
- `nmap` (for port scanning)
- `hydra` (optional, for advanced brute force)

---

## 🚀 Quick Start

### On VM1 (Defender - 192.168.100.20):

```bash
# 1. Copy IR-Project to VM1
cd /home/kali/IR-Project/IR-System

# 2. Run deployment script
./deploy_vm1_defender.sh

# 3. Start all services
./start_vm1_services.sh

# 4. Verify services are running
ps aux | grep -E '(app.py|detection_agent|streamlit)' | grep -v grep
```

**Expected Output:**
```
✅ Flask API running on 0.0.0.0:5000
✅ Detection Agent running (real mode)
✅ Dashboard running on 0.0.0.0:8501
```

### On VM2 (Attacker - 192.168.100.10):

```bash
# 1. Copy attack simulator to VM2
scp /home/kali/IR-Project/IR-System/vm2_attack_simulator.py kali@192.168.100.10:~/

# 2. Install required tools
sudo apt update
sudo apt install sshpass nmap hydra -y

# 3. Run attack simulator
python3 vm2_attack_simulator.py
```

### From Host (Your Laptop):

```bash
# Access dashboard in browser
http://192.168.100.20:8501
```

---

## 📖 Detailed Setup

### Step 1: VM1 (Defender) Setup

#### 1.1 Configure Network

```bash
# Verify IP address
ip addr show

# Should show: 192.168.100.20
```

#### 1.2 Deploy IR System

```bash
cd /home/kali/IR-Project/IR-System
./deploy_vm1_defender.sh
```

**What this script does:**
- ✅ Configures Flask API to listen on 0.0.0.0
- ✅ Opens firewall ports (5000, 8501, 22)
- ✅ Updates whitelist to include attacker IP
- ✅ Installs dependencies
- ✅ Initializes database
- ✅ Creates startup script

#### 1.3 Start Services

```bash
./start_vm1_services.sh
```

**Services started:**
- Flask API: http://192.168.100.20:5000
- Dashboard: http://192.168.100.20:8501
- Detection Agent: Monitoring system logs

#### 1.4 Verify Deployment

```bash
# Check services
ps aux | grep -E '(app.py|detection_agent|streamlit)' | grep -v grep

# Test API
curl http://192.168.100.20:5000/

# Check logs
tail -f logs/detection.log
```

---

### Step 2: VM2 (Attacker) Setup

#### 2.1 Configure Network

```bash
# Verify IP address
ip addr show

# Should show: 192.168.100.10
```

#### 2.2 Install Attack Tools

```bash
sudo apt update
sudo apt install sshpass nmap hydra -y
```

#### 2.3 Copy Attack Simulator

```bash
# From VM1 or use scp
scp kali@192.168.100.20:/home/kali/IR-Project/IR-System/vm2_attack_simulator.py ~/
chmod +x vm2_attack_simulator.py
```

#### 2.4 Test Connectivity

```bash
# Ping defender
ping -c 3 192.168.100.20

# Check SSH port
nmap -p 22 192.168.100.20
```

---

## 🎯 Running Attacks

### Using the Attack Simulator

```bash
python3 vm2_attack_simulator.py
```

**Available Attacks:**

1. **Brute Force** (3 failed logins)
   - Triggers: Brute Force rule
   - Severity: High
   - Duration: ~10 seconds

2. **Rapid Login Attempts** (10 failed logins)
   - Triggers: Rapid Attempts rule
   - Severity: Critical
   - Duration: ~20 seconds

3. **User Enumeration** (6 invalid users)
   - Triggers: User Enumeration rule
   - Severity: Medium
   - Duration: ~20 seconds

4. **Port Scan** (Nmap)
   - Reconnaissance activity
   - Scans ports 1-1000

5. **Hydra Brute Force** (Advanced)
   - Automated brute force tool
   - Uses small wordlist

### Manual Attack Examples

#### SSH Brute Force
```bash
# Single attempt
sshpass -p 'wrongpass' ssh root@192.168.100.20

# Multiple attempts (triggers detection)
for i in {1..5}; do
  sshpass -p 'wrongpass' ssh user$i@192.168.100.20
  sleep 2
done
```

#### Hydra Attack
```bash
# Create wordlist
echo -e "password\\n123456\\nadmin" > /tmp/passwords.txt

# Run hydra
hydra -l root -P /tmp/passwords.txt ssh://192.168.100.20
```

---

## 📊 Monitoring & Verification

### On VM1 (Defender):

#### Check Detection Agent Logs
```bash
tail -f logs/detection.log
```

**Expected output when attack detected:**
```
🚨 INCIDENT DETECTED
Type: Brute Force
Severity: High
IP: 192.168.100.10
Target: root
```

#### Check Automation Log
```bash
tail -f server_backend/automation.log
```

**Expected output:**
```
[2025-12-20 16:00:00] SUCCESS - BLOCK_IP | Target: 192.168.100.10 | Severity: High
```

#### Monitor Dashboard
```bash
# Access from host laptop
http://192.168.100.20:8501
```

**What to check:**
- ✅ Incidents appear in real-time
- ✅ Source IP shows 192.168.100.10
- ✅ Risk Level shows "Low" (private IP)
- ✅ Severity matches attack type
- ✅ Automation statistics update

### From Host (Laptop):

1. **Open Dashboard**: http://192.168.100.20:8501
2. **Filter by IP**: Enter "192.168.100.10"
3. **Watch Real-time**: Auto-refresh every 5 seconds
4. **Check Automation**: Settings → Automation Statistics

---

## 🔧 Configuration Options

### Disable Whitelist (Enable IP Blocking)

To test IP blocking automation:

```bash
# On VM1
cd /home/kali/IR-Project/IR-System

# Remove attacker from whitelist
cat > whitelist.json << 'EOF'
{
  "whitelist": {
    "ips": ["127.0.0.1", "::1"],
    "networks": ["10.0.0.0/8"]
  }
}
EOF

# Restart detection agent
sudo pkill -f detection_agent
sudo python3 detection_engine/detection_agent.py &
```

**Result:** Attacker IP will be blocked after High/Critical incidents

### Enable Automation Policies

```bash
# Edit config
nano server_backend/config.json

# Set automation policies
{
  "automation_policies": {
    "enabled": true,
    "actions": {
      "Critical": {
        "block_ip": true,
        "send_email": true
      }
    }
  }
}
```

---

## 🧪 Testing Checklist

### Basic Connectivity
- [ ] VM1 can ping VM2
- [ ] VM2 can ping VM1
- [ ] Host can access VM1 dashboard
- [ ] SSH works between VMs

### Detection Rules
- [ ] Brute Force (3 failed logins) - High
- [ ] Rapid Attempts (10 failed logins) - Critical
- [ ] User Enumeration (6 invalid users) - Medium
- [ ] Sudo Failures (if configured)
- [ ] Off-Hours Login (if configured)

### Threat Intelligence
- [ ] Incidents show Risk Level: "Low"
- [ ] Risk Score: 5
- [ ] No GeoIP data (private IP)
- [ ] Proper incident enrichment

### Automation
- [ ] Desktop notifications appear
- [ ] Automation log updated
- [ ] Statistics tracked correctly
- [ ] IP blocking works (if whitelist disabled)

### Dashboard
- [ ] Real-time updates work
- [ ] Filtering by IP works
- [ ] Export (CSV/JSON) works
- [ ] Incident resolution works

---

## 🐛 Troubleshooting

### "Cannot connect to API"
```bash
# On VM1, check if Flask is running
ps aux | grep app.py

# Check firewall
sudo ufw status

# Restart API
pkill -f app.py
python3 server_backend/app.py &
```

### "No incidents detected"
```bash
# Check detection agent logs
tail -f logs/detection.log

# Verify agent is running
ps aux | grep detection_agent

# Check if logs are being parsed
sudo journalctl -f | grep sshd
```

### "Dashboard not accessible from host"
```bash
# Verify Streamlit is listening on 0.0.0.0
netstat -tlnp | grep 8501

# Check firewall
sudo ufw allow 8501/tcp

# Restart dashboard
pkill -f streamlit
streamlit run server_backend/dashboard.py --server.address 0.0.0.0 &
```

### "Attacks not triggering detection"
```bash
# Verify SSH is accessible
nmap -p 22 192.168.100.20

# Check detection rules
python3 tests/test_detection.py

# Increase verbosity
sudo python3 detection_engine/detection_agent.py --verbose
```

---

## 📝 Notes

### Whitelist Behavior
- Attacker IP (192.168.100.10) is whitelisted by default
- This prevents IP blocking during testing
- Remove from whitelist to test blocking automation

### Private IP Risk Levels
- All private IPs get "Low" risk level automatically
- This is expected behavior
- External IPs would get full threat intelligence

### Performance
- Detection latency: <1 second
- Dashboard refresh: 5 seconds
- Automation response: Immediate

---

## 🎓 Learning Objectives

This two-VM setup demonstrates:
- ✅ Real-world attack detection
- ✅ Network-based incident response
- ✅ Threat intelligence integration
- ✅ Automated containment actions
- ✅ SOC dashboard operations
- ✅ Incident lifecycle management

---

## 📚 Additional Resources

- **Main README**: `/home/kali/IR-Project/IR-System/README.md`
- **API Documentation**: README.md → API Documentation
- **Detection Rules**: `detection_engine/detection_rules.py`
- **Automation Policies**: `server_backend/config.json`

---

**Deployment Complete! 🎉**

Access your dashboard: **http://192.168.100.20:8501**
