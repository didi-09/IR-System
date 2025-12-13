# Detection Engine (Bayoumy's Component)

This is the **Detection Engine** component of the Security Incident Detection & Response System. It monitors system logs, detects security incidents, and applies automated containment actions.

## Components

### 1. `log_parser.py`
Parses authentication logs (`/var/log/auth.log`) to extract:
- Failed login attempts
- Successful logins
- Invalid user attempts
- IP addresses, timestamps, PIDs, target users

### 2. `detection_rules.py`
Implements detection rules:
- **BruteForceRule**: Detects 3+ failed logins from same IP within 60 seconds
- **RapidLoginAttemptsRule**: Detects 10+ failed attempts in 30 seconds (Critical)
- Extensible framework for adding custom rules

### 3. `containment.py`
Automated response actions:
- **IP Blocking**: Blocks IPs using `iptables` (simulation mode by default)
- **Process Termination**: Kills suspicious processes using `kill` (simulation mode by default)
- Safety features: Requires root for real actions, falls back to simulation

### 4. `detection_agent.py`
Main agent that:
- Monitors logs continuously
- Runs detection rules
- Applies containment actions
- Sends alerts to Flask API backend

### 5. `system_info.py` (Day 2 & 3)
System information collection:
- **Day 2**: Print current running processes using psutil
- **Day 3**: Capture System Info (OS, Users, Uptime) when incidents detected
- **Day 3**: Capture Active Network Connections using socket and psutil
- Automatic system context collection for incident enrichment

## Usage

### Basic Usage (Simulation Mode - Safe)

```bash
cd detection_engine
python detection_agent.py
```

### With Custom Options

```bash
python detection_agent.py \
    --log-file /var/log/auth.log \
    --api-url http://127.0.0.1:5000/api/alert \
    --simulation \
    --interval 5.0
```

### Day 2: Print Running Processes

```bash
# Print current running processes and exit
python detection_agent.py --print-processes
```

### Day 2/3: Print System Information

```bash
# Print comprehensive system information summary and exit
python detection_agent.py --print-system-info
```

### Production Mode (WARNING: Real Actions)

```bash
# Requires root privileges
sudo python detection_agent.py --no-simulation
```

## Integration

The detection agent automatically sends detected incidents to the Flask API backend at `/api/alert`. Ensure the Flask backend is running before starting the agent.

## Safety Features

- **Simulation Mode (Default)**: All containment actions are simulated
- **Permission Checks**: Real actions require appropriate permissions
- **Error Handling**: Graceful fallback to simulation if actions fail
- **Duplicate Prevention**: Tracks blocked IPs to avoid duplicates

## Requirements

- Python 3.6+
- `requests` library (for API communication)
- `psutil` library (for system info and process monitoring - Day 2 & 3)
- Linux system (for real iptables/kill actions)
- Root privileges (for real containment actions)

Install dependencies:
```bash
pip install -r requirements.txt
```

## Day 2 & 3 Features

### Day 2: Process Monitoring
- Use `--print-processes` to view current running processes
- Processes are sorted by CPU usage
- Shows PID, name, status, CPU%, and Memory%

### Day 3: System Context Collection
- Automatically collects system info when incidents are detected:
  - OS information (system, release, version)
  - Current user and system users
  - System uptime
  - CPU and memory usage
  - Active network connections
  - Top running processes
- System context is included in incident data sent to API
- Use `--no-system-info` to disable collection (faster, less detailed)

## Testing

The agent can be tested even without access to `/var/log/auth.log` - it will automatically fall back to simulation mode and log warnings.

