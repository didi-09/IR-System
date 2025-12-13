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
- Linux system (for real iptables/kill actions)
- Root privileges (for real containment actions)

## Testing

The agent can be tested even without access to `/var/log/auth.log` - it will automatically fall back to simulation mode and log warnings.

