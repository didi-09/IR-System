# 🚀 Quick Start Guide

This guide shows you how to run the complete Security Incident Detection & Response System.

## System Architecture

- **Detection Engine** (Bayoumy): Monitors logs, detects incidents, applies containment
- **Flask API Backend** (Didi): Receives alerts, stores in database
- **Streamlit Dashboard** (Didi): Visualizes incidents in real-time

## Prerequisites

```bash
pip install flask sqlalchemy streamlit pandas requests
```

## Running the System

You need **3 terminal windows**:

### Terminal 1: Start Flask API Backend

```bash
cd server_backend
python app.py
```

**Verify:** You should see:
```
Starting Flask API server on http://127.0.0.1:5000
```

### Terminal 2: Start Streamlit Dashboard

```bash
cd server_backend
streamlit run dashboard.py
```

**Verify:** Browser opens automatically showing the dashboard.

### Terminal 3: Start Detection Agent

```bash
cd detection_engine
python detection_agent.py
```

**Verify:** You should see:
```
🛡️  Detection Agent Initialized
Log File: /var/log/auth.log
API URL: http://127.0.0.1:5000/api/alert
Simulation Mode: True
```

## Testing the System

### Option 1: Use Test Client

```bash
cd server_backend
python test.py
```

This sends a sample incident to the API.

### Option 2: Test Detection Rules

```bash
cd detection_engine
python -m detection_engine.test_detection
```

### Option 3: Generate Test Data

```bash
cd server_backend
python generate_data.py
```

## How It Works

1. **Detection Agent** monitors `/var/log/auth.log` for authentication events
2. When it detects suspicious activity (e.g., 3 failed logins in 60 seconds):
   - Applies containment (blocks IP, kills process if needed)
   - Sends alert to Flask API
3. **Flask API** receives the alert and saves it to the database
4. **Dashboard** automatically updates to show the new incident

## Simulation Mode (Default)

By default, the detection agent runs in **simulation mode**:
- ✅ Safe for testing
- ✅ No real iptables/kill commands executed
- ✅ All actions are logged but not executed

## Production Mode (WARNING)

To run with real containment actions:

```bash
sudo python detection_agent.py --no-simulation
```

**Requirements:**
- Linux system
- Root privileges
- iptables installed

## Troubleshooting

### "Cannot connect to API"
- Ensure Flask backend is running (Terminal 1)
- Check API URL: `http://127.0.0.1:5000/api/alert`

### "Log file not found"
- The agent will automatically use simulation mode
- On Windows, this is expected (auth.log is Linux-specific)

### "Permission denied"
- For real actions, run with `sudo`
- Or use simulation mode (default)

## File Structure

```
IR-System/
├── detection_engine/          # Bayoumy's Detection Engine
│   ├── log_parser.py          # Parses auth.log
│   ├── detection_rules.py     # Detection rules
│   ├── containment.py         # IP blocking, process killing
│   ├── detection_agent.py      # Main agent
│   └── test_detection.py      # Test script
├── server_backend/            # Didi's Backend
│   ├── app.py                 # Flask API
│   ├── models.py              # Database models
│   ├── dashboard.py           # Streamlit dashboard
│   └── test.py                # Test client
└── database.db                 # SQLite database
```

## Next Steps

1. Review the main `README.md` for detailed documentation
2. Check `detection_engine/README.md` for detection engine details
3. Customize detection rules in `detection_rules.py`
4. Adjust containment actions in `containment.py`

