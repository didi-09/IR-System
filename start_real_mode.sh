#!/bin/bash
# start_real_mode.sh
# Starts the IR System in Real Data Mode (Production)

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}🛡️  Starting Security Incident Response System - REAL DATA MODE${NC}"
echo "================================================================"
echo "WARNING: This mode will execute REAL ACTIONS (iptables blocking, process killing)."
echo "Ensure you have permission to monitor logs and execute commands."
echo "================================================================"

# Check for root if running agent
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}⚠️  Warning: You are running without sudo.${NC}"
  echo "The Detection Agent may fail to read /var/log/auth.log or execute containment."
  echo "It is recommended to run this script with sudo if you want full functionality."
  read -p "Continue anyway? (y/n) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
fi

# 1. Start Backend API
echo -e "\n${GREEN}[1/3] Starting Flask API Backend...${NC}"
cd /home/kali/IR-Project/IR-System/server_backend
python3 app.py > api.log 2>&1 &
API_PID=$!
echo "Backend running (PID: $API_PID). Logs: server_backend/api.log"

# Wait for API to start
sleep 3

# 2. Start Dashboard
echo -e "\n${GREEN}[2/3] Starting Streamlit Dashboard...${NC}"
streamlit run dashboard.py > dashboard.log 2>&1 &
DASH_PID=$!
echo "Dashboard running (PID: $DASH_PID). Logs: server_backend/dashboard.log"

# 3. Start Detection Agent (Real Mode)
echo -e "\n${GREEN}[3/3] Starting Detection Agent (REAL MODE)...${NC}"
cd /home/kali/IR-Project/IR-System/detection_engine
# Explicitly use --no-simulation just to be 100% sure, though we changed the default
python3 detection_agent.py --no-simulation
