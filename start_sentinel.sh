#!/bin/bash
# Sentinel IR System - Unified Launcher
# Starts all components: Flask API, Detection Agent, and Dashboard

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================="
echo "🛡️  Sentinel IR System - Starting"
echo -e "==========================================${NC}"
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down all components...${NC}"
    kill $FLASK_PID $AGENT_PID 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# Check if already running
if pgrep -f "server_backend/app.py" > /dev/null; then
    echo -e "${YELLOW}⚠️  Flask API already running. Stopping it...${NC}"
    pkill -f "server_backend/app.py"
    sleep 2
fi

if pgrep -f "detection_engine/detection_agent.py" > /dev/null; then
    echo -e "${YELLOW}⚠️  Detection agent already running. Stopping it...${NC}"
    sudo pkill -f "detection_engine/detection_agent.py"
    sleep 2
fi

# Start Flask API
echo -e "${GREEN}[1/3] Starting Flask API...${NC}"
python3 server_backend/app.py > /tmp/sentinel_api.log 2>&1 &
FLASK_PID=$!
sleep 3

# Check if Flask started successfully
if ! kill -0 $FLASK_PID 2>/dev/null; then
    echo -e "${YELLOW}❌ Flask API failed to start. Check /tmp/sentinel_api.log${NC}"
    exit 1
fi
echo -e "${GREEN}      ✓ Flask API running (PID: $FLASK_PID)${NC}"

# Start Detection Agent
echo -e "${GREEN}[2/3] Starting Detection Agent...${NC}"
sudo python3 detection_engine/detection_agent.py --multi-source --no-simulation > /tmp/sentinel_agent.log 2>&1 &
AGENT_PID=$!
sleep 3

# Check if agent started successfully
if ! sudo kill -0 $AGENT_PID 2>/dev/null; then
    echo -e "${YELLOW}❌ Detection agent failed to start. Check /tmp/sentinel_agent.log${NC}"
    kill $FLASK_PID
    exit 1
fi
echo -e "${GREEN}      ✓ Detection Agent running (PID: $AGENT_PID)${NC}"

echo ""
echo -e "${BLUE}=========================================="
echo "✅ Backend Services Running"
echo -e "==========================================${NC}"
echo "  Flask API:        http://127.0.0.1:5000"
echo "  API Logs:         /tmp/sentinel_api.log"
echo "  Agent Logs:       /tmp/sentinel_agent.log"
echo ""
echo -e "${YELLOW}[3/3] Launching Dashboard...${NC}"
echo -e "${BLUE}==========================================${NC}"
echo ""

# Start Streamlit Dashboard (foreground)
streamlit run server_backend/dashboard.py

# Cleanup when dashboard exits
cleanup
