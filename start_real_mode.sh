#!/bin/bash
# Start IR System in Real Detection Mode
# This script starts all services needed for real-time incident detection

set -e

echo "🛡️  IR System - Real Detection Mode"
echo "====================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
   echo "❌ This script must be run with sudo!"
   echo "   Usage: sudo ./start_real_mode.sh"
   exit 1
fi

cd /home/kali/IR-Project/IR-System

# Clean up old processes
echo "🧹 Stopping old processes..."
pkill -f detection_agent.py 2>/dev/null || true
pkill -f "python3 app.py" 2>/dev/null || true
pkill -f streamlit 2>/dev/null || true
sleep 2

# Start Flask API (as kali user)
echo "🚀 Starting Flask API..."
su - kali -c "cd /home/kali/IR-Project/IR-System/server_backend && python3 app.py > /tmp/ir_api.log 2>&1 &"
sleep 3

# Verify API started
if curl -s http://127.0.0.1:5000/ > /dev/null 2>&1; then
    echo "   ✅ API running on http://127.0.0.1:5000"
else
    echo "   ❌ API failed to start. Check /tmp/ir_api.log"
    exit 1
fi

# Start Dashboard (as kali user)
echo "🚀 Starting Dashboard..."
su - kali -c "cd /home/kali/IR-Project/IR-System && streamlit run server_backend/dashboard.py --server.address 0.0.0.0 --server.port 8501 > /tmp/ir_dashboard.log 2>&1 &"
sleep 3

echo "   ✅ Dashboard running on http://0.0.0.0:8501"

# Start Detection Agent (as root, in foreground)
echo "🚀 Starting Detection Agent..."
echo ""
echo "📊 Detection agent will run in foreground."
echo "   You'll see real-time detection output below."
echo "   Press Ctrl+C to stop."
echo ""
echo "🧪 To test, from another device run:"
echo "   ssh wronguser@$(hostname -I | awk '{print $1}')"
echo "   (Do this 3 times to trigger Brute Force detection)"
echo ""
echo "====================================="
echo ""

cd /home/kali/IR-Project/IR-System/detection_engine
exec python3 detection_agent.py --no-simulation
