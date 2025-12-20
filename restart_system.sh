#!/bin/bash
# Quick restart script for the IR system

echo "🔄 Restarting IR System..."

# Kill existing processes
echo "Stopping old processes..."
pkill -f "python3.*app.py" 2>/dev/null
pkill -f "python3.*detection_agent.py" 2>/dev/null
pkill -f "streamlit.*dashboard.py" 2>/dev/null
sleep 2

# Start Flask API
echo "Starting Flask API..."
cd /home/kali/IR-Project/IR-System
python3 server_backend/app.py > /dev/null 2>&1 &
sleep 3

# Start Detection Agent  
echo "Starting Detection Agent..."
python3 detection_engine/detection_agent.py --simulation > /dev/null 2>&1 &
sleep 2

# Start Dashboard
echo "Starting Dashboard..."
streamlit run server_backend/dashboard.py > /dev/null 2>&1 &
sleep 2

echo ""
echo "✅ System restarted!"
echo ""
echo "📊 Dashboard: http://localhost:8501"
echo "🔌 API: http://127.0.0.1:5000"
echo ""
echo "To check status:"
echo "  ps aux | grep -E '(app.py|detection_agent|streamlit)' | grep -v grep"
