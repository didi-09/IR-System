#!/bin/bash
# VM1 Deployment Script - IR System (Defender)
# IP: 192.168.100.20
# Run this script on the defender VM

echo "======================================"
echo "IR System - VM1 Deployment (Defender)"
echo "IP: 192.168.100.20"
echo "======================================"
echo ""

# Check if running as root for network configuration
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  Note: Some network configurations may require sudo"
fi

# Step 1: Update Flask API to listen on all interfaces
echo "📝 Step 1: Configuring Flask API for network access..."
cd /home/kali/IR-Project/IR-System

# Backup original app.py
if [ ! -f server_backend/app.py.backup ]; then
    cp server_backend/app.py server_backend/app.py.backup
    echo "✅ Backed up app.py"
fi

# Update Flask to listen on 0.0.0.0
sed -i "s/app.run(debug=True, port=5000)/app.run(host='0.0.0.0', debug=True, port=5000)/" server_backend/app.py
echo "✅ Flask API configured to listen on 0.0.0.0:5000"

# Step 2: Configure firewall (optional)
echo ""
echo "📝 Step 2: Configuring firewall..."
sudo ufw allow 5000/tcp comment 'Flask API' 2>/dev/null && echo "✅ Opened port 5000 (Flask API)" || echo "⚠️  UFW not available or already configured"
sudo ufw allow 8501/tcp comment 'Streamlit Dashboard' 2>/dev/null && echo "✅ Opened port 8501 (Dashboard)" || echo "⚠️  UFW not available or already configured"
sudo ufw allow 22/tcp comment 'SSH' 2>/dev/null && echo "✅ Opened port 22 (SSH)" || echo "⚠️  UFW not available or already configured"

# Step 3: Update whitelist (optional - for testing without blocking attacker)
echo ""
echo "📝 Step 3: Updating whitelist..."
cat > whitelist.json << 'EOF'
{
  "whitelist": {
    "ips": [
      "127.0.0.1",
      "::1",
      "192.168.100.10"
    ],
    "networks": [
      "10.0.0.0/8"
    ],
    "comment": "192.168.100.10 is the attacker VM - whitelisted for testing"
  }
}
EOF
echo "✅ Whitelist updated (attacker IP: 192.168.100.10)"

# Step 4: Install dependencies
echo ""
echo "📝 Step 4: Installing dependencies..."
pip install -r requirements.txt --break-system-packages -q
echo "✅ Dependencies installed"

# Step 5: Initialize database
echo ""
echo "📝 Step 5: Initializing database..."
python3 server_backend/models.py
echo "✅ Database initialized"

# Step 6: Create startup script
echo ""
echo "📝 Step 6: Creating startup script..."
cat > start_vm1_services.sh << 'STARTSCRIPT'
#!/bin/bash
# Start all IR System services on VM1

echo "🚀 Starting IR System Services..."

# Kill existing processes
pkill -f "python3.*app.py" 2>/dev/null
pkill -f "python3.*detection_agent" 2>/dev/null
pkill -f streamlit 2>/dev/null
sleep 2

# Start Flask API
echo "Starting Flask API on 0.0.0.0:5000..."
cd /home/kali/IR-Project/IR-System
python3 server_backend/app.py > logs/api.log 2>&1 &
sleep 3

# Start Detection Agent (REAL MODE - not simulation)
echo "Starting Detection Agent (Real Mode)..."
sudo python3 detection_engine/detection_agent.py > logs/detection.log 2>&1 &
sleep 2

# Start Dashboard
echo "Starting Dashboard on 0.0.0.0:8501..."
streamlit run server_backend/dashboard.py --server.address 0.0.0.0 --server.port 8501 > logs/dashboard.log 2>&1 &
sleep 2

echo ""
echo "✅ All services started!"
echo ""
echo "📊 Dashboard: http://192.168.100.20:8501"
echo "🔌 API: http://192.168.100.20:5000"
echo ""
echo "Check status:"
echo "  ps aux | grep -E '(app.py|detection_agent|streamlit)' | grep -v grep"
STARTSCRIPT

chmod +x start_vm1_services.sh
echo "✅ Startup script created: start_vm1_services.sh"

# Step 7: Create logs directory
mkdir -p logs
echo "✅ Logs directory created"

# Step 8: Display network info
echo ""
echo "======================================"
echo "✅ VM1 Deployment Complete!"
echo "======================================"
echo ""
echo "Network Configuration:"
ip addr show | grep "inet " | grep -v "127.0.0.1"
echo ""
echo "Next Steps:"
echo "1. Start services: ./start_vm1_services.sh"
echo "2. Access dashboard from your laptop: http://192.168.100.20:8501"
echo "3. On VM2 (attacker), run attack scripts targeting 192.168.100.20"
echo ""
echo "To remove whitelist protection (enable IP blocking):"
echo "  Edit whitelist.json and remove 192.168.100.10"
echo ""
