#!/bin/bash
# Quick System Test Script
# Tests all major components of the IR-System

echo "🧪 Quick System Test"
echo "==================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: System Info (Day 2)
echo "Test 1: System Information (Day 2)..."
cd detection_engine 2>/dev/null || { echo -e "${RED}❌ detection_engine directory not found${NC}"; exit 1; }
if python3 detection_agent.py --print-system-info > /dev/null 2>&1; then
    echo -e "${GREEN}✅ System Info OK${NC}"
else
    echo -e "${RED}❌ System Info Failed${NC}"
fi

# Test 2: Process Listing (Day 2)
echo "Test 2: Process Listing (Day 2)..."
if python3 detection_agent.py --print-processes > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Process Listing OK${NC}"
else
    echo -e "${RED}❌ Process Listing Failed${NC}"
fi

# Test 3: Detection Rules (Day 4)
echo "Test 3: Detection Rules (Day 4)..."
if python3 test_detection.py > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Detection Rules OK${NC}"
else
    echo -e "${YELLOW}⚠️  Detection Rules Test (may need dependencies)${NC}"
fi

# Test 4: API Health Check
echo "Test 4: Flask API Health Check..."
cd ../server_backend 2>/dev/null || { echo -e "${RED}❌ server_backend directory not found${NC}"; exit 1; }
if curl -s http://127.0.0.1:5000/ > /dev/null 2>&1; then
    echo -e "${GREEN}✅ API is Running${NC}"
else
    echo -e "${YELLOW}⚠️  API not running (start with: cd server_backend && python3 app.py)${NC}"
fi

# Test 5: Database Connection
echo "Test 5: Database Connection..."
if python3 -c "from models import Session, Incident; s = Session(); s.close(); print('OK')" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Database Connection OK${NC}"
else
    echo -e "${RED}❌ Database Connection Failed${NC}"
fi

# Test 6: Dependencies Check
echo "Test 6: Python Dependencies..."
if python3 -c "import flask, sqlalchemy, streamlit, pandas, requests, psutil" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ All Dependencies Installed${NC}"
else
    echo -e "${YELLOW}⚠️  Some dependencies missing (run: pip install -r requirements.txt)${NC}"
fi

# Test 7: Blacklist File (Day 9)
echo "Test 7: Threat Intelligence Blacklist (Day 9)..."
cd .. 2>/dev/null
if [ -f "ip_blacklist.json" ]; then
    echo -e "${GREEN}✅ Blacklist File Exists${NC}"
else
    echo -e "${YELLOW}⚠️  Blacklist file not found${NC}"
fi

echo ""
echo "==================="
echo -e "${GREEN}✅ Quick test complete!${NC}"
echo ""
echo "For comprehensive testing, see TESTING_GUIDE.md"
echo ""

