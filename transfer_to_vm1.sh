#!/bin/bash
# Quick transfer script for sensitive files to VM1

TARGET_VM="192.168.100.20"
TARGET_USER="kali"
TARGET_PATH="/home/kali/IR-Project/IR-System"

echo "======================================"
echo "Sensitive Files Transfer to VM1"
echo "======================================"
echo ""
echo "Target: $TARGET_USER@$TARGET_VM"
echo "Path: $TARGET_PATH"
echo ""

# Check connectivity
echo "📡 Testing connectivity..."
ping -c 1 $TARGET_VM > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "❌ Cannot reach $TARGET_VM"
    echo "   Check network connectivity"
    exit 1
fi
echo "✅ VM1 is reachable"
echo ""

# Check if files exist
echo "📋 Checking files..."
MISSING=0

if [ ! -f .env ]; then
    echo "❌ .env not found"
    MISSING=1
else
    echo "✅ .env found"
fi

if [ ! -f whitelist.json ]; then
    echo "⚠️  whitelist.json not found (will use default)"
else
    echo "✅ whitelist.json found"
fi

if [ ! -f ip_blacklist.json ]; then
    echo "⚠️  ip_blacklist.json not found (will use default)"
else
    echo "✅ ip_blacklist.json found"
fi

if [ $MISSING -eq 1 ]; then
    echo ""
    echo "❌ Critical files missing. Cannot proceed."
    exit 1
fi

echo ""
echo "📤 Starting transfer..."
echo ""

# Transfer .env
echo "[1/4] Transferring .env..."
scp .env $TARGET_USER@$TARGET_VM:$TARGET_PATH/ && echo "  ✅ Done" || echo "  ❌ Failed"

# Transfer whitelist
if [ -f whitelist.json ]; then
    echo "[2/4] Transferring whitelist.json..."
    scp whitelist.json $TARGET_USER@$TARGET_VM:$TARGET_PATH/ && echo "  ✅ Done" || echo "  ❌ Failed"
fi

# Transfer blacklist
if [ -f ip_blacklist.json ]; then
    echo "[3/4] Transferring ip_blacklist.json..."
    scp ip_blacklist.json $TARGET_USER@$TARGET_VM:$TARGET_PATH/ && echo "  ✅ Done" || echo "  ❌ Failed"
fi

# Optional: Transfer database
if [ -f database.db ]; then
    echo "[4/4] Transferring database.db (optional)..."
    read -p "Transfer database? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        scp database.db $TARGET_USER@$TARGET_VM:$TARGET_PATH/ && echo "  ✅ Done" || echo "  ❌ Failed"
    else
        echo "  ⏭️  Skipped"
    fi
else
    echo "[4/4] No database.db found (will create fresh)"
fi

echo ""
echo "======================================"
echo "✅ Transfer Complete!"
echo "======================================"
echo ""
echo "Next steps on VM1 ($TARGET_VM):"
echo "1. SSH to VM1: ssh $TARGET_USER@$TARGET_VM"
echo "2. Verify files: ls -la $TARGET_PATH/.env"
echo "3. Set permissions: chmod 600 $TARGET_PATH/.env"
echo "4. Deploy: cd $TARGET_PATH && ./deploy_vm1_defender.sh"
echo "5. Start services: ./start_vm1_services.sh"
echo ""
