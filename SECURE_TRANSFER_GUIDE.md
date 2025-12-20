# Secure File Transfer Guide for VM Deployment

## 🔐 Files That Need Manual Transfer

These files are in `.gitignore` for security but are needed for the system to work:

### Critical Files:
1. **`.env`** - API keys and SMTP credentials
2. **`database.db`** - Your incident database (optional, can start fresh)
3. **`whitelist.json`** - Your IP whitelist configuration
4. **`ip_blacklist.json`** - Known malicious IPs

---

## 📦 Method 1: Secure Copy (SCP) - Recommended

### From Current Machine to VM1 (192.168.100.20):

```bash
# Navigate to project directory
cd /home/kali/IR-Project/IR-System

# Copy .env file
scp .env kali@192.168.100.20:/home/kali/IR-Project/IR-System/

# Copy whitelist
scp whitelist.json kali@192.168.100.20:/home/kali/IR-Project/IR-System/

# Copy IP blacklist
scp ip_blacklist.json kali@192.168.100.20:/home/kali/IR-Project/IR-System/

# Copy database (optional - if you want to keep existing incidents)
scp database.db kali@192.168.100.20:/home/kali/IR-Project/IR-System/

# All at once
scp .env whitelist.json ip_blacklist.json kali@192.168.100.20:/home/kali/IR-Project/IR-System/
```

---

## 📦 Method 2: Create Transfer Package

### Create encrypted archive with sensitive files:

```bash
cd /home/kali/IR-Project/IR-System

# Create directory for sensitive files
mkdir -p /tmp/ir-sensitive-files

# Copy sensitive files
cp .env /tmp/ir-sensitive-files/
cp whitelist.json /tmp/ir-sensitive-files/
cp ip_blacklist.json /tmp/ir-sensitive-files/
cp database.db /tmp/ir-sensitive-files/ 2>/dev/null || echo "No database to copy"

# Create encrypted archive
tar czf - /tmp/ir-sensitive-files | openssl enc -aes-256-cbc -salt -out ir-sensitive.tar.gz.enc

# Enter password when prompted (remember it!)

# Transfer encrypted file
scp ir-sensitive.tar.gz.enc kali@192.168.100.20:~/

# On VM1, decrypt and extract:
# openssl enc -aes-256-cbc -d -in ir-sensitive.tar.gz.enc | tar xzf -
# mv /tmp/ir-sensitive-files/* /home/kali/IR-Project/IR-System/
```

---

## 📦 Method 3: USB Drive Transfer

If VMs are on same host:

```bash
# Copy to USB (replace /media/usb with your mount point)
cp .env whitelist.json ip_blacklist.json /media/usb/ir-sensitive/

# On VM1, copy from USB
cp /media/usb/ir-sensitive/* /home/kali/IR-Project/IR-System/
```

---

## 📦 Method 4: Manual Recreation

### Option: Recreate .env on VM1

Instead of transferring, you can recreate the `.env` file on VM1:

```bash
# On VM1
cd /home/kali/IR-Project/IR-System
nano .env
```

**Copy these values from your current .env:**
```bash
# Threat Intelligence
ABUSEIPDB_API_KEY=your_actual_key_here

# Email Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password_here
SMTP_TO=security-team@yourdomain.com
```

---

## ✅ Verification Checklist

After transferring files to VM1, verify:

```bash
cd /home/kali/IR-Project/IR-System

# Check .env exists and has content
ls -la .env
cat .env | grep -v "^#" | grep -v "^$"

# Check whitelist exists
ls -la whitelist.json
cat whitelist.json

# Check IP blacklist exists
ls -la ip_blacklist.json

# Check database (optional)
ls -la database.db

# Set proper permissions
chmod 600 .env
chmod 644 whitelist.json ip_blacklist.json
```

---

## 🔒 Security Best Practices

### After Transfer:

1. **Delete transfer files:**
   ```bash
   rm ir-sensitive.tar.gz.enc
   rm -rf /tmp/ir-sensitive-files
   ```

2. **Verify .env permissions:**
   ```bash
   chmod 600 .env  # Only owner can read/write
   ```

3. **Never commit .env to Git:**
   ```bash
   # Already in .gitignore, but double-check:
   git status | grep .env
   # Should show nothing (file is ignored)
   ```

---

## 📋 Complete Transfer Script

Save this as `transfer_sensitive_files.sh`:

```bash
#!/bin/bash
# Transfer sensitive files to VM1

TARGET_VM="192.168.100.20"
TARGET_USER="kali"
TARGET_PATH="/home/kali/IR-Project/IR-System"

echo "🔐 Transferring sensitive files to VM1..."
echo "Target: $TARGET_USER@$TARGET_VM:$TARGET_PATH"
echo ""

# Check if files exist
if [ ! -f .env ]; then
    echo "❌ .env not found!"
    exit 1
fi

# Transfer files
echo "📤 Transferring .env..."
scp .env $TARGET_USER@$TARGET_VM:$TARGET_PATH/

echo "📤 Transferring whitelist.json..."
scp whitelist.json $TARGET_USER@$TARGET_VM:$TARGET_PATH/

echo "📤 Transferring ip_blacklist.json..."
scp ip_blacklist.json $TARGET_USER@$TARGET_VM:$TARGET_PATH/

# Optional: database
if [ -f database.db ]; then
    echo "📤 Transferring database.db..."
    scp database.db $TARGET_USER@$TARGET_VM:$TARGET_PATH/
fi

echo ""
echo "✅ Transfer complete!"
echo ""
echo "Next steps on VM1:"
echo "1. Verify files: ls -la $TARGET_PATH/.env"
echo "2. Set permissions: chmod 600 $TARGET_PATH/.env"
echo "3. Start services: ./start_vm1_services.sh"
```

Make it executable:
```bash
chmod +x transfer_sensitive_files.sh
./transfer_sensitive_files.sh
```

---

## 🎯 Quick Reference

**What to transfer:**
- ✅ `.env` (API keys, SMTP credentials)
- ✅ `whitelist.json` (IP whitelist)
- ✅ `ip_blacklist.json` (Known bad IPs)
- ⚠️ `database.db` (Optional - existing incidents)

**What NOT to transfer:**
- ❌ `__pycache__/` (Python bytecode)
- ❌ `*.log` files (old logs)
- ❌ `threat_intel_cache.sqlite` (will regenerate)
- ❌ `reports/` (old PDF reports)

---

## 🔄 Alternative: Fresh Start on VM1

If you don't need old data:

1. **Clone from GitHub** (after pushing)
2. **Create new .env** with your credentials
3. **Use default whitelist.json** (already in repo)
4. **Fresh database** (will be created automatically)

This is cleaner but loses historical incident data.

---

**Choose your method and transfer the sensitive files! 🚀**
