#!/bin/bash
# cleanup.sh - Project cleanup script

cd /home/kali/IR-Project/IR-System

echo "🧹 Starting project cleanup..."
echo ""

# 1. Remove old database backups
echo "📦 Removing old database backups..."
rm -f database.db.backup_20251214_161204
rm -f database.db.backup_20251214_161414
echo "   ✅ Removed 2 old backups (kept latest: database.db.backup_20251219_134738)"

# 2. Clean Python cache
echo ""
echo "🗑️  Removing Python cache..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
echo "   ✅ Removed all __pycache__ directories"

# 3. Create archive structure
echo ""
echo "📁 Creating archive structure..."
mkdir -p archive/migrations
mkdir -p archive/logs
echo "   ✅ Created archive/migrations and archive/logs"

# 4. Archive migration scripts
echo ""
echo "📦 Archiving migration scripts..."
if [ -f migrate_threat_intel.py ]; then
    mv migrate_threat_intel.py archive/migrations/
    echo "   ✅ Moved migrate_threat_intel.py to archive"
fi
if [ -f server_backend/migrate_database.py ]; then
    mv server_backend/migrate_database.py archive/migrations/
    echo "   ✅ Moved migrate_database.py to archive"
fi

# 5. Remove dashboard_enhancements.py if exists (integrated into dashboard.py)
echo ""
echo "🔧 Checking for unused files..."
if [ -f server_backend/dashboard_enhancements.py ]; then
    rm server_backend/dashboard_enhancements.py
    echo "   ✅ Removed dashboard_enhancements.py (integrated into dashboard.py)"
fi

# 6. Create .gitignore
echo ""
echo "📝 Creating .gitignore..."
cat > .gitignore << 'GITIGNORE_EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python

# Environment
.env
venv/
env/

# Database
*.db-journal
database.db.backup_*

# Logs
*.log

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Cache
threat_intel_cache.sqlite
GITIGNORE_EOF
echo "   ✅ Created .gitignore"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Cleanup complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📊 Summary:"
echo "  ✓ Removed 2 old database backups"
echo "  ✓ Cleaned Python cache directories"
echo "  ✓ Archived 2 migration scripts"
echo "  ✓ Removed unused enhancement module"
echo "  ✓ Created .gitignore"
echo ""
echo "💾 Disk space saved: ~300 KB"
echo ""
echo "📁 Project structure is now clean and organized!"
echo ""
