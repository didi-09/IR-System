#!/bin/bash
# Script to remove files from git that are now in .gitignore
# Note: Log files are kept in git tracking as requested

echo "🧹 Removing tracked files that are now in .gitignore..."
echo "=================================================="

# Remove files from git index (but keep them locally)
git rm --cached Sentinel_Project_Documentation.pdf
git rm --cached cleanup_temp_files.sh
git rm --cached database.db
git rm --cached install_and_generate_pdf.sh
git rm --cached reports/incident_report_552_20251220_191225.pdf
git rm --cached server_backend/incidents.db
git rm --cached server_backend/threat_intel_cache.sqlite
git rm --cached threat_intel_cache.sqlite

echo ""
echo "✅ Files removed from git tracking (but kept locally)"
echo "📝 Log files are kept in git tracking as requested"
echo ""
echo "Next steps:"
echo "1. Review changes: git status"
echo "2. Commit changes: git commit -m 'Remove temporary and generated files from tracking'"
echo "3. Push to GitHub: git push origin main"
echo ""
echo "Note: These files will remain on your local system but won't be tracked by git anymore."
