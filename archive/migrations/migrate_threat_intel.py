#!/usr/bin/env python3
"""
Database migration script to add threat intelligence fields.
"""
import sqlite3
import os
import shutil
from datetime import datetime

# Database path
DB_PATH = '/home/kali/IR-Project/IR-System/database.db'

def backup_database():
    """Create a backup of the database."""
    # timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    # backup_path = f"{DB_PATH}.backup_{timestamp}"
    # shutil.copy2(DB_PATH, backup_path)
    # print(f"✅ Database backed up to: {backup_path}")
    # return backup_path
    return None

def migrate_database():
    """Add threat intelligence columns to incidents table."""
    print("🔄 Starting database migration...")
    
    # Backup first
    backup_path = backup_database()
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Add threat intelligence columns
        columns_to_add = [
            ("geo_country", "TEXT"),
            ("geo_country_code", "TEXT"),
            ("geo_city", "TEXT"),
            ("geo_region", "TEXT"),
            ("geo_lat", "TEXT"),
            ("geo_lon", "TEXT"),
            ("geo_isp", "TEXT"),
            ("geo_org", "TEXT"),
            ("is_proxy", "TEXT"),
            ("is_hosting", "TEXT"),
            ("abuse_confidence_score", "INTEGER"),
            ("abuse_total_reports", "INTEGER"),
            ("threat_risk_score", "INTEGER"),
            ("threat_risk_level", "TEXT")
        ]
        
        for column_name, column_type in columns_to_add:
            try:
                cursor.execute(f"ALTER TABLE incidents ADD COLUMN {column_name} {column_type}")
                print(f"  ✅ Added column: {column_name}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    print(f"  ⚠️  Column {column_name} already exists, skipping")
                else:
                    raise
        
        conn.commit()
        conn.close()
        
        print("\n✅ Migration completed successfully!")
        print(f"   Backup saved at: {backup_path}")
        
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        print(f"   Restoring from backup: {backup_path}")
        shutil.copy2(backup_path, DB_PATH)
        print("   Database restored to previous state")
        raise

if __name__ == '__main__':
    migrate_database()
