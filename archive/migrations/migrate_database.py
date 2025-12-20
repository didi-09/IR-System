# migrate_database.py - Migrate database schema to support extended fields
"""
Migration script to add new columns to the incidents table.
This handles SQLite's limited ALTER TABLE support.
"""

import sqlite3
import os
import shutil
from datetime import datetime
from models import _database_path

def migrate_database():
    """Migrate database to new schema with extended fields."""
    print("=" * 70)
    print("Database Schema Migration")
    print("=" * 70)
    
    if not os.path.exists(_database_path):
        print(f"✅ Database doesn't exist yet. It will be created with new schema.")
        return
    
    # Backup database
    # backup_path = _database_path + f".backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    # print(f"\n📦 Creating backup: {backup_path}")
    # shutil.copy2(_database_path, backup_path)
    # print("✅ Backup created")
    
    # Connect to database
    conn = sqlite3.connect(_database_path)
    cursor = conn.cursor()
    
    try:
        # Get existing columns
        cursor.execute("PRAGMA table_info(incidents)")
        existing_columns = [row[1] for row in cursor.fetchall()]
        print(f"\n📊 Existing columns: {len(existing_columns)}")
        
        # New columns to add
        new_columns = {
            'target_ip': 'TEXT',
            'outcome': 'TEXT',
            'data_compromised_GB': 'TEXT',
            'attack_duration_min': 'INTEGER',
            'security_tools_used': 'TEXT',
            'user_role': 'TEXT',
            'location': 'TEXT',
            'attack_severity': 'INTEGER',
            'industry': 'TEXT',
            'response_time_min': 'INTEGER',
            'mitigation_method': 'TEXT'
        }
        
        # Add missing columns
        columns_added = 0
        for column_name, column_type in new_columns.items():
            if column_name not in existing_columns:
                try:
                    cursor.execute(f"ALTER TABLE incidents ADD COLUMN {column_name} {column_type}")
                    print(f"   ✅ Added column: {column_name}")
                    columns_added += 1
                except sqlite3.OperationalError as e:
                    print(f"   ⚠️  Could not add {column_name}: {e}")
        
        conn.commit()
        
        if columns_added > 0:
            print(f"\n✅ Migration complete! Added {columns_added} new columns.")
        else:
            print("\n✅ Database already has all required columns.")
        
        # Verify
        cursor.execute("PRAGMA table_info(incidents)")
        final_columns = [row[1] for row in cursor.fetchall()]
        print(f"\n📊 Final column count: {len(final_columns)}")
        
    except Exception as e:
        conn.rollback()
        print(f"\n❌ Migration failed: {e}")
        print(f"   Restore from backup: cp {backup_path} {_database_path}")
        raise
    finally:
        conn.close()
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    migrate_database()

