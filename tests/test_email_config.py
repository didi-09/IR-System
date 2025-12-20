
import sys
import os
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../server_backend')))

from alert_manager import AlertManager
from config_manager import ConfigManager

def test_config_load():
    print("Testing Config Load...")
    cm = ConfigManager()
    config = cm.get("email_alerts", {})
    print(f"  Enabled: {config.get('enabled')}")
    print(f"  Recipient: {config.get('recipient')}")
    if config.get('recipient') == "abdelrahamanzakaria@gmail.com":
        print("  ✅ Default recipient verified.")
    else:
        print(f"  ❌ User Recipient: {config.get('recipient')}")

def test_alert_manager_init():
    print("\nTesting AlertManager Initialization...")
    try:
        am = AlertManager()
        print("  ✅ AlertManager initialized.")
    except Exception as e:
        print(f"  ❌ Init failed: {e}")

if __name__ == "__main__":
    print("🧪 Testing Email Alert System Configuration")
    test_config_load()
    test_alert_manager_init()
    print("\nNote: Actual email sending requires valid credentials and is tested via the Dashboard button.")
