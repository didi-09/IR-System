
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import sys
import os
import subprocess
from datetime import datetime

ALERT_LOG_PATH = os.path.join(os.path.dirname(__file__), 'alerts.log')

# Ensure we can import ConfigManager
try:
    from config_manager import ConfigManager
except ImportError:
    # Try alternate path
    try:
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'server_backend')))
        from config_manager import ConfigManager
    except ImportError:
        print("Warning: ConfigManager not found. AlertManager disabled.")
        ConfigManager = None

class AlertManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(AlertManager, cls).__new__(cls)
                    cls._instance.config_manager = ConfigManager() if ConfigManager else None
        return cls._instance

    def send_email_alert(self, incident_data):
        """
        Trigger an alert (Desktop Notification + Local Log).
        Renamed from send_email_alert to keep compatibility, 
        but logic is now strictly local as per user request.
        """
        # 1. Desktop Notification
        self.send_desktop_notification(incident_data)
        
        # 2. Local File Log
        self.log_alert_to_file(incident_data)

    def log_alert_to_file(self, data):
        """Append alert to a local log file."""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = (
                f"[{timestamp}] ALERT: {data.get('type', 'Unknown')} "
                f"(Severity: {data.get('severity')}) - "
                f"Source: {data.get('ip')} - "
                f"Target: {data.get('target')}\n"
            )
            
            with open(ALERT_LOG_PATH, 'a') as f:
                f.write(log_entry)
            
            # Print to console for verification
            print(f"📝 Alert logged: {data.get('type')} (Severity: {data.get('severity')})")
            
        except Exception as e:
            print(f"❌ Failed to log alert locally: {e}")

    def send_desktop_notification(self, data):
        """Send a desktop notification using notify-send (Linux only)."""
        try:
            if sys.platform != 'linux':
                return
                
            summary = f"🚨 {data.get('severity', 'Security')} Alert"
            body = f"{data.get('type')}\nHost: {data.get('target')}\nSource: {data.get('ip')}"
            
            # send notification with critical urgency
            subprocess.run(
                ['notify-send', '-u', 'critical', summary, body], 
                check=False
            )
            print("🔔 Desktop Notification Sent")
        except Exception as e:
            print(f"⚠️ Failed to send desktop notification: {e}")

    def send_test_email(self):
        """Test the alerting system (Desktop + Log)."""
        test_data = {
            "type": "TEST ALERT",
            "severity": "Info",
            "timestamp": "Now",
            "target": "System Test",
            "ip": "127.0.0.1",
            "rule": "Manual Test",
            "status": "Test"
        }
        self.send_email_alert(test_data)
        return True, "Test alert triggered (Check local logs & popup)."
