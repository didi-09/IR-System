
import json
import os
import threading

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.json')

DEFAULT_CONFIG = {
    "ping_targets": ["8.8.8.8", "1.1.1.1"],
    "dos_thresholds": {
        "cpu_percent": 80.0,
        "pps_in": 1000,
        "pps_out_ratio": 10.0
    },
    "simulation_mode": False,
    "email_alerts": {
        "enabled": False,
        "recipient": "abdelrahamanzakaria@gmail.com",
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "sender_email": "",
        "sender_password": ""
    },
    "automation_policies": {
        "enabled": True,
        "actions": {
            "Critical": {
                "block_ip": True,
                "kill_process": False,
                "send_email": True,
                "send_desktop_alert": True,
                "auto_resolve": False
            },
            "High": {
                "block_ip": True,
                "kill_process": False,
                "send_email": True,
                "send_desktop_alert": True,
                "auto_resolve": False
            },
            "Medium": {
                "block_ip": False,
                "kill_process": False,
                "send_email": False,
                "send_desktop_alert": True,
                "auto_resolve": False
            },
            "Low": {
                "block_ip": False,
                "kill_process": False,
                "send_email": False,
                "send_desktop_alert": True,
                "auto_resolve": True
            }
        }
    }
}

class ConfigManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(ConfigManager, cls).__new__(cls)
                    cls._instance._load_config()
        return cls._instance

    def _load_config(self):
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, 'r') as f:
                    self.config = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    for key, value in DEFAULT_CONFIG.items():
                        if key not in self.config:
                            self.config[key] = value
            except Exception as e:
                print(f"Error loading config: {e}. Using defaults.")
                self.config = DEFAULT_CONFIG.copy()
        else:
            self.config = DEFAULT_CONFIG.copy()
            self._save_config()

    def _save_config(self):
        try:
            with open(CONFIG_PATH, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"Error saving config: {e}")

    def get(self, key, default=None):
        return self.config.get(key, default)

    def set(self, key, value):
        self.config[key] = value
        self._save_config()

    def get_all(self):
        return self.config.copy()
