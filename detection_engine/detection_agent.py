# detection_agent.py (Bayoumy's Detection Engine - Main Agent)
"""
Main detection agent that monitors logs, detects incidents, applies containment,
and sends alerts to the Flask API backend.
"""
import time
import requests
import json
import sys
import os
from datetime import datetime
from typing import List, Dict, Optional

# Handle imports for both script and module execution
try:
    from .log_parser import AuthLogParser
    from .detection_rules import DetectionEngine
    from .containment import ContainmentActions
except ImportError:
    # If relative imports fail, try absolute imports (for direct script execution)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from log_parser import AuthLogParser
    from detection_rules import DetectionEngine
    from containment import ContainmentActions

class DetectionAgent:
    """
    Main detection agent that orchestrates log monitoring, detection, and alerting.
    """
    
    def __init__(
        self,
        log_file: str = "/var/log/auth.log",
        api_url: str = "http://127.0.0.1:5000/api/alert",
        simulation_mode: bool = True,
        check_interval: float = 5.0
    ):
        """
        Initialize the detection agent.
        
        Args:
            log_file: Path to auth.log file
            api_url: URL of the Flask API endpoint
            simulation_mode: If True, containment actions are simulated
            check_interval: Seconds between log checks
        """
        self.log_parser = AuthLogParser(log_file)
        self.detection_engine = DetectionEngine()
        self.containment = ContainmentActions(simulation_mode=simulation_mode)
        self.api_url = api_url
        self.check_interval = check_interval
        self.last_position = 0
        self.running = False
        
        # Track recent events for detection (keep last 1000 events)
        self.recent_events: List[Dict] = []
        self.max_events = 1000
        
        print("=" * 60)
        print("🛡️  Detection Agent Initialized")
        print("=" * 60)
        print(f"Log File: {log_file}")
        print(f"API URL: {api_url}")
        print(f"Simulation Mode: {simulation_mode}")
        print(f"Check Interval: {check_interval} seconds")
        print("=" * 60)
    
    def send_alert_to_api(self, incident: Dict) -> bool:
        """
        Send detected incident to Flask API backend.
        
        Args:
            incident: Incident dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            response = requests.post(
                self.api_url,
                json=incident,
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
            
            if response.status_code == 201:
                print(f"✅ Alert sent successfully: {incident.get('type')} from {incident.get('ip')}")
                return True
            else:
                print(f"❌ Failed to send alert: {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.ConnectionError:
            print(f"🔴 ERROR: Cannot connect to API at {self.api_url}")
            print("   Ensure Flask backend (app.py) is running!")
            return False
        except Exception as e:
            print(f"❌ Error sending alert: {e}")
            return False
    
    def process_events(self, events: List[Dict]) -> List[Dict]:
        """
        Process new events: add to recent events, run detection, apply containment.
        
        Args:
            events: List of newly parsed events
            
        Returns:
            List of detected incidents
        """
        if not events:
            return []
        
        # Add new events to recent events list
        self.recent_events.extend(events)
        
        # Keep only recent events (limit to max_events)
        if len(self.recent_events) > self.max_events:
            # Keep the most recent events
            self.recent_events = self.recent_events[-self.max_events:]
        
        # Run detection rules on recent events
        incidents = self.detection_engine.detect_incidents(self.recent_events)
        
        return incidents
    
    def handle_incident(self, incident: Dict):
        """
        Handle a detected incident: apply containment and send alert.
        
        Args:
            incident: Detected incident dictionary
        """
        print("\n" + "=" * 60)
        print("🚨 INCIDENT DETECTED")
        print("=" * 60)
        print(f"Type: {incident.get('type')}")
        print(f"Severity: {incident.get('severity')}")
        print(f"IP: {incident.get('ip')}")
        print(f"Target: {incident.get('target')}")
        print(f"Rule: {incident.get('rule')}")
        print(f"Timestamp: {incident.get('timestamp')}")
        if incident.get('attempt_count'):
            print(f"Attempt Count: {incident.get('attempt_count')}")
        print("=" * 60)
        
        # Apply containment actions
        containment_results = self.containment.apply_containment(incident)
        
        if containment_results.get('ip_blocked'):
            print("✅ IP blocking action completed")
        if containment_results.get('process_killed'):
            print("✅ Process termination action completed")
        
        # Send alert to API
        print("\n📤 Sending alert to API backend...")
        success = self.send_alert_to_api(incident)
        
        if success:
            print("✅ Incident handling complete\n")
        else:
            print("⚠️  Incident detected but alert failed to send\n")
    
    def run_once(self):
        """Run one iteration of log monitoring and detection."""
        # Read new log lines
        new_lines, new_position = self.log_parser.read_new_lines(self.last_position)
        self.last_position = new_position
        
        if not new_lines:
            return
        
        # Parse new lines
        new_events = []
        for line in new_lines:
            parsed_event = self.log_parser.parse_log_line(line)
            if parsed_event:
                new_events.append(parsed_event)
        
        if not new_events:
            return
        
        print(f"📊 Parsed {len(new_events)} new authentication events")
        
        # Process events and detect incidents
        incidents = self.process_events(new_events)
        
        # Handle each detected incident
        for incident in incidents:
            self.handle_incident(incident)
    
    def start(self):
        """Start the detection agent (runs continuously)."""
        self.running = True
        print("\n🔄 Starting detection agent...")
        print("Press Ctrl+C to stop\n")
        
        try:
            while self.running:
                self.run_once()
                time.sleep(self.check_interval)
        except KeyboardInterrupt:
            print("\n\n🛑 Detection agent stopped by user")
            self.running = False
        except Exception as e:
            print(f"\n❌ Error in detection agent: {e}")
            self.running = False
    
    def stop(self):
        """Stop the detection agent."""
        self.running = False


def main():
    """Main entry point for the detection agent."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Security Incident Detection Agent')
    parser.add_argument(
        '--log-file',
        default='/var/log/auth.log',
        help='Path to auth.log file (default: /var/log/auth.log)'
    )
    parser.add_argument(
        '--api-url',
        default='http://127.0.0.1:5000/api/alert',
        help='Flask API URL (default: http://127.0.0.1:5000/api/alert)'
    )
    parser.add_argument(
        '--simulation',
        action='store_true',
        default=True,
        help='Run in simulation mode (safe, no real actions)'
    )
    parser.add_argument(
        '--no-simulation',
        action='store_false',
        dest='simulation',
        help='Disable simulation mode (WARNING: will execute real iptables/kill commands)'
    )
    parser.add_argument(
        '--interval',
        type=float,
        default=5.0,
        help='Check interval in seconds (default: 5.0)'
    )
    
    args = parser.parse_args()
    
    # Create and start agent
    agent = DetectionAgent(
        log_file=args.log_file,
        api_url=args.api_url,
        simulation_mode=args.simulation,
        check_interval=args.interval
    )
    
    agent.start()


if __name__ == '__main__':
    main()

