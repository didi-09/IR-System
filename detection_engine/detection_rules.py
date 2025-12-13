# detection_rules.py (Bayoumy's Detection Engine - Detection Rules)
"""
Detection rules module for identifying security incidents.
Implements the core detection logic (e.g., 3 failed logins in 60 seconds).
"""
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict

class DetectionRule:
    """Base class for detection rules."""
    
    def __init__(self, rule_name: str, incident_type: str, severity: str):
        """
        Initialize a detection rule.
        
        Args:
            rule_name: Name of the rule
            incident_type: Type of incident this rule detects
            severity: Severity level (Low, Medium, High, Critical)
        """
        self.rule_name = rule_name
        self.incident_type = incident_type
        self.severity = severity
    
    def check(self, events: List[Dict]) -> Optional[Dict]:
        """
        Check if events match this rule's criteria.
        
        Args:
            events: List of parsed log events
            
        Returns:
            Incident dictionary if rule triggered, None otherwise
        """
        raise NotImplementedError("Subclasses must implement check()")


class BruteForceRule(DetectionRule):
    """
    Detects brute force attacks: 3 or more failed login attempts 
    from the same IP within 60 seconds.
    """
    
    def __init__(self, threshold: int = 3, time_window_seconds: int = 60):
        """
        Initialize brute force detection rule.
        
        Args:
            threshold: Number of failed attempts to trigger (default: 3)
            time_window_seconds: Time window in seconds (default: 60)
        """
        super().__init__(
            rule_name="Failed Login Count Exceeded",
            incident_type="Brute Force",
            severity="High"
        )
        self.threshold = threshold
        self.time_window = timedelta(seconds=time_window_seconds)
    
    def check(self, events: List[Dict]) -> Optional[Dict]:
        """
        Check for brute force patterns in events.
        
        Args:
            events: List of parsed log events
            
        Returns:
            Incident dictionary if brute force detected, None otherwise
        """
        # Filter for failed login and invalid user events
        failed_events = [
            e for e in events 
            if e.get('type') in ['failed_login', 'invalid_user']
        ]
        
        if len(failed_events) < self.threshold:
            return None
        
        # Group by IP address
        ip_groups = defaultdict(list)
        for event in failed_events:
            ip_groups[event['ip']].append(event)
        
        # Check each IP for threshold violations
        for ip, ip_events in ip_groups.items():
            if len(ip_events) < self.threshold:
                continue
            
            # Sort by timestamp
            ip_events.sort(key=lambda x: x['timestamp'])
            
            # Check for threshold within time window
            for i in range(len(ip_events) - self.threshold + 1):
                window_start = ip_events[i]['timestamp']
                window_end = window_start + self.time_window
                
                # Count events in this window
                window_events = [
                    e for e in ip_events[i:]
                    if window_start <= e['timestamp'] <= window_end
                ]
                
                if len(window_events) >= self.threshold:
                    # Get the most recent event in the window
                    latest_event = max(window_events, key=lambda x: x['timestamp'])
                    
                    # Determine target (most common target in window)
                    targets = [e['target'] for e in window_events]
                    most_common_target = max(set(targets), key=targets.count)
                    
                    return {
                        'ip': ip,
                        'type': self.incident_type,
                        'severity': self.severity,
                        'timestamp': latest_event['timestamp'].isoformat(),
                        'rule': self.rule_name,
                        'source_log': '/var/log/auth.log',
                        'target': most_common_target,
                        'attempt_count': len(window_events),
                        'pid': latest_event.get('pid')
                    }
        
        return None


class RapidLoginAttemptsRule(DetectionRule):
    """
    Detects rapid login attempts (more aggressive than brute force):
    10 or more failed attempts in 30 seconds.
    """
    
    def __init__(self, threshold: int = 10, time_window_seconds: int = 30):
        """
        Initialize rapid login attempts rule.
        
        Args:
            threshold: Number of failed attempts to trigger (default: 10)
            time_window_seconds: Time window in seconds (default: 30)
        """
        super().__init__(
            rule_name="Rapid Login Attempts Detected",
            incident_type="Brute Force",
            severity="Critical"
        )
        self.threshold = threshold
        self.time_window = timedelta(seconds=time_window_seconds)
    
    def check(self, events: List[Dict]) -> Optional[Dict]:
        """Check for rapid login attempts."""
        failed_events = [
            e for e in events 
            if e.get('type') in ['failed_login', 'invalid_user']
        ]
        
        if len(failed_events) < self.threshold:
            return None
        
        # Group by IP
        ip_groups = defaultdict(list)
        for event in failed_events:
            ip_groups[event['ip']].append(event)
        
        for ip, ip_events in ip_groups.items():
            if len(ip_events) < self.threshold:
                continue
            
            ip_events.sort(key=lambda x: x['timestamp'])
            
            # Check sliding window
            for i in range(len(ip_events) - self.threshold + 1):
                window_start = ip_events[i]['timestamp']
                window_end = window_start + self.time_window
                
                window_events = [
                    e for e in ip_events[i:]
                    if window_start <= e['timestamp'] <= window_end
                ]
                
                if len(window_events) >= self.threshold:
                    latest_event = max(window_events, key=lambda x: x['timestamp'])
                    targets = [e['target'] for e in window_events]
                    most_common_target = max(set(targets), key=targets.count)
                    
                    return {
                        'ip': ip,
                        'type': self.incident_type,
                        'severity': self.severity,
                        'timestamp': latest_event['timestamp'].isoformat(),
                        'rule': self.rule_name,
                        'source_log': '/var/log/auth.log',
                        'target': most_common_target,
                        'attempt_count': len(window_events),
                        'pid': latest_event.get('pid')
                    }
        
        return None


class DetectionEngine:
    """Main detection engine that runs all detection rules."""
    
    def __init__(self):
        """Initialize detection engine with default rules."""
        self.rules = [
            BruteForceRule(threshold=3, time_window_seconds=60),
            RapidLoginAttemptsRule(threshold=10, time_window_seconds=30)
        ]
    
    def add_rule(self, rule: DetectionRule):
        """Add a custom detection rule."""
        self.rules.append(rule)
    
    def detect_incidents(self, events: List[Dict]) -> List[Dict]:
        """
        Run all detection rules on events and return detected incidents.
        
        Args:
            events: List of parsed log events
            
        Returns:
            List of detected incidents
        """
        incidents = []
        
        for rule in self.rules:
            incident = rule.check(events)
            if incident:
                incidents.append(incident)
        
        return incidents

