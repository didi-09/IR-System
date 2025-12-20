# containment.py (Bayoumy's Detection Engine - Containment Actions)
"""
Containment module for automated response actions.
Implements IP blocking (iptables) and process termination (kill).
Supports configuration-based automation policies.
"""
import subprocess
import os
import sys
import json
from typing import Optional, Dict
from datetime import datetime

class ContainmentActions:
    """Handles automated containment actions for security incidents."""
    
    def __init__(self, simulation_mode: bool = True, config_path: str = None):
        """
        Initialize containment actions.
        
        Args:
            simulation_mode: If True, only simulate actions (safe for testing)
            config_path: Path to config.json (optional)
        """
        self.simulation_mode = simulation_mode
        self.blocked_ips = set()  # Track blocked IPs to avoid duplicates
        self.automation_stats = {
            'ips_blocked': 0,
            'processes_killed': 0,
            'actions_logged': 0
        }
        
        # Load automation policies from config
        self.automation_policies = self._load_automation_policies(config_path)
        self.automation_enabled = self.automation_policies.get('enabled', True)
        
        # Setup logging
        self.log_file = os.path.join(os.path.dirname(__file__), '..', 'server_backend', 'automation.log')
    
    def _load_automation_policies(self, config_path: str = None) -> Dict:
        """Load automation policies from config file."""
        if config_path is None:
            config_path = os.path.join(os.path.dirname(__file__), '..', 'server_backend', 'config.json')
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    return config.get('automation_policies', {'enabled': True, 'actions': {}})
        except Exception as e:
            print(f"Warning: Could not load automation policies: {e}")
        
        # Return default policies if loading fails
        return {
            'enabled': True,
            'actions': {
                'Critical': {'block_ip': True, 'kill_process': False, 'send_email': True},
                'High': {'block_ip': True, 'kill_process': False, 'send_email': True},
                'Medium': {'block_ip': False, 'kill_process': False, 'send_email': False},
                'Low': {'block_ip': False, 'kill_process': False, 'send_email': False}
            }
        }
    
    def _log_action(self, action_type: str, target: str, severity: str, success: bool, reason: str = ""):
        """Log automated action to file."""
        try:
            timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            status = 'SUCCESS' if success else 'FAILED'
            log_entry = f"[{timestamp}] {status} - {action_type} | Target: {target} | Severity: {severity} | Reason: {reason}\n"
            
            with open(self.log_file, 'a') as f:
                f.write(log_entry)
            
            self.automation_stats['actions_logged'] += 1
        except Exception as e:
            print(f"Warning: Could not log action: {e}")
    
    def block_ip(self, ip_address: str, reason: str = "Security Incident") -> bool:
        """
        Block an IP address using iptables.
        
        Args:
            ip_address: IP address to block
            reason: Reason for blocking (for logging)
            
        Returns:
            True if successful, False otherwise
        """
        if ip_address in self.blocked_ips:
            print(f"⚠️  IP {ip_address} is already blocked. Skipping.")
            return True
        
        if self.simulation_mode:
            print(f"[SIMULATION] Would block IP: {ip_address}")
            print(f"  Command: iptables -A INPUT -s {ip_address} -j DROP")
            print(f"  Reason: {reason}")
            self.blocked_ips.add(ip_address)
            return True
        
        try:
            # Check if running on Linux
            if sys.platform != 'linux':
                print(f"⚠️  IP blocking requires Linux. Simulating for {ip_address}")
                self.blocked_ips.add(ip_address)
                return True
            
            # Check if running as root (required for iptables)
            if os.geteuid() != 0:
                print(f"⚠️  IP blocking requires root privileges. Simulating for {ip_address}")
                self.blocked_ips.add(ip_address)
                return True
            
            # Execute iptables command to block IP
            command = ['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP']
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                print(f"✅ Successfully blocked IP: {ip_address} (Reason: {reason})")
                self.blocked_ips.add(ip_address)
                return True
            else:
                print(f"❌ Failed to block IP {ip_address}: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"❌ Timeout while blocking IP {ip_address}")
            return False
        except FileNotFoundError:
            print(f"⚠️  iptables not found. Simulating for {ip_address}")
            self.blocked_ips.add(ip_address)
            return True
        except Exception as e:
            print(f"❌ Error blocking IP {ip_address}: {e}")
            return False
    
    def kill_process(self, pid: str, reason: str = "Suspicious Activity") -> bool:
        """
        Kill a process by PID.
        
        Args:
            pid: Process ID to kill
            reason: Reason for killing (for logging)
            
        Returns:
            True if successful, False otherwise
        """
        if not pid:
            print("⚠️  No PID provided for process termination.")
            return False
        
        if self.simulation_mode:
            print(f"[SIMULATION] Would kill process: PID {pid}")
            print(f"  Command: kill -9 {pid}")
            print(f"  Reason: {reason}")
            return True
        
        try:
            # Check if running on Linux/Unix
            if sys.platform not in ['linux', 'darwin', 'freebsd']:
                print(f"⚠️  Process killing requires Unix-like OS. Simulating for PID {pid}")
                return True
            
            # Check if we have permission to kill the process
            # Try to send SIGTERM first (graceful), then SIGKILL if needed
            try:
                # Check if process exists
                subprocess.run(['kill', '-0', pid], check=True, timeout=2)
                
                # Try graceful termination first
                result = subprocess.run(
                    ['kill', '-TERM', pid],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    print(f"✅ Sent SIGTERM to process PID {pid} (Reason: {reason})")
                    return True
                else:
                    # If SIGTERM fails, try SIGKILL
                    result = subprocess.run(
                        ['kill', '-9', pid],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0:
                        print(f"✅ Force killed process PID {pid} (Reason: {reason})")
                        return True
                    else:
                        print(f"❌ Failed to kill process PID {pid}: {result.stderr}")
                        return False
                        
            except subprocess.CalledProcessError:
                print(f"⚠️  Process PID {pid} does not exist or cannot be accessed.")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"❌ Timeout while killing process PID {pid}")
            return False
        except Exception as e:
            print(f"❌ Error killing process PID {pid}: {e}")
            return False
    
    def apply_containment(self, incident: Dict) -> Dict[str, bool]:
        """
        Apply appropriate containment actions based on incident severity and automation policies.
        
        Args:
            incident: Incident dictionary with severity, ip, pid, etc.
            
        Returns:
            Dictionary with action results
        """
        results = {
            'ip_blocked': False,
            'process_killed': False,
            'automation_enabled': self.automation_enabled
        }
        
        # Check if automation is globally enabled
        if not self.automation_enabled:
            print("ℹ️  Automation is disabled. No containment actions will be taken.")
            return results
        
        severity = incident.get('severity', 'Medium')
        ip = incident.get('ip')
        pid = incident.get('pid')
        
        # Get automation policy for this severity level
        severity_policy = self.automation_policies.get('actions', {}).get(severity, {})
        
        if not severity_policy:
            print(f"⚠️  No automation policy defined for severity: {severity}")
            return results
        
        # Apply IP blocking if policy allows
        if severity_policy.get('block_ip', False) and ip:
            success = self.block_ip(
                ip,
                reason=f"{incident.get('type', 'Security Incident')} - {incident.get('rule', 'Rule Triggered')}"
            )
            results['ip_blocked'] = success
            if success:
                self.automation_stats['ips_blocked'] += 1
            self._log_action('BLOCK_IP', ip, severity, success, incident.get('rule', ''))
        
        # Apply process termination if policy allows
        if severity_policy.get('kill_process', False) and pid:
            success = self.kill_process(
                pid,
                reason=f"{incident.get('type', 'Security Incident')} - {severity} severity"
            )
            results['process_killed'] = success
            if success:
                self.automation_stats['processes_killed'] += 1
            self._log_action('KILL_PROCESS', str(pid), severity, success, incident.get('rule', ''))
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get automation statistics."""
        return self.automation_stats.copy()
    
    def get_blocked_ips(self) -> list:
        """Get list of currently blocked IPs."""
        return list(self.blocked_ips)
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock a previously blocked IP address.
        
        Args:
            ip_address: IP address to unblock
            
        Returns:
            True if successful, False otherwise
        """
        if self.simulation_mode:
            print(f"[SIMULATION] Would unblock IP: {ip_address}")
            print(f"  Command: iptables -D INPUT -s {ip_address} -j DROP")
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
            return True
        
        try:
            if sys.platform != 'linux' or os.geteuid() != 0:
                print(f"⚠️  IP unblocking requires Linux root. Simulating for {ip_address}")
                if ip_address in self.blocked_ips:
                    self.blocked_ips.remove(ip_address)
                return True
            
            command = ['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP']
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                print(f"✅ Successfully unblocked IP: {ip_address}")
                if ip_address in self.blocked_ips:
                    self.blocked_ips.remove(ip_address)
                return True
            else:
                print(f"⚠️  IP {ip_address} may not be in iptables rules: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error unblocking IP {ip_address}: {e}")
            return False

