# containment.py (Bayoumy's Detection Engine - Containment Actions)
"""
Containment module for automated response actions.
Implements IP blocking (iptables) and process termination (kill).
Currently runs in simulation mode for safety.
"""
import subprocess
import os
import sys
from typing import Optional, Dict

class ContainmentActions:
    """Handles automated containment actions for security incidents."""
    
    def __init__(self, simulation_mode: bool = True):
        """
        Initialize containment actions.
        
        Args:
            simulation_mode: If True, only simulate actions (safe for testing)
        """
        self.simulation_mode = simulation_mode
        self.blocked_ips = set()  # Track blocked IPs to avoid duplicates
    
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
        Apply appropriate containment actions based on incident severity.
        
        Args:
            incident: Incident dictionary with severity, ip, pid, etc.
            
        Returns:
            Dictionary with action results
        """
        results = {
            'ip_blocked': False,
            'process_killed': False
        }
        
        severity = incident.get('severity', 'Medium')
        ip = incident.get('ip')
        pid = incident.get('pid')
        
        # For High and Critical incidents, apply containment
        if severity in ['High', 'Critical']:
            # Block IP for High/Critical incidents
            if ip:
                results['ip_blocked'] = self.block_ip(
                    ip,
                    reason=f"{incident.get('type', 'Security Incident')} - {incident.get('rule', 'Rule Triggered')}"
                )
            
            # Kill process for Critical incidents only
            if severity == 'Critical' and pid:
                results['process_killed'] = self.kill_process(
                    pid,
                    reason=f"{incident.get('type', 'Security Incident')} - Critical severity"
                )
        
        return results
    
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

