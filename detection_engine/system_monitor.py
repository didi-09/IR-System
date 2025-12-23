# system_monitor.py (Bayoumy's Detection Engine - Active System Monitoring)
"""
Active system monitoring module for real-time detection of system events.
Monitors processes, services, resources, and file system changes.
"""
import threading
import time
import os
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Callable
from collections import defaultdict

try:
    import psutil
except ImportError:
    print("⚠️  psutil not installed. System monitoring will be limited.")
    psutil = None


class ResourceMonitor(threading.Thread):
    """Monitor system resource usage (CPU, memory, disk)."""
    
    def __init__(self, interval: int = 60, callback: Optional[Callable] = None):
        """
        Initialize resource monitor.
        
        Args:
            interval: Check interval in seconds
            callback: Function to call when threshold exceeded
        """
        super().__init__()
        self.interval = interval
        self.callback = callback
        self.running = False
        self.daemon = True
        
        # Thresholds
        self.cpu_threshold = 90.0
        self.memory_threshold = 90.0
        self.disk_threshold = 90.0
    
    def run(self):
        """Monitor resources continuously."""
        if not psutil:
            print("⚠️  ResourceMonitor disabled: psutil not installed")
            return
        
        print("🔄 ResourceMonitor started")
        self.running = True
        
        while self.running:
            try:
                # Check CPU
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > self.cpu_threshold:
                    event = {
                        'timestamp': datetime.utcnow(),
                        'event_type': 'high_cpu_usage',
                        'cpu_percent': cpu_percent,
                        'severity': 'High',
                        'category': 'resource',
                        'message': f'CPU usage at {cpu_percent}%'
                    }
                    if self.callback:
                        self.callback(event)
                
                # Check memory
                memory = psutil.virtual_memory()
                if memory.percent > self.memory_threshold:
                    event = {
                        'timestamp': datetime.utcnow(),
                        'event_type': 'high_memory_usage',
                        'memory_percent': memory.percent,
                        'severity': 'High',
                        'category': 'resource',
                        'message': f'Memory usage at {memory.percent}%'
                    }
                    if self.callback:
                        self.callback(event)
                
                # Check disk
                for partition in psutil.disk_partitions():
                    # Skip virtual/pseudo filesystems
                    if partition.fstype in ['tmpfs', 'devtmpfs', 'squashfs', 'overlay']:
                        continue
                    # Skip mount points that are not real disks
                    if partition.mountpoint.startswith(('/sys', '/proc', '/dev', '/run')):
                        continue
                        
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        if usage.percent > self.disk_threshold:
                            event = {
                                'timestamp': datetime.utcnow(),
                                'event_type': 'high_disk_usage',
                                'disk_percent': usage.percent,
                                'mountpoint': partition.mountpoint,
                                'severity': 'Critical' if usage.percent > 95 else 'High',
                                'category': 'resource',
                                'message': f'Disk usage at {usage.percent}% on {partition.mountpoint}'
                            }
                            if self.callback:
                                self.callback(event)
                    except PermissionError:
                        continue
                
            except Exception as e:
                print(f"Error in ResourceMonitor: {e}")
            
            time.sleep(self.interval)
    
    def stop(self):
        """Stop the monitor."""
        self.running = False


class ProcessMonitor(threading.Thread):
    """Monitor process creation and termination."""
    
    def __init__(self, interval: int = 10, callback: Optional[Callable] = None):
        """
        Initialize process monitor.
        
        Args:
            interval: Check interval in seconds
            callback: Function to call on process events
        """
        super().__init__()
        self.interval = interval
        self.callback = callback
        self.running = False
        self.daemon = True
        self.known_pids = set()
        
        # Suspicious process names
        self.suspicious_processes = [
            'nc', 'netcat', 'ncat',  # Network utilities
            'nmap', 'masscan',  # Port scanners
            'hydra', 'medusa',  # Brute force tools
            'sqlmap',  # SQL injection
            'metasploit', 'msfconsole',  # Exploitation frameworks
        ]
    
    def run(self):
        """Monitor processes continuously."""
        if not psutil:
            print("⚠️  ProcessMonitor disabled: psutil not installed")
            return
        
        print("🔄 ProcessMonitor started")
        self.running = True
        
        # Initialize known PIDs
        try:
            self.known_pids = set(p.pid for p in psutil.process_iter())
        except:
            pass
        
        while self.running:
            try:
                current_pids = set()
                
                for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                    try:
                        pid = proc.info['pid']
                        current_pids.add(pid)
                        
                        # Check for new processes
                        if pid not in self.known_pids:
                            name = proc.info['name']
                            
                            # Check if suspicious
                            is_suspicious = any(susp in name.lower() for susp in self.suspicious_processes)
                            
                            event = {
                                'timestamp': datetime.utcnow(),
                                'event_type': 'process_started',
                                'pid': pid,
                                'process_name': name,
                                'user': proc.info.get('username', 'unknown'),
                                'cmdline': ' '.join(proc.info.get('cmdline', [])),
                                'severity': 'Critical' if is_suspicious else 'Low',
                                'category': 'process',
                                'suspicious': is_suspicious
                            }
                            
                            if is_suspicious and self.callback:
                                self.callback(event)
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Detect terminated processes (optional, commented out to reduce noise)
                # terminated = self.known_pids - current_pids
                
                self.known_pids = current_pids
                
            except Exception as e:
                print(f"Error in ProcessMonitor: {e}")
            
            time.sleep(self.interval)
    
    def stop(self):
        """Stop the monitor."""
        self.running = False


class ServiceMonitor(threading.Thread):
    """Monitor systemd service status changes."""
    
    def __init__(self, interval: int = 30, callback: Optional[Callable] = None):
        """
        Initialize service monitor.
        
        Args:
            interval: Check interval in seconds
            callback: Function to call on service events
        """
        super().__init__()
        self.interval = interval
        self.callback = callback
        self.running = False
        self.daemon = True
        self.service_states = {}
        
        # Critical services to monitor
        self.critical_services = [
            'ssh', 'sshd',
            'apache2', 'nginx',
            'mysql', 'mariadb', 'postgresql',
            'docker', 'containerd',
        ]
    
    def get_service_status(self, service: str) -> Optional[str]:
        """
        Get status of a systemd service.
        
        Args:
            service: Service name
            
        Returns:
            Service status or None
        """
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', service],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip()
        except Exception:
            return None
    
    def run(self):
        """Monitor services continuously."""
        print("🔄 ServiceMonitor started")
        self.running = True
        
        # Initialize service states
        for service in self.critical_services:
            status = self.get_service_status(service)
            if status:
                self.service_states[service] = status
        
        while self.running:
            try:
                for service in self.critical_services:
                    current_status = self.get_service_status(service)
                    
                    if not current_status:
                        continue
                    
                    previous_status = self.service_states.get(service)
                    
                    # Detect status change
                    if previous_status and current_status != previous_status:
                        severity = 'High'
                        event_type = 'service_status_changed'
                        
                        # Higher severity if service failed
                        if current_status == 'failed':
                            severity = 'Critical'
                            event_type = 'service_failed'
                        elif current_status == 'inactive' and previous_status == 'active':
                            severity = 'High'
                            event_type = 'service_stopped'
                        
                        event = {
                            'timestamp': datetime.utcnow(),
                            'event_type': event_type,
                            'service': service,
                            'previous_status': previous_status,
                            'current_status': current_status,
                            'severity': severity,
                            'category': 'service'
                        }
                        
                        if self.callback:
                            self.callback(event)
                    
                    self.service_states[service] = current_status
                
            except Exception as e:
                print(f"Error in ServiceMonitor: {e}")
            
            time.sleep(self.interval)
    
    def stop(self):
        """Stop the monitor."""
        self.running = False


class FileSystemMonitor:
    """Monitor file system changes in critical directories."""
    
    def __init__(self, watch_paths: Optional[List[str]] = None):
        """
        Initialize file system monitor.
        
        Args:
            watch_paths: List of paths to monitor
        """
        self.watch_paths = watch_paths or [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/sudoers',
            '/etc/ssh/sshd_config',
        ]
        self.file_stats = {}
        
        # Initialize file stats
        for path in self.watch_paths:
            if os.path.exists(path):
                try:
                    stat = os.stat(path)
                    self.file_stats[path] = {
                        'mtime': stat.st_mtime,
                        'size': stat.st_size,
                        'mode': stat.st_mode
                    }
                except PermissionError:
                    pass
    
    def check_changes(self) -> List[Dict]:
        """
        Check for file system changes.
        
        Returns:
            List of change events
        """
        changes = []
        
        for path in self.watch_paths:
            if not os.path.exists(path):
                continue
            
            try:
                stat = os.stat(path)
                current_stats = {
                    'mtime': stat.st_mtime,
                    'size': stat.st_size,
                    'mode': stat.st_mode
                }
                
                if path in self.file_stats:
                    previous_stats = self.file_stats[path]
                    
                    # Check for modifications
                    if current_stats['mtime'] != previous_stats['mtime']:
                        changes.append({
                            'timestamp': datetime.utcnow(),
                            'event_type': 'file_modified',
                            'file_path': path,
                            'severity': 'Critical' if 'passwd' in path or 'shadow' in path else 'High',
                            'category': 'filesystem',
                            'previous_size': previous_stats['size'],
                            'current_size': current_stats['size']
                        })
                    
                    # Check for permission changes
                    if current_stats['mode'] != previous_stats['mode']:
                        changes.append({
                            'timestamp': datetime.utcnow(),
                            'event_type': 'permissions_changed',
                            'file_path': path,
                            'severity': 'High',
                            'category': 'filesystem',
                            'previous_mode': oct(previous_stats['mode']),
                            'current_mode': oct(current_stats['mode'])
                        })
                
                self.file_stats[path] = current_stats
            
            except PermissionError:
                continue
        
        return changes


class SystemMonitorManager:
    """Manages all system monitors."""
    
    def __init__(self, event_callback: Optional[Callable] = None):
        """
        Initialize system monitor manager.
        
        Args:
            event_callback: Function to call when events are detected
        """
        self.event_callback = event_callback
        self.monitors = []
        
        # Initialize monitors
        self.resource_monitor = ResourceMonitor(interval=60, callback=self.handle_event)
        self.process_monitor = ProcessMonitor(interval=10, callback=self.handle_event)
        self.service_monitor = ServiceMonitor(interval=30, callback=self.handle_event)
        self.filesystem_monitor = FileSystemMonitor()
        
        self.monitors = [
            self.resource_monitor,
            self.process_monitor,
            self.service_monitor,
        ]
    
    def handle_event(self, event: Dict):
        """
        Handle events from monitors.
        
        Args:
            event: Event dictionary
        """
        if self.event_callback:
            self.event_callback(event)
        else:
            # Default: print event
            print(f"🚨 {event['event_type']}: {event.get('message', '')}")
    
    def start_all(self):
        """Start all monitors."""
        print("\n🔄 Starting system monitors...")
        for monitor in self.monitors:
            monitor.start()
        print("✅ All system monitors started\n")
    
    def stop_all(self):
        """Stop all monitors."""
        print("\n🛑 Stopping system monitors...")
        for monitor in self.monitors:
            monitor.stop()
        print("✅ All system monitors stopped\n")
    
    def check_filesystem(self) -> List[Dict]:
        """
        Check for file system changes.
        
        Returns:
            List of change events
        """
        return self.filesystem_monitor.check_changes()


if __name__ == "__main__":
    # Test system monitoring
    def test_callback(event):
        print(f"📊 Event: {event['event_type']} - {event.get('message', '')} (Severity: {event['severity']})")
    
    manager = SystemMonitorManager(event_callback=test_callback)
    manager.start_all()
    
    try:
        print("Monitoring system... Press Ctrl+C to stop")
        while True:
            # Check filesystem periodically
            fs_changes = manager.check_filesystem()
            for change in fs_changes:
                test_callback(change)
            
            time.sleep(30)
    except KeyboardInterrupt:
        manager.stop_all()
        print("\nMonitoring stopped.")
