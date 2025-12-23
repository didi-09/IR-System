# log_discovery.py (Bayoumy's Detection Engine - Log Discovery)
"""
Automatic log file discovery module.
Scans /var/log for readable log files and detects their types.
"""
import os
import glob
from typing import List, Dict, Optional
from pathlib import Path


class LogDiscovery:
    """Discovers and identifies available log files on the system."""
    
    def __init__(self, base_path: str = "/var/log"):
        """
        Initialize log discovery.
        
        Args:
            base_path: Base directory to scan for logs (default: /var/log)
        """
        self.base_path = base_path
        self.discovered_logs = []
    
    def is_readable(self, file_path: str) -> bool:
        """
        Check if a file is readable.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if readable, False otherwise
        """
        try:
            with open(file_path, 'r') as f:
                f.read(1)
            return True
        except (PermissionError, FileNotFoundError, IsADirectoryError, UnicodeDecodeError):
            return False
    
    def detect_log_type(self, file_path: str) -> Optional[str]:
        """
        Detect the type of log file based on path and content.
        
        Args:
            file_path: Path to log file
            
        Returns:
            Log type string or None
        """
        filename = os.path.basename(file_path)
        
        # Authentication logs
        if 'auth.log' in filename:
            return 'auth'
        
        # Syslog
        if filename == 'syslog' or filename.startswith('syslog.'):
            return 'syslog'
        
        # Kernel logs
        if filename.startswith('kern.log'):
            return 'kernel'
        
        # Web server logs
        if 'apache2' in file_path:
            if 'access.log' in filename:
                return 'apache_access'
            elif 'error.log' in filename:
                return 'apache_error'
            elif 'other_vhosts_access.log' in filename:
                return 'apache_access'
        
        if 'nginx' in file_path:
            if 'access.log' in filename:
                return 'nginx_access'
            elif 'error.log' in filename:
                return 'nginx_error'
        
        # Database logs
        if 'mysql' in file_path or 'mariadb' in file_path:
            if 'error.log' in filename or 'mariadb.log' in filename:
                return 'mysql'
        
        if 'postgresql' in file_path:
            if filename.endswith('.log'):
                return 'postgresql'
        
        # Generic application logs
        if filename.endswith('.log') and not filename.endswith('.log.1'):
            return 'application'
        
        return None
    
    def discover_logs(self, max_depth: int = 2) -> List[Dict]:
        """
        Discover all available log files.
        
        Args:
            max_depth: Maximum depth to scan subdirectories
            
        Returns:
            List of dictionaries with log file information
        """
        discovered = []
        
        # Common log files to check
        common_logs = [
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/log/kern.log",
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/log/mysql/error.log",
            "/var/log/mariadb/mariadb.log",
        ]
        
        # Check common logs first
        for log_path in common_logs:
            if os.path.exists(log_path) and self.is_readable(log_path):
                log_type = self.detect_log_type(log_path)
                if log_type:
                    discovered.append({
                        'path': log_path,
                        'type': log_type,
                        'size': os.path.getsize(log_path),
                        'priority': 1  # High priority for common logs
                    })
        
        # Scan for additional logs
        try:
            for root, dirs, files in os.walk(self.base_path):
                # Limit depth
                depth = root[len(self.base_path):].count(os.sep)
                if depth >= max_depth:
                    dirs[:] = []
                    continue
                
                for filename in files:
                    file_path = os.path.join(root, filename)
                    
                    # Skip if already discovered
                    if any(d['path'] == file_path for d in discovered):
                        continue
                    
                    # Skip archived/compressed logs
                    if any(file_path.endswith(ext) for ext in ['.gz', '.bz2', '.xz', '.1', '.2', '.3']):
                        continue
                    
                    # Check if it's a log file
                    if not filename.endswith('.log') and 'log' not in filename:
                        continue
                    
                    # Check if readable
                    if not self.is_readable(file_path):
                        continue
                    
                    log_type = self.detect_log_type(file_path)
                    if log_type:
                        discovered.append({
                            'path': file_path,
                            'type': log_type,
                            'size': os.path.getsize(file_path),
                            'priority': 2  # Lower priority for discovered logs
                        })
        
        except PermissionError:
            print(f"⚠️  Permission denied scanning {self.base_path}")
        
        self.discovered_logs = discovered
        return discovered
    
    def get_log_sources_config(self) -> List[Dict]:
        """
        Generate configuration for detected log sources.
        
        Returns:
            List of log source configurations
        """
        if not self.discovered_logs:
            self.discover_logs()
        
        configs = []
        for log in self.discovered_logs:
            config = {
                'type': log['type'],
                'path': log['path'],
                'enabled': True,
                'priority': log['priority']
            }
            configs.append(config)
        
        # Sort by priority (higher priority first)
        configs.sort(key=lambda x: x['priority'])
        
        return configs
    
    def print_discovered_logs(self):
        """Print a summary of discovered logs."""
        if not self.discovered_logs:
            self.discover_logs()
        
        print("\n" + "=" * 70)
        print("🔍 DISCOVERED LOG FILES")
        print("=" * 70)
        
        if not self.discovered_logs:
            print("No readable log files found.")
            return
        
        # Group by type
        by_type = {}
        for log in self.discovered_logs:
            log_type = log['type']
            if log_type not in by_type:
                by_type[log_type] = []
            by_type[log_type].append(log)
        
        for log_type, logs in sorted(by_type.items()):
            print(f"\n📁 {log_type.upper()}")
            for log in logs:
                size_kb = log['size'] / 1024
                priority = "HIGH" if log['priority'] == 1 else "NORMAL"
                print(f"  • {log['path']} ({size_kb:.1f} KB) [Priority: {priority}]")
        
        print(f"\nTotal: {len(self.discovered_logs)} log files discovered")
        print("=" * 70 + "\n")


def discover_available_parsers() -> Dict[str, str]:
    """
    Discover which parsers can be used based on available log files.
    
    Returns:
        Dictionary mapping parser types to log file paths
    """
    discovery = LogDiscovery()
    configs = discovery.get_log_sources_config()
    
    parser_map = {}
    for config in configs:
        if config['enabled']:
            parser_map[config['type']] = config['path']
    
    return parser_map


if __name__ == "__main__":
    # Test log discovery
    discovery = LogDiscovery()
    discovery.print_discovered_logs()
    
    print("\nGenerated configuration:")
    configs = discovery.get_log_sources_config()
    for config in configs[:5]:  # Show first 5
        print(f"  {config['type']}: {config['path']}")
