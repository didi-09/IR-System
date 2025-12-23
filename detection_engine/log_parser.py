# log_parser.py (Bayoumy's Detection Engine - Log Parsing)
"""
Unified log parsing module for extracting security-relevant information from system logs.
Supports multiple log sources: auth, syslog, kernel, web servers, databases.
"""
import re
import subprocess
import select
import os
from datetime import datetime
from typing import Dict, Optional, List, Tuple
from abc import ABC, abstractmethod


class BaseLogParser(ABC):
    """Base class for all log parsers with common functionality."""
    
    def __init__(self, log_file_path: str = None):
        """
        Initialize the base log parser.
        
        Args:
            log_file_path: Path to the log file
        """
        self.log_file_path = log_file_path
        self.current_year = datetime.now().year
    
    def parse_timestamp(self, log_timestamp: str, fmt: str = "%b %d %H:%M:%S %Y") -> Optional[datetime]:
        """
        Parse timestamp from log line.
        
        Args:
            log_timestamp: Timestamp string from log
            fmt: Format string for strptime
            
        Returns:
            datetime object or None if parsing fails
        """
        try:
            # Add current year if not present
            if '%Y' not in fmt and len(log_timestamp.split()) == 3: # e.g., "Dec 12 10:30:00"
                full_timestamp = f"{log_timestamp} {self.current_year}"
                fmt = "%b %d %H:%M:%S %Y"
            else:
                full_timestamp = log_timestamp
            return datetime.strptime(full_timestamp, fmt)
        except ValueError:
            return None
    
    def read_new_lines(self, last_position: int = 0) -> Tuple[List[str], int]:
        """
        Read new lines from the log file since last_position.
        
        Args:
            last_position: Byte position where we last read from
            
        Returns:
            Tuple of (new_lines, new_position)
        """
        if not self.log_file_path or not os.path.exists(self.log_file_path):
            return [], last_position
        
        try:
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                new_position = f.tell()
                return new_lines, new_position
        except (FileNotFoundError, PermissionError) as e:
            # print(f"Warning: Could not read log file {self.log_file_path}: {e}. Using simulation mode.")
            return [], last_position
    
    @abstractmethod
    def parse_log_line(self, log_line: str) -> Optional[Dict]:
        """
        Parse a log line and extract relevant information.
        Must be implemented by subclasses.
        
        Args:
            log_line: Log line to parse
            
        Returns:
            Parsed event dictionary or None
        """
        pass


class AuthLogParser(BaseLogParser):
    """Parser for /var/log/auth.log to extract authentication events."""
    
    # Common patterns in auth.log
    FAILED_LOGIN_PATTERN = re.compile(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?sshd.*?Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)'
    )
    
    SUCCESSFUL_LOGIN_PATTERN = re.compile(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?sshd.*?Accepted (?:password|publickey) for (\S+) from ([\d.]+)'
    )
    
    INVALID_USER_PATTERN = re.compile(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?sshd.*?Invalid user (\S+) from ([\d.]+)'
    )
    
    PROCESS_PATTERN = re.compile(r'\[pid\s+(\d+)\]')
    
    def __init__(self, log_file_path: str = "/var/log/auth.log"):
        """
        Initialize the log parser.
        
        Args:
            log_file_path: Path to the auth.log file
        """
        super().__init__(log_file_path)
    
    def parse_timestamp(self, log_timestamp: str) -> Optional[datetime]:
        """
        Parse timestamp from log line.
        Format: "Dec 12 10:30:00"
        
        Args:
            log_timestamp: Timestamp string from log
            
        Returns:
            datetime object or None if parsing fails
        """
        try:
            # Add current year since logs don't include it
            full_timestamp = f"{log_timestamp} {self.current_year}"
            return datetime.strptime(full_timestamp, "%b %d %H:%M:%S %Y")
        except ValueError:
            return None
    
    def extract_pid(self, log_line: str) -> Optional[str]:
        """
        Extract process ID from log line if present.
        
        Args:
            log_line: Full log line
            
        Returns:
            PID as string or None
        """
        match = self.PROCESS_PATTERN.search(log_line)
        return match.group(1) if match else None
    
    def parse_failed_login(self, log_line: str) -> Optional[Dict]:
        """
        Parse a failed login attempt from auth.log.
        
        Args:
            log_line: Log line to parse
            
        Returns:
            Dictionary with parsed data or None
        """
        match = self.FAILED_LOGIN_PATTERN.search(log_line)
        if not match:
            return None
        
        timestamp_str, username, ip_address, port = match.groups()
        timestamp = self.parse_timestamp(timestamp_str)
        pid = self.extract_pid(log_line)
        
        if not timestamp:
            return None
        
        return {
            'timestamp': timestamp,
            'ip': ip_address,
            'target': username,
            'type': 'failed_login',
            'port': port,
            'pid': pid,
            'raw_line': log_line.strip()
        }
    
    def parse_successful_login(self, log_line: str) -> Optional[Dict]:
        """
        Parse a successful login from auth.log.
        
        Args:
            log_line: Log line to parse
            
        Returns:
            Dictionary with parsed data or None
        """
        match = self.SUCCESSFUL_LOGIN_PATTERN.search(log_line)
        if not match:
            return None
        
        timestamp_str, username, ip_address = match.groups()
        timestamp = self.parse_timestamp(timestamp_str)
        pid = self.extract_pid(log_line)
        
        if not timestamp:
            return None
        
        return {
            'timestamp': timestamp,
            'ip': ip_address,
            'target': username,
            'type': 'successful_login',
            'pid': pid,
            'raw_line': log_line.strip()
        }
    
    def parse_invalid_user(self, log_line: str) -> Optional[Dict]:
        """
        Parse an invalid user attempt from auth.log.
        
        Args:
            log_line: Log line to parse
            
        Returns:
            Dictionary with parsed data or None
        """
        match = self.INVALID_USER_PATTERN.search(log_line)
        if not match:
            return None
        
        timestamp_str, username, ip_address = match.groups()
        timestamp = self.parse_timestamp(timestamp_str)
        pid = self.extract_pid(log_line)
        
        if not timestamp:
            return None
        
        return {
            'timestamp': timestamp,
            'ip': ip_address,
            'target': username,
            'type': 'invalid_user',
            'pid': pid,
            'raw_line': log_line.strip()
        }
    
    def read_new_lines(self, last_position: int = 0) -> tuple[List[str], int]:
        """
        Read new lines from the log file since last_position.
        
        Args:
            last_position: Byte position where we last read from
            
        Returns:
            Tuple of (new_lines, new_position)
        """
        try:
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                new_position = f.tell()
                return new_lines, new_position
        except FileNotFoundError:
            print(f"Warning: Log file {self.log_file_path} not found. Using simulation mode.")
            return [], last_position
        except PermissionError:
            print(f"Warning: Permission denied reading {self.log_file_path}. Using simulation mode.")
            return [], last_position
    
    def parse_log_line(self, log_line: str) -> Optional[Dict]:
        """
        Parse any type of authentication event from a log line.
        
        Args:
            log_line: Log line to parse
            
        Returns:
            Parsed event dictionary or None
        """
        # Try different parsers in order of priority
        parsed = self.parse_failed_login(log_line)
        if parsed:
            return parsed
        
        parsed = self.parse_invalid_user(log_line)
        if parsed:
            return parsed
        
        parsed = self.parse_successful_login(log_line)
        if parsed:
            return parsed
        
        return None


class SyslogParser(BaseLogParser):
    """Parser for /var/log/syslog to extract system events."""
    
    # Patterns for common syslog events
    SERVICE_START_PATTERN = re.compile(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?systemd\[\d+\]:\s*Started\s+(.+?)\.$'
    )
    SERVICE_STOP_PATTERN = re.compile(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?systemd\[\d+\]:\s*Stopped\s+(.+?)\.$'
    )
    SERVICE_FAILED_PATTERN = re.compile(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?systemd\[\d+\]:\s*(.+?)\s+failed'
    )
    CRON_PATTERN = re.compile(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?CRON\[(\d+)\].*?\((.+?)\)\s+CMD\s+\((.+?)\)'
    )
    
    def __init__(self, log_file_path: str = "/var/log/syslog"):
        super().__init__(log_file_path)
    
    def parse_log_line(self, log_line: str) -> Optional[Dict]:
        """
        Parse syslog events.
        
        Args:
            log_line: Log line to parse
            
        Returns:
            Parsed event dictionary or None
        """
        # Try service start
        match = self.SERVICE_START_PATTERN.search(log_line)
        if match:
            timestamp_str, service = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            if timestamp:
                return {
                    'timestamp': timestamp,
                    'event_type': 'service_start',
                    'service': service,
                    'severity': 'Low',
                    'category': 'system',
                    'raw_line': log_line.strip()
                }
        
        # Try service stop
        match = self.SERVICE_STOP_PATTERN.search(log_line)
        if match:
            timestamp_str, service = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            if timestamp:
                return {
                    'timestamp': timestamp,
                    'event_type': 'service_stop',
                    'service': service,
                    'severity': 'Low',
                    'category': 'system',
                    'raw_line': log_line.strip()
                }
        
        # Try service failed
        match = self.SERVICE_FAILED_PATTERN.search(log_line)
        if match:
            timestamp_str, service = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            if timestamp:
                return {
                    'timestamp': timestamp,
                    'event_type': 'service_failed',
                    'service': service,
                    'severity': 'High',
                    'category': 'system',
                    'raw_line': log_line.strip()
                }
        
        # Try cron job
        match = self.CRON_PATTERN.search(log_line)
        if match:
            timestamp_str, pid, user, command = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            if timestamp:
                return {
                    'timestamp': timestamp,
                    'event_type': 'cron_job',
                    'user': user,
                    'command': command,
                    'pid': pid,
                    'severity': 'Low',
                    'category': 'system',
                    'raw_line': log_line.strip()
                }
        
        return None


class KernelLogParser(BaseLogParser):
    """Parser for /var/log/kern.log to extract kernel events."""
    
    # Patterns for kernel events
    KERNEL_ERROR_PATTERN = re.compile(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?kernel:.*?\[.*?\]\s+(.*?error.*?)$',
        re.IGNORECASE
    )
    KERNEL_WARNING_PATTERN = re.compile(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?kernel:.*?\[.*?\]\s+(.*?warning.*?)$',
        re.IGNORECASE
    )
    USB_DEVICE_PATTERN = re.compile(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?kernel:.*?usb.*?New USB device found.*?idVendor=([0-9a-fA-F]+).*?idProduct=([0-9a-fA-F]+)'
    )
    OOM_KILLER_PATTERN = re.compile(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?kernel:.*?Out of memory.*?Kill process (\d+)'
    )
    
    def __init__(self, log_file_path: str = "/var/log/kern.log"):
        super().__init__(log_file_path)
    
    def parse_log_line(self, log_line: str) -> Optional[Dict]:
        """
        Parse kernel log events.
        
        Args:
            log_line: Log line to parse
            
        Returns:
            Parsed event dictionary or None
        """
        # Try OOM killer (critical)
        match = self.OOM_KILLER_PATTERN.search(log_line)
        if match:
            timestamp_str, pid = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            if timestamp:
                return {
                    'timestamp': timestamp,
                    'event_type': 'oom_killer',
                    'pid': pid,
                    'severity': 'Critical',
                    'category': 'kernel',
                    'raw_line': log_line.strip()
                }
        
        # Try USB device
        match = self.USB_DEVICE_PATTERN.search(log_line)
        if match:
            timestamp_str, vendor_id, product_id = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            if timestamp:
                return {
                    'timestamp': timestamp,
                    'event_type': 'usb_device',
                    'vendor_id': vendor_id,
                    'product_id': product_id,
                    'severity': 'Medium',
                    'category': 'kernel',
                    'raw_line': log_line.strip()
                }
        
        # Try kernel error
        match = self.KERNEL_ERROR_PATTERN.search(log_line)
        if match:
            timestamp_str, message = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            if timestamp:
                return {
                    'timestamp': timestamp,
                    'event_type': 'kernel_error',
                    'message': message.strip(),
                    'severity': 'High',
                    'category': 'kernel',
                    'raw_line': log_line.strip()
                }
        
        # Try kernel warning
        match = self.KERNEL_WARNING_PATTERN.search(log_line)
        if match:
            timestamp_str, message = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            if timestamp:
                return {
                    'timestamp': timestamp,
                    'event_type': 'kernel_warning',
                    'message': message.strip(),
                    'severity': 'Medium',
                    'category': 'kernel',
                    'raw_line': log_line.strip()
                }
        
        return None


class WebServerLogParser(BaseLogParser):
    """Parser for Apache/Nginx access and error logs."""
    
    # Apache/Nginx access log (Common Log Format)
    ACCESS_LOG_PATTERN = re.compile(
        r'^([\d.]+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\w+)\s+([^"]+)\s+HTTP/[\d.]+"\s+(\d{3})\s+(\d+|-)'
    )
    # SQL injection patterns
    SQLI_PATTERN = re.compile(
        r"(union.*select|select.*from|insert.*into|delete.*from|'\s*or\s*'1'='1|1=1|--)",
        re.IGNORECASE
    )
    # XSS patterns
    XSS_PATTERN = re.compile(
        r'(<script|<iframe|javascript:|onerror=|onload=)',
        re.IGNORECASE
    )
    # Apache/Nginx error log
    ERROR_LOG_PATTERN = re.compile(
        r'\[(\w{3}\s+\w{3}\s+\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\d{4})\]\s+\[(\w+)\](?:.*?client:\s+([\d.]+))?'
    )
    
    def __init__(self, log_file_path: str = "/var/log/apache2/access.log", log_type: str = "access"):
        super().__init__(log_file_path)
        self.log_type = log_type  # 'access' or 'error'
    
    def parse_log_line(self, log_line: str) -> Optional[Dict]:
        """
        Parse web server log events.
        
        Args:
            log_line: Log line to parse
            
        Returns:
            Parsed event dictionary or None
        """
        if self.log_type == "access":
            return self.parse_access_log(log_line)
        else:
            return self.parse_error_log(log_line)
    
    def parse_access_log(self, log_line: str) -> Optional[Dict]:
        """Parse Apache/Nginx access log."""
        match = self.ACCESS_LOG_PATTERN.search(log_line)
        if not match:
            return None
        
        ip, timestamp_str, method, uri, status, size = match.groups()
        
        # Parse timestamp (different format for access logs)
        try:
            timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                # Try without timezone
                timestamp = datetime.strptime(timestamp_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                return None
        
        # Detect attacks
        severity = 'Low'
        attack_type = None
        
        if self.SQLI_PATTERN.search(uri):
            severity = 'Critical'
            attack_type = 'sql_injection'
        elif self.XSS_PATTERN.search(uri):
            severity = 'High'
            attack_type = 'xss_attempt'
        elif int(status) >= 400:
            severity = 'Medium' if int(status) >= 500 else 'Low'
        
        result = {
            'timestamp': timestamp,
            'ip': ip,
            'event_type': attack_type or 'web_access',
            'method': method,
            'uri': uri,
            'status': status,
            'severity': severity,
            'category': 'web',
            'raw_line': log_line.strip()
        }
        
        if attack_type:
            result['attack_detected'] = True
        
        return result
    
    def parse_error_log(self, log_line: str) -> Optional[Dict]:
        """Parse Apache/Nginx error log."""
        match = self.ERROR_LOG_PATTERN.search(log_line)
        if not match:
            return None
        
        timestamp_str, level, client_ip = match.groups()
        
        try:
            timestamp = datetime.strptime(timestamp_str, "%a %b %d %H:%M:%S.%f %Y")
        except ValueError:
            return None
        
        severity_map = {
            'emerg': 'Critical',
            'alert': 'Critical',
            'crit': 'Critical',
            'error': 'High',
            'warn': 'Medium',
            'notice': 'Low',
            'info': 'Low',
            'debug': 'Low'
        }
        
        return {
            'timestamp': timestamp,
            'ip': client_ip or 'unknown',
            'event_type': 'web_error',
            'error_level': level,
            'severity': severity_map.get(level.lower(), 'Medium'),
            'category': 'web',
            'raw_line': log_line.strip()
        }


class DatabaseLogParser(BaseLogParser):
    """Parser for MySQL/MariaDB/PostgreSQL logs."""
    
    # MySQL/MariaDB error patterns
    MYSQL_ACCESS_DENIED_PATTERN = re.compile(
        r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?Access denied for user '(.+?)'@'(.+?)'"
    )
    MYSQL_ERROR_PATTERN = re.compile(
        r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?\[ERROR\]\s+(.+)$"
    )
    # PostgreSQL patterns
    PGSQL_FAILED_LOGIN_PATTERN = re.compile(
        r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?FATAL:.*?password authentication failed for user "(.+?)"'
    )
    PGSQL_ERROR_PATTERN = re.compile(
        r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?ERROR:.*?(.+)$'
    )
    
    def __init__(self, log_file_path: str = None, db_type: str = "mysql"):
        super().__init__(log_file_path)
        self.db_type = db_type  # 'mysql' or 'postgresql'
        
        # Auto-detect log path if not provided
        if not log_file_path:
            if db_type == "mysql":
                possible_paths = [
                    "/var/log/mysql/error.log",
                    "/var/log/mariadb/mariadb.log",
                    "/var/log/mysql.log"
                ]
            else:  # postgresql
                possible_paths = [
                    "/var/log/postgresql/postgresql.log",
                    "/var/log/postgresql/postgresql-*.log"
                ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    self.log_file_path = path
                    break
    
    def parse_log_line(self, log_line: str) -> Optional[Dict]:
        """
        Parse database log events.
        
        Args:
            log_line: Log line to parse
            
        Returns:
            Parsed event dictionary or None
        """
        if self.db_type == "mysql":
            return self.parse_mysql_log(log_line)
        else:
            return self.parse_postgresql_log(log_line)
    
    def parse_mysql_log(self, log_line: str) -> Optional[Dict]:
        """Parse MySQL/MariaDB log."""
        # Try access denied
        match = self.MYSQL_ACCESS_DENIED_PATTERN.search(log_line)
        if match:
            timestamp_str, user, host = match.groups()
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
            
            return {
                'timestamp': timestamp,
                'event_type': 'db_auth_failed',
                'user': user,
                'ip': host,
                'severity': 'High',
                'category': 'database',
                'raw_line': log_line.strip()
            }
        
        # Try error
        match = self.MYSQL_ERROR_PATTERN.search(log_line)
        if match:
            timestamp_str, message = match.groups()
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
            
            return {
                'timestamp': timestamp,
                'event_type': 'db_error',
                'message': message.strip(),
                'severity': 'Medium',
                'category': 'database',
                'raw_line': log_line.strip()
            }
        
        return None
    
    def parse_postgresql_log(self, log_line: str) -> Optional[Dict]:
        """Parse PostgreSQL log."""
        # Try failed login
        match = self.PGSQL_FAILED_LOGIN_PATTERN.search(log_line)
        if match:
            timestamp_str, user = match.groups()
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
            
            return {
                'timestamp': timestamp,
                'event_type': 'db_auth_failed',
                'user': user,
                'severity': 'High',
                'category': 'database',
                'raw_line': log_line.strip()
            }
        
        # Try error
        match = self.PGSQL_ERROR_PATTERN.search(log_line)
        if match:
            timestamp_str, message = match.groups()
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
            
            return {
                'timestamp': timestamp,
                'event_type': 'db_error',
                'message': message.strip(),
                'severity': 'Medium',
                'category': 'database',
                'raw_line': log_line.strip()
            }
        
        return None


class JournalLogParser(AuthLogParser):
    """Parser that reads from systemd-journald using journalctl."""
    
    def __init__(self, services: List[str] = ['ssh', 'sshd']):
        """
        Initialize journal parser.
        
        Args:
            services: List of systemd variables to filter by (e.g. ssh, sshd)
        """
        self.cmd = ['journalctl', '-f', '-n', '0', '--no-pager']
        # Use -t (syslog identifier) instead of -u (unit) to catch logger messages too
        # Modern SSH uses 'sshd-session' identifier, older versions use 'sshd'
        identifiers = ['sshd', 'sshd-session', 'ssh', 'sudo', 'su']
        for ident in identifiers:
            self.cmd.extend(['-t', ident])
            
        self.process = None
        self.current_year = datetime.now().year
        self._start_process()
    
    def _start_process(self):
        """Start the journalctl process."""
        try:
            # Use bufsize=1 for line buffering and text mode
            self.process = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,           # Text mode instead of bytes
                bufsize=1,           # Line buffering
            )
            print(f"✅ Started journalctl monitoring: {' '.join(self.cmd)}")
        except Exception as e:
            print(f"❌ Failed to start journalctl: {e}")
            self.process = None

    def read_new_lines(self, last_position: int = 0) -> Tuple[List[str], int]:
        """
        Read new lines from journalctl stdout.
        Ignores last_position as this is a stream.
        """
        lines = []
        if not self.process:
            return [], 0

        # Check if process is still alive
        if self.process.poll() is not None:
            print("⚠️  journalctl process died, restarting...")
            self._start_process()
            return [], 0

        # Read available lines with multiple attempts
        # journalctl may take a moment to output events
        try:
            max_attempts = 10
            for attempt in range(max_attempts):
                ready, _, _ = select.select([self.process.stdout], [], [], 0.1)
                
                if ready:
                    line = self.process.stdout.readline()
                    if line:
                        lines.append(line)
                        # After getting a line, quickly check for more
                        continue
                    else:
                        # readline() returned empty, no more data
                        break
                else:
                    # No data available
                    if lines:
                        # We already got some lines, stop waiting
                        break
                    # No lines yet, keep waiting (up to max_attempts)
                    
        except Exception as e:
            print(f"Error reading journal: {e}")
            
        return lines, 0
