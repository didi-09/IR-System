# log_parser.py (Bayoumy's Detection Engine - Log Parsing)
"""
Log parsing module for extracting security-relevant information from system logs.
Focuses on /var/log/auth.log for authentication events.
"""
import re
from datetime import datetime
from typing import Dict, Optional, List

class AuthLogParser:
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
        self.log_file_path = log_file_path
        self.current_year = datetime.now().year
    
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

