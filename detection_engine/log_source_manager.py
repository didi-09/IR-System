# log_source_manager.py (Bayoumy's Detection Engine - Log Source Management)
"""
Manages multiple log sources and parsers in a unified way.
Coordinates reading from multiple log files and processing events.
"""
import threading
import time
import sys
import os
from typing import Dict, List, Optional, Callable
from datetime import datetime
from collections import defaultdict

# Handle imports for both module and script execution
try:
    from .log_parser import (
        AuthLogParser, SyslogParser, KernelLogParser,
        WebServerLogParser, DatabaseLogParser, JournalLogParser
    )
    from .log_discovery import LogDiscovery
except ImportError:
    # If relative imports fail, try absolute imports
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from log_parser import (
        AuthLogParser, SyslogParser, KernelLogParser,
        WebServerLogParser, DatabaseLogParser, JournalLogParser
    )
    from log_discovery import LogDiscovery


class LogSource:
    """Represents a single log source with its parser and state."""
    
    def __init__(self, log_type: str, log_path: str, parser_class, priority: int = 1):
        """
        Initialize a log source.
        
        Args:
            log_type: Type of log (auth, syslog, kernel, etc.)
            log_path: Path to log file
            parser_class: Parser class to use
            priority: Priority level (1=high, 2=normal, 3=low)
        """
        self.log_type = log_type
        self.log_path = log_path
        self.priority = priority
        self.last_position = 0
        self.enabled = True
        self.error_count = 0
        self.max_errors = 5
        
        # Initialize parser
        try:
            if parser_class == WebServerLogParser:
                # Determine log type (access vs error)
                subtype = "access" if "access" in log_path else "error"
                self.parser = parser_class(log_path, log_type=subtype)
            elif parser_class == DatabaseLogParser:
                # Determine database type
                db_type = "mysql" if "mysql" in log_path or "mariadb" in log_path else "postgresql"
                self.parser = parser_class(log_path, db_type=db_type)
            else:
                self.parser = parser_class(log_path)
        except Exception as e:
            print(f"⚠️  Error initializing parser for {log_path}: {e}")
            self.enabled = False
            self.parser = None
    
    def read_new_events(self) -> List[Dict]:
        """
        Read new events from this log source.
        
        Returns:
            List of parsed events
        """
        if not self.enabled or not self.parser:
            return []
        
        try:
            # Read new lines
            new_lines, new_position = self.parser.read_new_lines(self.last_position)
            self.last_position = new_position
            
            if not new_lines:
                return []
            
            # Parse lines
            events = []
            for line in new_lines:
                try:
                    parsed = self.parser.parse_log_line(line)
                    if parsed:
                        # Add log source metadata
                        parsed['log_source'] = self.log_type
                        parsed['log_path'] = self.log_path
                        events.append(parsed)
                except Exception as e:
                    # Don't crash on parse errors
                    continue
            
            # Reset error count on success
            if events:
                self.error_count = 0
            
            return events
        
        except Exception as e:
            self.error_count += 1
            if self.error_count >= self.max_errors:
                print(f"⚠️  Disabling {self.log_type} source after {self.error_count} errors")
                self.enabled = False
            return []
    
    def __repr__(self):
        return f"LogSource(type={self.log_type}, path={self.log_path}, enabled={self.enabled})"


class LogSourceManager:
    """Manages multiple log sources and coordinates event processing."""
    
    def __init__(self, auto_discover: bool = True, event_callback: Optional[Callable] = None):
        """
        Initialize log source manager.
        
        Args:
            auto_discover: Automatically discover log files
            event_callback: Function to call when events are parsed
        """
        self.log_sources: List[LogSource] = []
        self.event_callback = event_callback
        self.auto_discover = auto_discover
        self.running = False
        self.event_queue = []
        self.lock = threading.Lock()
        
        # Statistics
        self.stats = defaultdict(int)
    
    def add_log_source(self, log_type: str, log_path: str, priority: int = 1):
        """
        Add a log source.
        
        Args:
            log_type: Type of log
            log_path: Path to log file
            priority: Priority level
        """
        # Determine parser class
        parser_class = self._get_parser_class(log_type)
        if not parser_class:
            print(f"⚠️  Unknown log type: {log_type}")
            return
        
        # Create log source
        source = LogSource(log_type, log_path, parser_class, priority)
        if source.enabled:
            self.log_sources.append(source)
            print(f"✅ Added log source: {log_type} -> {log_path}")
        else:
            print(f"❌ Failed to add log source: {log_type} -> {log_path}")
    
    def _get_parser_class(self, log_type: str):
        """Get parser class for log type."""
        parser_map = {
            'auth': AuthLogParser,
            'syslog': SyslogParser,
            'kernel': KernelLogParser,
            'apache_access': WebServerLogParser,
            'apache_error': WebServerLogParser,
            'nginx_access': WebServerLogParser,
            'nginx_error': WebServerLogParser,
            'mysql': DatabaseLogParser,
            'postgresql': DatabaseLogParser,
            'mariadb': DatabaseLogParser,
            'journal': JournalLogParser,
        }
        return parser_map.get(log_type)
    
    def discover_and_add_sources(self):
        """Automatically discover and add log sources."""
        if not self.auto_discover:
            return
        
        print("\n🔍 Discovering log sources...")
        discovery = LogDiscovery()
        configs = discovery.get_log_sources_config()
        
        for config in configs:
            self.add_log_source(
                config['type'],
                config['path'],
                config['priority']
            )
        
        print(f"✅ Discovered and added {len(self.log_sources)} log sources\n")
    
    def read_all_sources(self) -> List[Dict]:
        """
        Read events from all log sources.
        
        Returns:
            List of all new events
        """
        all_events = []
        
        # Sort by priority (higher priority first)
        sorted_sources = sorted(self.log_sources, key=lambda x: x.priority)
        
        for source in sorted_sources:
            if not source.enabled:
                continue
            
            try:
                events = source.read_new_events()
                if events:
                    all_events.extend(events)
                    self.stats[f'{source.log_type}_events'] += len(events)
                    self.stats['total_events'] += len(events)
            except Exception as e:
                print(f"Error reading from {source.log_type}: {e}")
                continue
        
        return all_events
    
    def process_events(self, events: List[Dict]):
        """
        Process events (call callback or queue).
        
        Args:
            events: List of events to process
        """
        if not events:
            return
        
        if self.event_callback:
            for event in events:
                try:
                    self.event_callback(event)
                except Exception as e:
                    print(f"Error in event callback: {e}")
        else:
            # Queue events if no callback
            with self.lock:
                self.event_queue.extend(events)
    
    def get_queued_events(self) -> List[Dict]:
        """
        Get and clear queued events.
        
        Returns:
            List of queued events
        """
        with self.lock:
            events = self.event_queue.copy()
            self.event_queue.clear()
        return events
    
    def run_once(self):
        """Read and process events from all sources once."""
        events = self.read_all_sources()
        self.process_events(events)
        return events
    
    def print_stats(self):
        """Print statistics about log sources."""
        print("\n" + "=" * 60)
        print("📊 LOG SOURCE STATISTICS")
        print("=" * 60)
        print(f"Total Sources: {len(self.log_sources)}")
        print(f"Active Sources: {sum(1 for s in self.log_sources if s.enabled)}")
        print(f"Total Events Processed: {self.stats.get('total_events', 0)}")
        print("\nEvents by Source:")
        for source in self.log_sources:
            count = self.stats.get(f'{source.log_type}_events', 0)
            status = "✅" if source.enabled else "❌"
            print(f"  {status} {source.log_type}: {count} events")
        print("=" * 60 + "\n")
    
    def __repr__(self):
        return f"LogSourceManager(sources={len(self.log_sources)}, active={sum(1 for s in self.log_sources if s.enabled)})"


if __name__ == "__main__":
    # Test log source manager
    def test_callback(event):
        print(f"📝 Event: {event.get('event_type')} from {event.get('log_source')} (Severity: {event.get('severity', 'N/A')})")
    
    manager = LogSourceManager(auto_discover=True, event_callback=test_callback)
    manager.discover_and_add_sources()
    
    print("\nReading events (this will run once)...")
    events = manager.run_once()
    print(f"\nRead {len(events)} events")
    
    manager.print_stats()
