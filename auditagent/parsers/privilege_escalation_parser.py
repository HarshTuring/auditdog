import re
import time
from datetime import datetime
from typing import Dict, Any, Optional
import logging

from .base import BaseParser

logger = logging.getLogger('auditdog.privilege')

class PrivilegeEscalationParser(BaseParser):
    """Parser for privilege escalation events from auth logs."""
    
    def __init__(self, debug=False):
        super().__init__()
        self.debug = debug
        
        if debug:
            logger.setLevel(logging.DEBUG)
            
        # Regular expressions based on actual log format samples
        self.PATTERNS = {
            'su_authentication_failure': [
                # Match the auth failure line pattern exactly as in the log
                re.compile(
                    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                    r'(?P<hostname>\S+)\s+su:\s+pam_unix\(su:auth\):\s+authentication failure;'
                    r'.*ruser=(?P<user>\S+).*user=(?P<target_user>\S+)'
                )
            ],
            'su_session_opened': [
                # Match the session opened line pattern exactly as in the log
                re.compile(
                    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                    r'(?P<hostname>\S+)\s+su\[\d+\]:\s+pam_unix\(su:session\):\s+session\s+'
                    r'opened for user\s+(?P<target_user>[^\(]+)(?:\(uid=\d+\))?\s+by\s+(?P<user>[^\(]+)'
                )
            ],
            'sudo_auth_failure': [
                # Match sudo authentication failure pattern
                re.compile(
                    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                    r'(?P<hostname>\S+)\s+sudo:.*authentication failure.*user=(?P<user>\S+)'
                )
            ],
            'sudo_exec': [
                # Match sudo execution pattern
                re.compile(
                    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                    r'(?P<hostname>\S+)\s+sudo(?:\[\d+\])?:\s+(?P<user>\S+)\s+:\s+.*COMMAND=(?P<command>.*)'
                )
            ]
        }
        
        # Track recent events to avoid duplicates
        self.recent_events = {}
        self.dedup_window = 5  # seconds
        
    def parse(self, log_line: str, metadata: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Parse a log line into a structured privilege escalation event.
        
        Args:
            log_line: The log line to parse
            metadata: Additional metadata about the log line
            
        Returns:
            Dict containing the parsed event or None if line doesn't match
        """
        if metadata is None:
            metadata = {}
            
        # Quick pre-check to skip irrelevant lines
        if not ('su[' in log_line or 'su:' in log_line or 'sudo' in log_line):
            return None
            
        # Print all lines containing su or sudo for debugging
        if self.debug:
            logger.debug(f"Checking privilege escalation line: {log_line}")
            
        # Try each pattern type
        for event_type, patterns in self.PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(log_line)
                if match:
                    if self.debug:
                        logger.debug(f"Matched privilege escalation pattern for {event_type}")
                    
                    # Extract matched data
                    event_data = match.groupdict()
                    
                    # Create the base event
                    event = {
                        'event': 'privilege_escalation',
                        'subtype': event_type,
                        'timestamp': event_data.get('timestamp'),
                        'source': metadata.get('source', 'unknown'),
                        'original_log': log_line  # Store original log for debugging
                    }
                    
                    # Add fields based on the event type
                    if event_type in ['su_authentication_failure', 'su_failed_attempt']:
                        event['user'] = event_data.get('user', '').strip('()')
                        event['target_user'] = event_data.get('target_user', '').strip('()')
                        event['success'] = False
                        
                    elif event_type in ['su_attempt_success', 'su_session_opened']:
                        event['user'] = event_data.get('user', '').strip('()')
                        event['target_user'] = event_data.get('target_user', '').strip('()')
                        event['success'] = True
                        
                    elif event_type == 'sudo_auth_failure':
                        event['user'] = event_data.get('user', '')
                        event['success'] = False
                        
                    elif event_type == 'sudo_exec':
                        event['user'] = event_data.get('user', '')
                        event['command'] = event_data.get('command', '')
                        event['success'] = True
                    
                    # Check for duplicates
                    event_key = self._create_event_key(event)
                    if self._is_duplicate_event(event_key):
                        if self.debug:
                            logger.debug(f"Suppressing duplicate privilege escalation event: {event_key}")
                        return None
                    
                    # Save event to recently seen
                    self.recent_events[event_key] = time.time()
                    
                    if self.debug:
                        logger.debug(f"Created privilege escalation event: {event}")
                    
                    return event
                    
        return None
        
    def _create_event_key(self, event: Dict[str, Any]) -> str:
        """Create a unique key for deduplication based on event data."""
        subtype = event.get('subtype', '')
        user = event.get('user', '')
        target_user = event.get('target_user', '')
        command = event.get('command', '')[:20] if 'command' in event else ''
        
        return f"{subtype}:{user}:{target_user}:{command}"
    
    def _is_duplicate_event(self, event_key: str) -> bool:
        """Check if we've seen this event recently."""
        if event_key in self.recent_events:
            # Check if it's within our deduplication window
            if time.time() - self.recent_events[event_key] < self.dedup_window:
                return True
        return False
    
    def cleanup_old_events(self):
        """Clean up old events to prevent memory leaks."""
        current_time = time.time()
        # Remove events older than 5x our dedup window
        cutoff = current_time - (self.dedup_window * 5)
        
        # Remove old events
        keys_to_remove = [key for key, timestamp in self.recent_events.items() if timestamp < cutoff]
        for key in keys_to_remove:
            del self.recent_events[key]