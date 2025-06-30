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
        
        # Regular expressions for different privilege escalation patterns
        # Simplified and more generic patterns to increase match likelihood
        self.PATTERNS = {
            'sudo_exec': [
                # Sudo execution pattern - more lenient to match various formats
                re.compile(
                    r'sudo(?:\[\d+\])?:?\s+(?P<user>\S+)\s+:.*(?:COMMAND=(?P<command>.*))'
                )
            ],
            'sudo_auth_failure': [
                # Sudo authentication failure pattern
                re.compile(
                    r'(?:sudo|pam_unix)(?:\[\d+\])?:(?:[^:]*authentication failure|.*incorrect password)[^:]*(?:user=)?(?P<user>\S+)'
                )
            ],
            'su_attempt': [
                # Su attempt pattern
                re.compile(
                    r'su(?:\[\d+\])?:(?:\s+.*)?(?:(?P<result>Successful|FAILED)\s+su\s+for|session (?P<action>opened|closed) for user)\s+(?P<target_user>\S+)(?:\s+by\s+(?P<user>\S+))?'
                )
            ],
            'group_mod': [
                # Group modification pattern
                re.compile(
                    r'(?:usermod|groupmod|gpasswd)(?:\[\d+\])?:.*(?:group \'(?P<group>\S+)\'|\'(?P<target_user>\S+)\' to group)'
                )
            ],
            'sudoers_mod': [
                # Direct sudoers file access pattern
                re.compile(
                    r'(?:vi|vim|nano|emacs|visudo|cat|more|less)(?:\[\d+\])?:.*(?:/etc/sudoers)'
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
            
        # Skip lines that don't look relevant to privilege escalation to improve performance
        # Quick pre-check to only process relevant lines
        if not any(keyword in log_line for keyword in ['sudo', 'su:', 'su[', 'pam_unix', 'usermod', 'groupmod', 'visudo']):
            return None
            
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
                        'timestamp': datetime.now().isoformat(),
                        'source': metadata.get('source', 'unknown'),
                        'original_log': log_line  # Store original log for debugging
                    }
                    
                    # Add fields based on the event type
                    if event_type == 'sudo_exec':
                        event['user'] = event_data.get('user', 'unknown')
                        event['command'] = event_data.get('command', '')
                        event['success'] = True
                        
                    elif event_type == 'sudo_auth_failure':
                        event['user'] = event_data.get('user', 'unknown')
                        event['success'] = False
                        
                    elif event_type == 'su_attempt':
                        event['user'] = event_data.get('user', 'unknown')
                        event['target_user'] = event_data.get('target_user', '')
                        event['action'] = event_data.get('action', '')
                        result = event_data.get('result', '')
                        event['success'] = (result == 'Successful' or event_data.get('action') == 'opened')
                        
                    elif event_type == 'group_mod':
                        event['target_user'] = event_data.get('target_user', '')
                        event['group'] = event_data.get('group', '')
                        event['success'] = True
                        
                    elif event_type == 'sudoers_mod':
                        # We can't reliably extract user from sudoers_mod patterns
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
        command = event.get('command', '')[:20] # Truncate command for key
        
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