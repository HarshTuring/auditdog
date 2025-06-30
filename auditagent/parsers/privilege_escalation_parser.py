import re
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import logging

from .base import BaseParser

logger = logging.getLogger('auditdog.privilege')

class PrivilegeEscalationParser(BaseParser):
    """Parser for privilege escalation events from auth logs."""
    
    # Default configuration
    DEFAULT_FAILURE_THRESHOLD = 3       # Max allowed failures before alerting
    DEFAULT_FAILURE_WINDOW = 30 * 60    # 30 minutes in seconds
    
    def __init__(self, debug=False, failure_threshold=None, failure_window_minutes=None):
        super().__init__()
        self.debug = debug
        
        # Configure failure tracking
        self.failure_threshold = failure_threshold or self.DEFAULT_FAILURE_THRESHOLD
        self.failure_window = (failure_window_minutes or 30) * 60  # Convert minutes to seconds
        
        if debug:
            logger.setLevel(logging.DEBUG)
            
        # Regular expressions based on actual log format samples
        self.PATTERNS = [
            # Sudo authentication failure pattern
            ('sudo_auth_failure', re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sudo:.*authentication failure.*user=(?P<user>\S+)'
            )),
            # Sudo execution pattern
            ('sudo_exec', re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sudo(?:\[\d+\])?:\s+(?P<user>\S+)\s+:\s+.*COMMAND=(?P<command>.*)'
            )),
            # Su session opened pattern - indicates a successful attempt
            ('su_session_opened', re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+su\[\d+\]:\s+pam_unix\(su:session\):\s+session\s+'
                r'opened for user\s+(?P<target_user>[^\(]+)(?:\(uid=\d+\))?\s+by\s+(?P<user>[^\(]+)'
            )),
            # Su authentication failure pattern 
            ('su_authentication_failure', re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+su:\s+pam_unix\(su:auth\):\s+authentication failure;'
                r'.*ruser=(?P<user>\S+).*user=(?P<target_user>\S+)'
            ))
        ]
        
        # Track recent events for deduplication
        self.recent_events = {}
        self.dedup_window = 5  # seconds
        
        # Track authentication failures
        self.auth_failures = {}  # Format: {username: [timestamp1, timestamp2, ...]}
        
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
            
        # For debugging
        if self.debug:
            logger.debug(f"Checking privilege escalation line: {log_line}")
            
        # Try each pattern
        for event_type, pattern in self.PATTERNS:
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
                if event_type == 'su_authentication_failure':
                    event['user'] = event_data.get('user', '').strip('()')
                    event['target_user'] = event_data.get('target_user', '').strip('()')
                    event['success'] = False
                    event['description'] = f"User '{event['user']}' failed to switch to '{event['target_user']}'"
                    
                    # Track this failure
                    self._record_auth_failure(event['user'])
                    
                elif event_type == 'su_session_opened':
                    event['user'] = event_data.get('user', '').strip('()')
                    event['target_user'] = event_data.get('target_user', '').strip('()')
                    event['success'] = True
                    event['description'] = f"User '{event['user']}' successfully switched to '{event['target_user']}'"
                    
                elif event_type == 'sudo_auth_failure':
                    event['user'] = event_data.get('user', '')
                    event['success'] = False
                    event['description'] = f"User '{event['user']}' failed sudo authentication"
                    
                    # Track this failure
                    self._record_auth_failure(event['user'])
                    
                elif event_type == 'sudo_exec':
                    event['user'] = event_data.get('user', '')
                    event['command'] = event_data.get('command', '')
                    event['success'] = True
                    event['description'] = f"User '{event['user']}' executed command with sudo: {event['command']}"
                
                # Check for duplicate events by their keys
                event_key = self._create_event_key(event)
                if self._is_duplicate_event(event_key):
                    if self.debug:
                        logger.debug(f"Suppressing duplicate privilege escalation event: {event_key}")
                    return None
                
                # Save event key to recent events
                self.recent_events[event_key] = time.time()
                
                # Check if we need to alert for excessive failures
                if not event.get('success', True):
                    user = event.get('user', '')
                    failure_count = self._get_recent_failure_count(user)
                    if failure_count >= self.failure_threshold:
                        event['threshold_exceeded'] = True
                        event['failure_count'] = failure_count
                        event['description'] += f" [ALERT: {failure_count} failed attempts in the last {self.failure_window // 60} minutes]"
                
                if self.debug:
                    logger.debug(f"Created privilege escalation event: {event}")
                
                return event
                
        return None
    
    def _record_auth_failure(self, username: str) -> None:
        """
        Record an authentication failure for a user.
        
        Args:
            username: The username to record the failure for
        """
        current_time = time.time()
        
        # Initialize list for this user if needed
        if username not in self.auth_failures:
            self.auth_failures[username] = []
            
        # Add the current timestamp to the user's failures
        self.auth_failures[username].append(current_time)
        
        # Clean up old failures for this user
        self._cleanup_old_failures(username)
        
        # Log the failure count for debugging
        failure_count = len(self.auth_failures[username])
        if self.debug:
            logger.debug(f"Recorded auth failure for {username} (count: {failure_count})")
            if failure_count >= self.failure_threshold:
                logger.debug(f"ALERT: User {username} has exceeded the failure threshold ({self.failure_threshold})")
    
    def _get_recent_failure_count(self, username: str) -> int:
        """
        Get the number of recent failures for a user within the failure window.
        
        Args:
            username: The username to check
            
        Returns:
            The number of failures within the window
        """
        if username not in self.auth_failures:
            return 0
            
        # Clean up old failures first
        self._cleanup_old_failures(username)
        
        # Return the count of remaining failures
        return len(self.auth_failures[username])
    
    def _cleanup_old_failures(self, username: str) -> None:
        """
        Remove old failures outside the failure window.
        
        Args:
            username: The username to clean up failures for
        """
        if username not in self.auth_failures:
            return
            
        current_time = time.time()
        cutoff_time = current_time - self.failure_window
        
        # Keep only failures within the window
        self.auth_failures[username] = [
            timestamp for timestamp in self.auth_failures[username]
            if timestamp >= cutoff_time
        ]
        
    def _create_event_key(self, event: Dict[str, Any]) -> str:
        """Create a unique key for deduplication based on event data."""
        subtype = event.get('subtype', '')
        user = event.get('user', '')
        target_user = event.get('target_user', '')
        timestamp = event.get('timestamp', '')[:19]  # Use just the main part of timestamp
        
        return f"{timestamp}:{subtype}:{user}:{target_user}"
    
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
            
        # Clean up old failures for all users
        usernames = list(self.auth_failures.keys())
        for username in usernames:
            self._cleanup_old_failures(username)
            # Remove users with no recent failures
            if not self.auth_failures[username]:
                del self.auth_failures[username]