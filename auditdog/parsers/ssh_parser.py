import re
from datetime import datetime
from typing import Dict, Any, Optional
import time
from .base import BaseParser

class SSHParser(BaseParser):
    """Parser for SSH log entries with expanded pattern support for various formats"""
    
    # Enhanced regular expressions for different SSH log formats
    PATTERNS = {
        'accepted': [
            # Modern format with ISO timestamp and hostname (AWS/systemd)
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
                r'Accepted (?P<auth_method>\S+) for (?P<user>\S+) from '
                r'(?P<ip_address>\S+)'
            ),
            # Traditional syslog format
            re.compile(
                r'(?P<time>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+'
                r'Accepted (?P<auth_method>\S+) for (?P<user>\S+) from '
                r'(?P<ip_address>\S+)'
            ),
            # Session opened format
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
                r'(?:session opened|New session) .*? for user (?P<user>\S+)'
            ),
        ],
        'pam_session': [
            # PAM session opening (common in Ubuntu/RHEL)
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
                r'pam_unix\(sshd:session\): session opened for user (?P<user>[^\s\(]+)(?:\(uid=\d+\))? by'
            ),
            # Traditional format
            re.compile(
                r'(?P<time>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+'
                r'pam_unix\(sshd:session\): session opened for user (?P<user>[^\s\(]+)'
            ),
        ],
        'systemd_session': [
            # Systemd-logind new session
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+systemd-logind\[\d+\]:\s+'
                r'New session (?P<session_id>\d+) of user (?P<user>\S+)'
            ),
        ],
        'failed': [
            # Modern format
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
                r'Failed (?P<auth_method>\S+) for (?P<user>\S+) from '
                r'(?P<ip_address>\S+)'
            ),
            # Traditional format
            re.compile(
                r'(?P<time>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+'
                r'Failed (?P<auth_method>\S+) for (?P<user>\S+) from '
                r'(?P<ip_address>\S+)'
            ),
            # Modern authentication failure format
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
                r'pam_unix\(sshd:auth\): authentication failure.*rhost=(?P<ip_address>\S+).*user=(?P<user>\S+)'
            ),
        ],
        'invalid_user': [
            # Modern format
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
                r'Invalid user (?P<user>\S+) from (?P<ip_address>\S+)'
            ),
            # Traditional format
            re.compile(
                r'(?P<time>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+'
                r'Invalid user (?P<user>\S+) from (?P<ip_address>\S+)'
            ),
        ],
        'connection_closed': [
            # Modern format
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
                r'(?:Connection closed|Disconnected from) (?:user (?P<user>\S+) )?(?P<ip_address>\S+)'
            ),
            # Traditional format
            re.compile(
                r'(?P<time>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+'
                r'(?:Connection closed|Disconnected from) (?:user (?P<user>\S+) )?(?P<ip_address>\S+)'
            ),
        ]
    }
    
    # Track recent events to correlate related events
    SESSION_TIMEOUT = 5  # seconds
    
    def __init__(self, debug=False):
        super().__init__()
        self.debug = debug
        self._recent_events = {}  # user -> (timestamp, event_data)
        
    def parse(self, log_line: str, metadata: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Parse an SSH log line into a structured event.
        
        Args:
            log_line: The log line to parse
            metadata: Additional metadata about the log line
            
        Returns:
            A structured event dict if the line matches an SSH event pattern,
            None otherwise.
        """
        if self.debug:
            print(f"DEBUG: Parsing line: {log_line}")
            
        if metadata is None:
            metadata = {}
            
        # Try each event type and its patterns
        for event_type, patterns in self.PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(log_line)  # Using search instead of match
                if match:
                    if self.debug:
                        print(f"DEBUG: Matched pattern for {event_type}")
                    
                    event_data = match.groupdict()
                    
                    # Fill in defaults for missing fields
                    if 'auth_method' not in event_data:
                        event_data['auth_method'] = 'unknown'
                    
                    if 'user' not in event_data:
                        event_data['user'] = 'unknown'
                        
                    if 'ip_address' not in event_data and 'sshd' in log_line:
                        # Try to extract IP from the log line for sshd entries
                        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_line)
                        if ip_match:
                            event_data['ip_address'] = ip_match.group(1)
                        else:
                            event_data['ip_address'] = 'unknown'
                    
                    # Add event type
                    if event_type == 'accepted':
                        event_data['event'] = 'ssh_login_success'
                    elif event_type == 'pam_session':
                        event_data['event'] = 'ssh_session_opened'
                        # This might be part of a login sequence, check if we've seen this user recently
                        self._recent_events[event_data['user']] = (time.time(), event_data)
                        # This might not be an event we want to report directly
                        return None
                    elif event_type == 'systemd_session':
                        event_data['event'] = 'ssh_login_success'
                        # Check if we have a recent accepted event for this user
                        if event_data['user'] in self._recent_events:
                            recent_time, recent_data = self._recent_events[event_data['user']]
                            # If this is within our timeout, merge the events
                            if time.time() - recent_time < self.SESSION_TIMEOUT:
                                # Take IP from the earlier event if available
                                if 'ip_address' in recent_data and 'ip_address' not in event_data:
                                    event_data['ip_address'] = recent_data['ip_address']
                                # Take authentication method if available
                                if 'auth_method' in recent_data:
                                    event_data['auth_method'] = recent_data['auth_method']
                    elif event_type == 'failed':
                        event_data['event'] = 'ssh_login_failed'
                    elif event_type == 'invalid_user':
                        event_data['event'] = 'ssh_invalid_user'
                    elif event_type == 'connection_closed':
                        event_data['event'] = 'ssh_connection_closed'
                    
                    # Add metadata
                    event_data.update(metadata)
                    
                    # Parse timestamp if possible
                    if 'time' in event_data:
                        try:
                            # Try ISO format first
                            if 'T' in event_data['time']:
                                # Handle ISO 8601 timestamp
                                # Strip microseconds and timezone for simpler parsing
                                iso_time = event_data['time'].split('.')[0]
                                event_data['timestamp'] = datetime.fromisoformat(iso_time)
                            else:
                                # Handle traditional syslog format
                                current_year = datetime.now().year
                                timestamp = f"{event_data['time']} {current_year}"
                                event_data['timestamp'] = datetime.strptime(
                                    timestamp, '%b %d %H:%M:%S %Y'
                                )
                        except (ValueError, TypeError):
                            # Keep the original string if parsing fails
                            if self.debug:
                                print(f"DEBUG: Failed to parse timestamp: {event_data['time']}")
                    
                    # Clean up the event data before returning
                    cleaned_event = {}
                    for key, value in event_data.items():
                        # Skip metadata keys or internal keys
                        if key not in ('hostname', 'time'):
                            cleaned_event[key] = value
                            
                    return cleaned_event
                    
        # If we get here, no pattern matched
        if self.debug and ('sshd' in log_line or 'ssh' in log_line):
            print(f"DEBUG: No pattern matched for SSH-related line: {log_line}")
            
        return None