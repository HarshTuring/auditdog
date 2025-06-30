import re
import time
from datetime import datetime
from typing import Dict, Any, Optional

from .base import BaseParser

class PrivilegeEscalationParser(BaseParser):
    """Parser for privilege escalation events from auth logs."""
    
    def __init__(self, debug=False):
        super().__init__()
        self.debug = debug
        
        # Regular expressions for different privilege escalation patterns
        self.PATTERNS = {
            'sudo_exec': [
                # Modern format with ISO timestamp (systemd)
                re.compile(
                    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                    r'(?P<hostname>\S+)\s+sudo\[\d+\]:\s+'
                    r'(?P<user>\S+)\s+:\s+(?:TTY=(?P<tty>\S+))?\s*'
                    r'(?:PWD=(?P<pwd>\S+))?\s*(?:USER=(?P<target_user>\S+))?\s*'
                    r'(?:COMMAND=(?P<command>.*))?'
                ),
                # Traditional syslog format
                re.compile(
                    r'(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+).*sudo\[\d+\]:\s+'
                    r'(?P<user>\S+)\s+:\s+(?:TTY=(?P<tty>\S+))?\s*'
                    r'(?:PWD=(?P<pwd>\S+))?\s*(?:USER=(?P<target_user>\S+))?\s*'
                    r'(?:COMMAND=(?P<command>.*))?'
                )
            ],
            'sudo_auth_failure': [
                # Modern format
                re.compile(
                    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                    r'(?P<hostname>\S+)\s+sudo\[\d+\]:\s+(?:pam_unix\(sudo:auth\):)?\s*'
                    r'authentication failure.*user=(?P<user>\S+)'
                ),
                # Traditional format
                re.compile(
                    r'(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+).*sudo\[\d+\]:\s+(?:pam_unix\(sudo:auth\):)?\s*'
                    r'authentication failure.*user=(?P<user>\S+)'
                )
            ],
            'su_attempt': [
                # Modern format
                re.compile(
                    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                    r'(?P<hostname>\S+)\s+su\[\d+\]:\s+'
                    r'(?P<result>Successful|FAILED) su for (?P<target_user>\S+) by (?P<user>\S+)'
                ),
                # Traditional format
                re.compile(
                    r'(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+).*su\[\d+\]:\s+'
                    r'(?P<result>Successful|FAILED) su for (?P<target_user>\S+) by (?P<user>\S+)'
                )
            ],
            'su_session': [
                # PAM session opening for su
                re.compile(
                    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                    r'(?P<hostname>\S+)\s+su\[\d+\]:\s+pam_unix\(su(?:-l)?:session\):\s*session\s+'
                    r'(?P<action>opened|closed) for user (?P<target_user>\S+)(?:\s+by\s+(?P<user>\S+))?'
                ),
                # Traditional format
                re.compile(
                    r'(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+).*su\[\d+\]:\s+pam_unix\(su(?:-l)?:session\):\s*session\s+'
                    r'(?P<action>opened|closed) for user (?P<target_user>\S+)(?:\s+by\s+(?P<user>\S+))?'
                )
            ],
            'sudo_session': [
                # PAM session for sudo
                re.compile(
                    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                    r'(?P<hostname>\S+)\s+sudo\[\d+\]:\s+pam_unix\(sudo:session\):\s*session\s+'
                    r'(?P<action>opened|closed) for user (?P<target_user>\S+)'
                ),
                # Traditional format
                re.compile(
                    r'(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+).*sudo\[\d+\]:\s+pam_unix\(sudo:session\):\s*session\s+'
                    r'(?P<action>opened|closed) for user (?P<target_user>\S+)'
                )
            ],
            'pkexec': [
                # Polkit execution
                re.compile(
                    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                    r'(?P<hostname>\S+)\s+pkexec\[\d+\]:\s+(?P<user>\S+): Executing command'
                    r'\s+\[(?P<command>.*)\]'
                ),
                # Traditional format
                re.compile(
                    r'(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+).*pkexec\[\d+\]:\s+(?P<user>\S+): Executing command'
                    r'\s+\[(?P<command>.*)\]'
                )
            ],
            'group_mod': [
                # Group modification (adding user to sudo/wheel group)
                re.compile(
                    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                    r'(?P<hostname>\S+)\s+(?:usermod|groupmod|gpasswd)\[\d+\]:\s+'
                    r'add \'(?P<target_user>\S+)\' to group \'(?P<group>\S+)\''
                ),
                # Traditional format
                re.compile(
                    r'(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+).*(?:usermod|groupmod|gpasswd)\[\d+\]:\s+'
                    r'add \'(?P<target_user>\S+)\' to group \'(?P<group>\S+)\''
                )
            ],
            'sudoers_mod': [
                # Direct sudoers file modification
                re.compile(
                    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                    r'(?P<hostname>\S+)\s+(?P<command>vi|vim|nano|emacs|visudo)\[\d+\]:\s+'
                    r'(?P<user>\S+)\s+:.*(?:/etc/sudoers)'
                ),
                # Traditional format
                re.compile(
                    r'(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+).*(?P<command>vi|vim|nano|emacs|visudo)\[\d+\]:\s+'
                    r'(?P<user>\S+)\s+:.*(?:/etc/sudoers)'
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
            
        # Try each pattern type
        for event_type, patterns in self.PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(log_line)
                if match:
                    if self.debug:
                        print(f"DEBUG: Matched privilege escalation pattern for {event_type}")
                    
                    # Extract matched data
                    event_data = match.groupdict()
                    
                    # Create the base event
                    event = {
                        'event': 'privilege_escalation',
                        'subtype': event_type,
                        'timestamp': self._parse_timestamp(event_data.get('timestamp')),
                        'source': metadata.get('source', 'unknown')
                    }
                    
                    # Add fields based on the event type
                    if event_type == 'sudo_exec':
                        event['user'] = event_data.get('user', 'unknown')
                        event['target_user'] = event_data.get('target_user', 'root')
                        event['command'] = event_data.get('command', '')
                        event['tty'] = event_data.get('tty', '')
                        event['pwd'] = event_data.get('pwd', '')
                        event['success'] = True
                        
                    elif event_type == 'sudo_auth_failure':
                        event['user'] = event_data.get('user', 'unknown')
                        event['success'] = False
                        
                    elif event_type == 'su_attempt':
                        event['user'] = event_data.get('user', 'unknown')
                        event['target_user'] = event_data.get('target_user', '')
                        event['success'] = event_data.get('result') == 'Successful'
                        
                    elif event_type == 'su_session':
                        event['target_user'] = event_data.get('target_user', '')
                        event['user'] = event_data.get('user', 'unknown')
                        event['action'] = event_data.get('action', '')
                        event['success'] = event_data.get('action') == 'opened'
                        
                    elif event_type == 'sudo_session':
                        event['target_user'] = event_data.get('target_user', '')
                        event['action'] = event_data.get('action', '')
                        event['success'] = event_data.get('action') == 'opened'
                        
                    elif event_type == 'pkexec':
                        event['user'] = event_data.get('user', 'unknown')
                        event['command'] = event_data.get('command', '')
                        event['success'] = True
                        
                    elif event_type == 'group_mod':
                        event['target_user'] = event_data.get('target_user', '')
                        event['group'] = event_data.get('group', '')
                        event['success'] = True
                        
                    elif event_type == 'sudoers_mod':
                        event['user'] = event_data.get('user', 'unknown')
                        event['command'] = event_data.get('command', '')
                        event['success'] = True
                    
                    # Check for duplicates
                    event_key = self._create_event_key(event)
                    if self._is_duplicate_event(event_key):
                        if self.debug:
                            print(f"DEBUG: Suppressing duplicate privilege escalation event: {event_key}")
                        return None
                    
                    # Save event to recently seen
                    self.recent_events[event_key] = time.time()
                    
                    return event
                    
        return None
        
    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[str]:
        """Parse a timestamp string into an ISO format string."""
        if not timestamp_str:
            return None
            
        try:
            # Try ISO format first
            if 'T' in timestamp_str:
                # Already ISO format, return as is or parse and reformat
                return timestamp_str
            else:
                # Handle traditional syslog format
                current_year = datetime.now().year
                dt = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                return dt.isoformat()
        except ValueError:
            # Return the original if we can't parse it
            if self.debug:
                print(f"DEBUG: Failed to parse timestamp: {timestamp_str}")
            return timestamp_str
    
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