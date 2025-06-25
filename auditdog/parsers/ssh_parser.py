import re
from datetime import datetime
from typing import Dict, Any, Optional

from .base import BaseParser

class SSHParser(BaseParser):
    """Parser for SSH log entries"""
    
    # Regular expressions for different SSH log formats
    PATTERNS = {
        'accepted': re.compile(
            r'(?P<time>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: '
            r'Accepted (?P<auth_method>\S+) for (?P<user>\S+) from '
            r'(?P<ip_address>\S+) port (?P<port>\d+)'
        ),
        'failed': re.compile(
            r'(?P<time>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: '
            r'Failed (?P<auth_method>\S+) for (?P<user>\S+) from '
            r'(?P<ip_address>\S+) port (?P<port>\d+)'
        ),
        'invalid_user': re.compile(
            r'(?P<time>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: '
            r'Invalid user (?P<user>\S+) from (?P<ip_address>\S+)'
        ),
        'connection_closed': re.compile(
            r'(?P<time>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: '
            r'Connection closed by (?P<ip_address>\S+)'
        )
    }
    
    def __init__(self):
        super().__init__()
        
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
        if metadata is None:
            metadata = {}
            
        # Try each pattern
        for event_type, pattern in self.PATTERNS.items():
            match = pattern.match(log_line)
            if match:
                event_data = match.groupdict()
                
                # Add event type
                if event_type == 'accepted':
                    event_data['event'] = 'ssh_login_success'
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
                        # Assume current year for the timestamp
                        current_year = datetime.now().year
                        timestamp = f"{event_data['time']} {current_year}"
                        event_data['timestamp'] = datetime.strptime(
                            timestamp, '%b %d %H:%M:%S %Y'
                        )
                    except ValueError:
                        # Keep the original string if parsing fails
                        pass
                        
                return event_data
                
        # No pattern matched
        return None