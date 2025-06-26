import re
import time
from datetime import datetime
from typing import Dict, Any, Optional, List

from .base import BaseParser

class AuditdCommandParser(BaseParser):
    """Parser for auditd log entries related to command execution."""
    
    def __init__(self, debug=False):
        self.debug = debug
        # Track partial command events by ID
        self.partial_events = {}
        # Event cleanup timer
        self.last_cleanup = time.time()
        # Track recently reported commands to avoid duplicates
        self.recent_commands = {}
        
        # Patterns for matching different auditd record types
        self.timestamp_pattern = re.compile(r'audit\((?P<timestamp>[\d\.]+):(?P<event_id>\d+)\)')
        self.syscall_pattern = re.compile(r'type=SYSCALL .*?syscall=(?P<syscall>\d+).*? success=(?P<success>\S+).*? uid=(?P<uid>\d+).*? gid=(?P<gid>\d+).*? euid=(?P<euid>\d+).*? pid=(?P<pid>\d+)')
        self.execve_pattern = re.compile(r'type=EXECVE .*?argc=(?P<argc>\d+) a0=(?P<command>\S+)(?: a1=(?P<arg1>\S+))?(?: a2=(?P<arg2>\S+))?')
        self.path_pattern = re.compile(r'type=PATH .*?item=(?P<item>\d+).*? name=(?P<name>\S+).*? inode=(?P<inode>\d+)')
        self.cwd_pattern = re.compile(r'type=CWD .*?cwd=(?P<cwd>\S+)')
        self.user_pattern = re.compile(r'type=USER .*?uid=(?P<uid>\d+).*? auid=(?P<auid>\d+).*? ses=(?P<session>\d+)')
        
        # Syscall number for execve (could be different on some architectures)
        self.execve_syscall = 59  # execve syscall number on x86_64
        
        # Command deduplication window (seconds)
        self.dedup_window = 5
        
    def parse(self, log_line: str, metadata: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Parse a log line into a structured event.
        
        Args:
            log_line: The log line to parse
            metadata: Additional metadata about the log line
            
        Returns:
            A structured event dict if the parsing succeeded, None otherwise.
        """
        if metadata is None:
            metadata = {}
            
        # Check if it's time to clean up old events
        current_time = time.time()
        if current_time - self.last_cleanup > 60:  # Clean up every minute
            self._cleanup_old_events()
            self.last_cleanup = current_time
        
        # Only process auditd logs
        if not log_line.startswith('type='):
            return None
            
        # Extract event ID and timestamp
        timestamp_match = self.timestamp_pattern.search(log_line)
        if not timestamp_match:
            return None
            
        timestamp = timestamp_match.group('timestamp')
        event_id = timestamp_match.group('event_id')
        
        # Initialize event if not already present
        if event_id not in self.partial_events:
            self.partial_events[event_id] = {
                'timestamp': datetime.fromtimestamp(float(timestamp)).isoformat(),
                'event_id': event_id,
                'parts': set(),
                'created_at': current_time
            }
        
        # Track which parts we've seen
        event = self.partial_events[event_id]
        
        # Process SYSCALL records
        syscall_match = self.syscall_pattern.search(log_line)
        if syscall_match:
            event['parts'].add('syscall')
            syscall = int(syscall_match.group('syscall'))
            if syscall != self.execve_syscall:
                # We're only interested in execve syscalls
                del self.partial_events[event_id]
                return None
                
            # This is an execve syscall, so gather relevant information
            event['success'] = syscall_match.group('success') == 'yes'
            event['uid'] = syscall_match.group('uid')
            event['euid'] = syscall_match.group('euid')
            event['gid'] = syscall_match.group('gid')
            event['pid'] = syscall_match.group('pid')
            
        # Process EXECVE records
        execve_match = self.execve_pattern.search(log_line)
        if execve_match:
            event['parts'].add('execve')
            # Remove quotes if present
            command = execve_match.group('command')
            event['command'] = self._unquote(command)
            
            # Build arguments list
            args = []
            for i in range(1, int(execve_match.group('argc'))):
                arg_match = re.search(f'a{i}=(?P<arg>\\S+)', log_line)
                if arg_match:
                    args.append(self._unquote(arg_match.group('arg')))
            
            event['args'] = args
                
        # Process CWD records
        cwd_match = self.cwd_pattern.search(log_line)
        if cwd_match:
            event['parts'].add('cwd')
            event['cwd'] = self._unquote(cwd_match.group('cwd'))
            
        # Process PATH records for the executable path
        path_match = self.path_pattern.search(log_line)
        if path_match and path_match.group('item') == '0':
            event['parts'].add('path')
            event['executable'] = self._unquote(path_match.group('name'))
            
        # Process USER records
        user_match = self.user_pattern.search(log_line)
        if user_match:
            event['parts'].add('user')
            event['auid'] = user_match.group('auid')
            event['session'] = user_match.group('session')
            
        # Check if we have enough information to create a complete command event
        # At minimum, we need syscall, execve and either command or executable
        if {'syscall', 'execve'}.issubset(event['parts']) and event.get('success', False):
            if 'command' in event or 'executable' in event:
                # Get username from UID (would need to use pwd module in production)
                username = self._get_username_from_uid(event.get('uid', '0'))
                
                # Create a command event
                command_str = event.get('command', event.get('executable', 'unknown'))
                args_str = ' '.join(event.get('args', []))
                
                # Check for duplication
                command_key = f"{username}:{command_str}:{args_str}"
                if self._is_duplicate_command(command_key, current_time):
                    # Clean up and skip this duplicate
                    if self.debug:
                        print(f"DEBUG: Skipping duplicate command: {command_key}")
                    del self.partial_events[event_id]
                    return None
                
                # Mark this command as seen
                self.recent_commands[command_key] = current_time
                
                # Build the complete event
                command_event = {
                    'event': 'command_execution',
                    'timestamp': event['timestamp'],
                    'user': username,
                    'command': command_str,
                    'arguments': args_str,
                    'working_directory': event.get('cwd', ''),
                    'pid': event.get('pid', ''),
                    'exit_code': 0 if event.get('success', False) else 1,
                    'source': metadata.get('source', 'auditd'),
                    'metadata': {
                        'uid': event.get('uid', ''),
                        'euid': event.get('euid', ''),
                        'gid': event.get('gid', ''),
                        'session_id': event.get('session', '')
                    }
                }
                
                # Clean up the partial event
                del self.partial_events[event_id]
                
                return command_event
                
        # If we get here, the event is not yet complete
        return None
    
    def _unquote(self, text):
        """Remove quotes from text if present."""
        if text.startswith('"') and text.endswith('"'):
            return text[1:-1].replace('\\"', '"')
        return text
        
    def _get_username_from_uid(self, uid):
        """Get username from UID."""
        # In a real implementation, we would use:
        # import pwd
        # try:
        #     return pwd.getpwuid(int(uid)).pw_name
        # except (KeyError, ValueError):
        #     return f"user_{uid}"
        return f"user_{uid}"
        
    def _is_duplicate_command(self, command_key, current_time):
        """Check if this command was recently seen."""
        if command_key in self.recent_commands:
            if current_time - self.recent_commands[command_key] < self.dedup_window:
                return True
        return False
        
    def _cleanup_old_events(self):
        """Clean up old partial events and recent commands."""
        current_time = time.time()
        
        # Clean up partial events older than 30 seconds
        event_ids_to_remove = []
        for event_id, event in self.partial_events.items():
            if current_time - event.get('created_at', 0) > 30:
                event_ids_to_remove.append(event_id)
        
        for event_id in event_ids_to_remove:
            del self.partial_events[event_id]
            
        # Clean up old command records
        commands_to_remove = []
        for command_key, timestamp in self.recent_commands.items():
            if current_time - timestamp > 300:  # 5 minutes
                commands_to_remove.append(command_key)
                
        for command_key in commands_to_remove:
            del self.recent_commands[command_key]