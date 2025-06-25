import asyncio
import os
from typing import Dict, List, Any, Optional

class AuditDogAgent:
    """Main agent controller for AuditDog"""
    
    def __init__(self, debug=False, storage=None):
        self.watchers = []
        self.parsers = []
        self.storage = storage
        self.running = False
        self.debug = debug
        
    def add_watcher(self, watcher):
        """Add a watcher to the agent"""
        self.watchers.append(watcher)
        
    def add_parser(self, parser):
        """Add a parser to the agent"""
        self.parsers.append(parser)
        
    def set_storage(self, storage):
        """Set the storage backend"""
        self.storage = storage
        
    def _process_log_line(self, log_line: str, metadata: Dict[str, Any]) -> None:
        """Process a new log line from a watcher"""
        if self.debug:
            # Check if it's SSH-related before printing debug
            if 'sshd' in log_line:
                print(f"DEBUG: Processing SSH-related log line: {log_line}")
            
        # Try each parser until one succeeds
        for parser in self.parsers:
            event = parser.parse(log_line, metadata)
            if event:
                self._process_event(event)
                break
                
    def _process_event(self, event: Dict[str, Any]) -> None:
        """Process a structured event"""
        # Store the event if we have storage
        if self.storage:
            self.storage.store_event(event)
        
        # Print the event to the console
        event_type = event.get('event', 'unknown')
        
        if event_type == 'ssh_login_success':
            auth_method = event.get('auth_method', 'unknown method')
            ip_address = event.get('ip_address', 'unknown IP')
            user = event.get('user', 'unknown user')
            
            print(f"\nSSH Login Detected: User '{user}' logged in from {ip_address}" + 
                  (f" using {auth_method}" if auth_method != 'unknown method' else ""))
        elif event_type == 'ssh_login_failed':
            user = event.get('user', 'unknown user')
            ip_address = event.get('ip_address', 'unknown IP')
            auth_method = event.get('auth_method', 'unknown method')
            
            print(f"\nFailed SSH Login: User '{user}' failed to log in from {ip_address}" + 
                  (f" using {auth_method}" if auth_method != 'unknown method' else ""))
        elif event_type == 'ssh_invalid_user':
            user = event.get('user', 'unknown')
            ip_address = event.get('ip_address', 'unknown IP')
            print(f"\nInvalid SSH User: '{user}' from {ip_address}")
        elif event_type == 'ssh_connection_closed':
            ip_address = event.get('ip_address', 'unknown IP')
            user = event.get('user', 'unknown user')
            if user != 'unknown user':
                print(f"\nSSH Connection Closed: User '{user}' from {ip_address}")
            else:
                print(f"\nSSH Connection Closed: {ip_address}")
        else:
            print(f"\nUnknown event: {event}")
            
        # Print a separator to make output more readable
        print("-" * 60)
            
    async def start(self) -> None:
        """Start the agent and all its watchers"""
        if self.running:
            return
            
        if self.debug:
            print("DEBUG: Starting AuditDog agent")
            
        self.running = True
        
        # Start all watchers
        start_tasks = [watcher.start() for watcher in self.watchers]
        if start_tasks:
            await asyncio.gather(*start_tasks)
            
        if self.debug:
            print("DEBUG: All watchers started")
            
    async def stop(self) -> None:
        """Stop the agent and all its watchers"""
        if not self.running:
            return
            
        if self.debug:
            print("DEBUG: Stopping AuditDog agent")
            
        self.running = False
        
        # Stop all watchers
        stop_tasks = [watcher.stop() for watcher in self.watchers]
        if stop_tasks:
            await asyncio.gather(*stop_tasks)
            
        # Close storage if available
        if self.storage and hasattr(self.storage, 'close'):
            self.storage.close()
            
        if self.debug:
            print("DEBUG: All watchers stopped")