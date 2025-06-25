import asyncio
from typing import Dict, List, Any, Optional

class AuditDogAgent:
    """Main agent controller for AuditDog"""
    
    def __init__(self):
        self.watchers = []
        self.parsers = []
        self.running = False
        
    def add_watcher(self, watcher):
        """Add a watcher to the agent"""
        self.watchers.append(watcher)
        
    def add_parser(self, parser):
        """Add a parser to the agent"""
        self.parsers.append(parser)
        
    def _process_log_line(self, log_line: str, metadata: Dict[str, Any]) -> None:
        """Process a new log line from a watcher"""
        # Try each parser until one succeeds
        for parser in self.parsers:
            event = parser.parse(log_line, metadata)
            if event:
                self._process_event(event)
                break
                
    def _process_event(self, event: Dict[str, Any]) -> None:
        """Process a structured event"""
        # In the initial implementation, we'll just print the event
        event_type = event.get('event', 'unknown')
        
        if event_type == 'ssh_login_success':
            print(f"SSH Login: User {event['user']} logged in from {event['ip_address']} using {event['auth_method']}")
        elif event_type == 'ssh_login_failed':
            print(f"Failed SSH Login: User {event['user']} failed to log in from {event['ip_address']}")
        elif event_type == 'ssh_invalid_user':
            print(f"Invalid SSH User: {event['user']} from {event['ip_address']}")
        elif event_type == 'ssh_connection_closed':
            print(f"SSH Connection Closed: {event['ip_address']}")
        else:
            print(f"Unknown event: {event}")
            
    async def start(self) -> None:
        """Start the agent and all its watchers"""
        if self.running:
            return
            
        self.running = True
        
        # Start all watchers
        start_tasks = [watcher.start() for watcher in self.watchers]
        if start_tasks:
            await asyncio.gather(*start_tasks)
            
    async def stop(self) -> None:
        """Stop the agent and all its watchers"""
        if not self.running:
            return
            
        self.running = False
        
        # Stop all watchers
        stop_tasks = [watcher.stop() for watcher in self.watchers]
        if stop_tasks:
            await asyncio.gather(*stop_tasks)