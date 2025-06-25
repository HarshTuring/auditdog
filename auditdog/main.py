import asyncio
import argparse
import os
import signal
import sys
from datetime import datetime

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from auditdog.core.agent import AuditDogAgent
from auditdog.watchers.file_watcher import FileWatcher
from auditdog.parsers.ssh_parser import SSHParser
from auditdog.storage.json_storage import JSONFileStorage

async def main():
    """Main entry point for the AuditDog agent"""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='AuditDog system monitoring agent')
    parser.add_argument('--ssh-log', type=str, 
                        help='Path to the SSH log file (default: auto-detect)',
                        default=None)
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    parser.add_argument('--from-beginning', action='store_true',
                        help='Process log file from the beginning instead of just new entries')
    parser.add_argument('--storage-dir', type=str,
                        help='Directory to store event logs (default: ./logs)',
                        default='./logs')
    parser.add_argument('--query', action='store_true',
                        help='Query mode: display stored events instead of monitoring')
    parser.add_argument('--event-type', type=str,
                        help='Filter events by type (with --query)')
    parser.add_argument('--user', type=str,
                        help='Filter events by username (with --query)')
    parser.add_argument('--ip', type=str,
                        help='Filter events by IP address (with --query)')
    parser.add_argument('--last', type=int,
                        help='Show only the last N events (with --query)')
    parser.add_argument('--stats', action='store_true',
                        help='Show event statistics')
    args = parser.parse_args()
    
    debug = args.debug
    seek_to_end = not args.from_beginning
    
    # Set up storage directory
    storage_dir = os.path.abspath(args.storage_dir)
    os.makedirs(storage_dir, exist_ok=True)
    
    # Create storage backend
    storage_path = os.path.join(storage_dir, 'events.json')
    storage = JSONFileStorage(storage_path)
    
    # Query mode: display stored events and exit
    if args.query:
        return query_stored_events(storage, args)
    
    # Stats mode: show statistics and exit
    if args.stats:
        return show_statistics(storage)
    
    if debug:
        print("DEBUG: Debug mode enabled")
        print(f"DEBUG: Processing from {'new entries only' if seek_to_end else 'beginning of file'}")
        print(f"DEBUG: Storing events to {storage_path}")
    
    # Determine SSH log file location
    ssh_log_path = args.ssh_log
    if ssh_log_path is None:
        # Auto-detect based on common locations
        possible_paths = [
            '/var/log/auth.log',  # Debian/Ubuntu
            '/var/log/secure',    # RHEL/CentOS
            '/var/log/syslog'     # Fallback
        ]
        for path in possible_paths:
            if os.path.exists(path) and os.access(path, os.R_OK):
                ssh_log_path = path
                if debug:
                    print(f"DEBUG: Auto-detected log file at {ssh_log_path}")
                break
                
    if ssh_log_path is None or not os.path.exists(ssh_log_path):
        print(f"Error: Cannot find readable SSH log file. Please specify with --ssh-log")
        sys.exit(1)
        
    print(f"Monitoring SSH log file: {ssh_log_path}")
    print(f"Storing events to: {storage_path}")
    
    # Test read a few lines to verify access
    try:
        with open(ssh_log_path, 'r') as f:
            test_lines = [f.readline() for _ in range(3)]
        if debug:
            print(f"DEBUG: Successfully read from log file. Example lines:")
            for i, line in enumerate(test_lines):
                if line.strip():
                    print(f"DEBUG: Line {i+1}: {line.strip()}")
    except Exception as e:
        print(f"Error reading from log file: {str(e)}")
        if "Permission denied" in str(e):
            print("Hint: You may need to run this program with sudo or as root")
        sys.exit(1)
    
    # Create and configure the agent
    agent = AuditDogAgent(debug=debug, storage=storage)
    
    # Add the SSH parser
    ssh_parser = SSHParser(debug=debug)
    agent.add_parser(ssh_parser)
    
    # Add the file watcher for SSH logs
    ssh_watcher = FileWatcher(
        ssh_log_path,
        agent._process_log_line,
        seek_to_end=seek_to_end,
        debug=debug
    )
    agent.add_watcher(ssh_watcher)
    
    # Handle graceful shutdown
    loop = asyncio.get_event_loop()
    
    def signal_handler():
        print("\nShutting down...")
        loop.create_task(agent.stop())
        loop.stop()
        
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)
    
    # Start the agent
    await agent.start()
    
    # Add periodic cleanup tasks
    async def cleanup_tasks():
        while True:
            # Clean up old parser events
            for parser in agent.parsers:
                if hasattr(parser, 'cleanup_old_events'):
                    parser.cleanup_old_events()
                    
            # Clean up old storage events (keep last 30 days)
            if storage:
                deleted = storage.cleanup_old_events(max_age_days=30)
                if deleted and debug:
                    print(f"DEBUG: Cleaned up {deleted} old events from storage")
                    
            # Run cleanup every hour
            await asyncio.sleep(3600)
    
    cleanup_task = asyncio.create_task(cleanup_tasks())
    
    try:
        # Run forever
        await asyncio.Future()
    finally:
        # Cancel cleanup task
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
            
        # Make sure we clean up
        await agent.stop()

def query_stored_events(storage, args):
    """Query and display stored events"""
    events = storage.query_events(
        event_type=args.event_type,
        user=args.user,
        ip_address=args.ip,
        limit=args.last
    )
    
    if not events:
        print("No events found matching the criteria.")
        return 0
        
    print(f"Found {len(events)} events:")
    print("-" * 60)
    
    for event in events:
        timestamp = event.get('timestamp', 'unknown time')
        event_type = event.get('event', 'unknown')
        
        if event_type == 'ssh_login_success':
            user = event.get('user', 'unknown')
            ip = event.get('ip_address', 'unknown')
            method = event.get('auth_method', 'unknown')
            print(f"{timestamp} - SSH Login: User '{user}' from {ip} using {method}")
        elif event_type == 'ssh_login_failed':
            user = event.get('user', 'unknown')
            ip = event.get('ip_address', 'unknown')
            print(f"{timestamp} - Failed Login: User '{user}' from {ip}")
        elif event_type == 'ssh_invalid_user':
            user = event.get('user', 'unknown')
            ip = event.get('ip_address', 'unknown')
            print(f"{timestamp} - Invalid User: '{user}' from {ip}")
        else:
            print(f"{timestamp} - {event_type}: {event}")
            
        print("-" * 60)
        
    return 0

def show_statistics(storage):
    """Show statistics about stored events"""
    stats = storage.get_stats()
    
    print("AuditDog Event Statistics")
    print("=" * 40)
    print(f"Total events: {stats['total_events']}")
    print(f"Unique users: {stats['unique_users']}")
    print(f"Unique IP addresses: {stats['unique_ips']}")
    print(f"Storage file: {stats['storage_file']}")
    
    if stats['last_event_time']:
        print(f"Last event: {stats['last_event_time']}")
        
    print("\nEvents by type:")
    for event_type, count in stats['events_by_type'].items():
        print(f"  {event_type}: {count}")
        
    return 0

if __name__ == '__main__':
    asyncio.run(main())