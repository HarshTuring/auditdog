import asyncio
import argparse
import os
import signal
import sys

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from auditdog.core.agent import AuditDogAgent
from auditdog.watchers.file_watcher import FileWatcher
from auditdog.parsers.ssh_parser import SSHParser

async def main():
    """Main entry point for the AuditDog agent"""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='AuditDog system monitoring agent')
    parser.add_argument('--ssh-log', type=str, 
                        help='Path to the SSH log file (default: auto-detect)',
                        default=None)
    args = parser.parse_args()
    
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
                break
                
    if ssh_log_path is None or not os.path.exists(ssh_log_path):
        print(f"Error: Cannot find readable SSH log file. Please specify with --ssh-log")
        sys.exit(1)
        
    print(f"Monitoring SSH log file: {ssh_log_path}")
    
    # Create and configure the agent
    agent = AuditDogAgent()
    
    # Add the SSH parser
    ssh_parser = SSHParser()
    agent.add_parser(ssh_parser)
    
    # Add the file watcher for SSH logs
    ssh_watcher = FileWatcher(
        ssh_log_path,
        agent._process_log_line,
        seek_to_end=True
    )
    agent.add_watcher(ssh_watcher)
    
    # Handle graceful shutdown
    loop = asyncio.get_event_loop()
    
    def signal_handler():
        print("Shutting down...")
        loop.create_task(agent.stop())
        loop.stop()
        
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)
    
    # Start the agent
    await agent.start()

    async def cleanup_old_events():
        while True:
            for parser in agent.parsers:
                if hasattr(parser, 'cleanup_old_events'):
                    parser.cleanup_old_events()
            await asyncio.sleep(60)  # Clean up every minute
            
    cleanup_task = asyncio.create_task(cleanup_old_events())
    
    try:
        # Run forever
        await asyncio.Future()
    finally:
        # Make sure we clean up

        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass

        
        await agent.stop()

if __name__ == '__main__':
    asyncio.run(main())