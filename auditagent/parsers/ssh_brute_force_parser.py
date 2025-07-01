import re
import time
import subprocess
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Set
import ipaddress

from .base import BaseParser

logger = logging.getLogger('auditdog.ssh_brute_force')

class SSHBruteForceBlocker:
    """Manages blocking and unblocking of IP addresses for SSH brute force attempts."""
    
    def __init__(self, debug=False):
        self.debug = debug
        self.blocked_ips = {}  # IP address -> unblock_time
        self.block_timers = {}  # IP address -> timer
        
    def block_ip(self, ip_address: str, minutes: int) -> bool:
        """
        Block an IP address for the specified duration.
        
        Args:
            ip_address: IP to block
            minutes: Duration in minutes
            
        Returns:
            True if successfully blocked, False otherwise
        """
        if self.debug:
            logger.debug(f"Attempting to block IP {ip_address} for {minutes} minutes")
            
        # Skip if already blocked
        if ip_address in self.blocked_ips:
            return False
            
        try:
            # Use iptables to block the IP
            # Create a rule to reject SSH traffic from this IP
            cmd = ['iptables', '-A', 'INPUT', '-s', ip_address, '-p', 'tcp', 
                   '--dport', '22', '-j', 'REJECT', '--reject-with', 'tcp-reset']
            
            if self.debug:
                logger.debug(f"Running command: {' '.join(cmd)}")
                
            result = subprocess.run(cmd, check=True, capture_output=True)
            
            # Calculate unblock time
            unblock_time = time.time() + (minutes * 60)
            self.blocked_ips[ip_address] = unblock_time
            
            # Schedule unblock
            self._schedule_unblock(ip_address, minutes)
            
            if self.debug:
                logger.debug(f"IP {ip_address} blocked until {datetime.fromtimestamp(unblock_time)}")
                
            return True
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to block IP: {e.stderr.decode() if e.stderr else str(e)}"
            logger.error(error_msg)
            return False
        except Exception as e:
            logger.error(f"Unexpected error blocking IP: {str(e)}")
            return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Remove block for an IP address.
        
        Args:
            ip_address: IP to unblock
            
        Returns:
            True if successfully unblocked, False otherwise
        """
        if self.debug:
            logger.debug(f"Attempting to unblock IP {ip_address}")
            
        # Skip if not blocked
        if ip_address not in self.blocked_ips:
            return False
            
        try:
            # Use iptables to remove the block rule
            cmd = ['iptables', '-D', 'INPUT', '-s', ip_address, '-p', 'tcp', 
                   '--dport', '22', '-j', 'REJECT', '--reject-with', 'tcp-reset']
            
            if self.debug:
                logger.debug(f"Running command: {' '.join(cmd)}")
                
            result = subprocess.run(cmd, check=True, capture_output=True)
            
            # Remove from tracking
            del self.blocked_ips[ip_address]
            
            # Cancel timer if exists
            if ip_address in self.block_timers:
                timer = self.block_timers.pop(ip_address)
                timer.cancel()
                
            if self.debug:
                logger.debug(f"IP {ip_address} unblocked")
                
            return True
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to unblock IP: {e.stderr.decode() if e.stderr else str(e)}"
            logger.error(error_msg)
            return False
        except Exception as e:
            logger.error(f"Unexpected error unblocking IP: {str(e)}")
            return False
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """
        Check if an IP is currently blocked.
        
        Args:
            ip_address: IP to check
            
        Returns:
            True if blocked, False otherwise
        """
        return ip_address in self.blocked_ips
    
    def get_remaining_block_time(self, ip_address: str) -> int:
        """
        Get the remaining block time in minutes.
        
        Args:
            ip_address: IP to check
            
        Returns:
            Remaining minutes or 0 if not blocked
        """
        if ip_address not in self.blocked_ips:
            return 0
            
        remaining_seconds = max(0, self.blocked_ips[ip_address] - time.time())
        return int(remaining_seconds / 60)
    
    def _schedule_unblock(self, ip_address: str, minutes: int) -> None:
        """
        Schedule IP unblock after specified minutes.
        
        Args:
            ip_address: IP to unblock
            minutes: Minutes to wait before unblocking
        """
        import threading
        
        # Create a timer to unblock after the specified time
        timer = threading.Timer(
            minutes * 60, 
            self._unblock_timer_callback,
            args=[ip_address]
        )
        timer.daemon = True
        
        # Save and start the timer
        self.block_timers[ip_address] = timer
        timer.start()
        
        if self.debug:
            logger.debug(f"Scheduled unblock for IP {ip_address} in {minutes} minutes")
    
    def _unblock_timer_callback(self, ip_address: str) -> None:
        """
        Callback for timer to unblock an IP.
        
        Args:
            ip_address: IP to unblock
        """
        success = self.unblock_ip(ip_address)
        
        if self.debug:
            if success:
                logger.debug(f"Auto-unblocked IP {ip_address}")
            else:
                logger.debug(f"Auto-unblock failed for IP {ip_address}")


class SSHBruteForceParser(BaseParser):
    """
    Parser for detecting SSH brute force attempts based on failed login patterns.
    """
    
    # Default configuration
    DEFAULT_FAILURE_THRESHOLD = 5    # Block after this many failures
    DEFAULT_FAILURE_WINDOW = 5 * 60  # Look at failures in the last 5 minutes
    DEFAULT_BLOCK_MINUTES = 30       # Block IPs for 30 minutes
    
    def __init__(self, debug=False,
                failure_threshold=None,
                failure_window_minutes=None,
                block_minutes=None,
                enable_blocking=True,
                whitelist=None):
        """
        Initialize the SSH brute force parser.
        
        Args:
            debug: Enable debug logging
            failure_threshold: Number of failures before blocking (default: 5)
            failure_window_minutes: Window for counting failures in minutes (default: 5)
            block_minutes: How long to block IPs in minutes (default: 30)
            enable_blocking: Whether to enable automatic IP blocking (default: True)
            whitelist: List of IPs/networks to never block (default: None)
        """
        self.debug = debug
        
        # Configure thresholds
        self.failure_threshold = failure_threshold or self.DEFAULT_FAILURE_THRESHOLD
        self.failure_window = (failure_window_minutes or 5) * 60  # Convert to seconds
        self.block_minutes = block_minutes or self.DEFAULT_BLOCK_MINUTES
        self.enable_blocking = enable_blocking
        
        # Initialize blocklist manager
        self.blocker = SSHBruteForceBlocker(debug=debug)
        
        # IP tracking data structures
        self.ip_failures = {}        # IP -> list of failure timestamps
        self.user_failures = {}      # Username -> list of failure timestamps
        self.ip_user_failures = {}   # IP+User -> list of failure timestamps
        self.recent_alerts = set()   # Set of recently alerted IPs to avoid spam
        
        # Configure whitelist
        self.whitelist = set()
        self.whitelist_networks = []
        if whitelist:
            self._configure_whitelist(whitelist)
            
        # Patterns to match SSH authentication failures and invalid users
        # These are already covered by SSHParser but we're specifically tracking 
        # them for brute force detection
        self.ssh_failure_patterns = [
            # Failed password pattern
            re.compile(
                r'(?:Failed password for|authentication failure;).*'
                r'(?:user\s+|from\s+)(?P<user>\S+).*'
                r'(?:from\s+|rhost=)(?P<ip_address>\S+)'
            ),
            # Invalid user pattern
            re.compile(
                r'Invalid user (?P<user>\S+) from (?P<ip_address>\S+)'
            ),
            # Authentication failure pattern with rhost
            re.compile(
                r'pam_unix\(sshd:auth\):\s+authentication failure.*'
                r'rhost=(?P<ip_address>\S+).*user=(?P<user>\S+)'
            ),
            # Maximum authentication attempts exceeded
            re.compile(
                r'error: maximum authentication attempts exceeded for '
                r'(?:invalid user )?(?P<user>\S+) from (?P<ip_address>\S+)'
            )
        ]
        
        # For tracking events that have already been processed
        self.processed_lines = set()
        
        if debug:
            logger.setLevel(logging.DEBUG)
            logger.debug("SSH brute force parser initialized")
    
    def parse(self, log_line: str, metadata: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Parse a log line to detect SSH brute force attempts.
        
        Args:
            log_line: The log line to parse
            metadata: Additional metadata about the log line
            
        Returns:
            Dict containing the event if a brute force attempt is detected, None otherwise.
        """
        if metadata is None:
            metadata = {}
            
        # Easy pre-filter to skip irrelevant lines
        if not ('sshd' in log_line and ('fail' in log_line.lower() or 'invalid' in log_line)):
            return None
            
        # Skip already processed lines
        line_hash = hash(log_line)
        if line_hash in self.processed_lines:
            return None
            
        # Add to processed lines
        self.processed_lines.add(line_hash)
        
        # Limit size of processed_lines set to avoid memory issues
        if len(self.processed_lines) > 10000:
            self.processed_lines = set(list(self.processed_lines)[-5000:])
        
        # For debugging
        if self.debug:
            logger.debug(f"Checking brute force pattern: {log_line}")
            
        # Extract timestamp from the log line if present
        # Patterns vary by system, so try a few common formats
        timestamp_patterns = [
            # ISO format: 2023-01-02T03:04:05.123+00:00
            re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'),
            # Syslog format: Jan  1 01:23:45
            re.compile(r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')
        ]
        
        log_timestamp = None
        for pattern in timestamp_patterns:
            match = pattern.search(log_line)
            if match:
                log_timestamp = match.group('timestamp')
                break
        
        # Try to match against our failure patterns
        for pattern in self.ssh_failure_patterns:
            match = pattern.search(log_line)
            if match:
                # Extract user and IP information
                user = match.group('user') if 'user' in match.groupdict() else 'unknown'
                ip_address = match.group('ip_address') if 'ip_address' in match.groupdict() else 'unknown'
                
                # Skip if IP is invalid or unknown
                if ip_address == 'unknown' or not self._is_valid_ip(ip_address):
                    continue
                    
                # Skip if IP is in whitelist
                if self._is_ip_whitelisted(ip_address):
                    if self.debug:
                        logger.debug(f"Skipping whitelisted IP {ip_address}")
                    continue
                
                if self.debug:
                    logger.debug(f"SSH failure detected: User={user}, IP={ip_address}")
                
                # Record the failure
                current_time = time.time()
                event = self._record_failure(ip_address, user, current_time)
                
                # If we've created an event (threshold exceeded), return it
                if event:
                    return event
                    
                # If no threshold exceeded yet, we just record the failure but don't return an event
                return None
                
        # No match found
        return None
    
    def _record_failure(self, ip_address: str, username: str, timestamp: float) -> Optional[Dict[str, Any]]:
        """
        Record a failed login attempt and check if thresholds have been exceeded.
        
        Args:
            ip_address: The source IP address
            username: The attempted username
            timestamp: The time of the attempt
            
        Returns:
            An event dict if thresholds exceeded, None otherwise
        """
        # Initialize tracking structures if needed
        if ip_address not in self.ip_failures:
            self.ip_failures[ip_address] = []
        
        if username not in self.user_failures:
            self.user_failures[username] = []
            
        ip_user_key = f"{ip_address}:{username}"
        if ip_user_key not in self.ip_user_failures:
            self.ip_user_failures[ip_user_key] = []
        
        # Record this failure
        self.ip_failures[ip_address].append(timestamp)
        self.user_failures[username].append(timestamp)
        self.ip_user_failures[ip_user_key].append(timestamp)
        
        # Clean up old failures
        self._cleanup_old_failures()
        
        # Create a failure entry for storage
        failure_event = {
            'event': 'ssh_brute_force_attempt',
            'subtype': 'failed_login',
            'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
            'ip_address': ip_address,
            'username': username,
            'failure_count': len(self.ip_failures[ip_address]),
            'is_blocked': self.blocker.is_ip_blocked(ip_address)
        }
        
        # Check if this IP is already blocked
        if self.blocker.is_ip_blocked(ip_address):
            # Update the event with remaining block time
            remaining_minutes = self.blocker.get_remaining_block_time(ip_address)
            failure_event['block_minutes_remaining'] = remaining_minutes
            # No need to check thresholds if already blocked
            return failure_event
        
        # Get counts of failures within our window
        ip_count = self._count_recent_failures(self.ip_failures[ip_address], timestamp)
        ip_user_count = self._count_recent_failures(self.ip_user_failures[ip_user_key], timestamp)
        
        # Check threshold for IP-based blocking
        if ip_count >= self.failure_threshold:
            if self.debug:
                logger.debug(f"IP {ip_address} exceeded threshold with {ip_count} failures")
                
            # Create a detection event
            detection_event = {
                'event': 'ssh_brute_force_detected',
                'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                'ip_address': ip_address,
                'username': username,
                'failure_count': ip_count,
                'threshold': self.failure_threshold,
                'window_minutes': self.failure_window // 60,
                'is_blocked': False,
                'block_minutes': self.block_minutes
            }
            
            # Block the IP if enabled
            if self.enable_blocking:
                block_success = self.blocker.block_ip(ip_address, self.block_minutes)
                detection_event['is_blocked'] = block_success
                
                if self.debug:
                    if block_success:
                        logger.debug(f"Blocked IP {ip_address} for {self.block_minutes} minutes")
                    else:
                        logger.debug(f"Failed to block IP {ip_address}")
            
            # Return the detection event
            return detection_event
            
        # Not enough failures to trigger detection yet
        return None
    
    def _count_recent_failures(self, failures: List[float], current_time: float) -> int:
        """
        Count failures within the configured window.
        
        Args:
            failures: List of failure timestamps
            current_time: Current timestamp
            
        Returns:
            Count of failures within the window
        """
        cutoff_time = current_time - self.failure_window
        return sum(1 for t in failures if t >= cutoff_time)
    
    def _cleanup_old_failures(self) -> None:
        """Remove old failures outside our window to prevent memory growth."""
        current_time = time.time()
        cutoff_time = current_time - (self.failure_window * 2)  # Double the window for cleanup
        
        # Helper to filter out old timestamps
        def filter_old_timestamps(timestamps):
            return [t for t in timestamps if t >= cutoff_time]
            
        # Clean up IP failures
        for ip in list(self.ip_failures.keys()):
            self.ip_failures[ip] = filter_old_timestamps(self.ip_failures[ip])
            if not self.ip_failures[ip]:
                del self.ip_failures[ip]
                
        # Clean up user failures
        for user in list(self.user_failures.keys()):
            self.user_failures[user] = filter_old_timestamps(self.user_failures[user])
            if not self.user_failures[user]:
                del self.user_failures[user]
                
        # Clean up IP:user failures
        for key in list(self.ip_user_failures.keys()):
            self.ip_user_failures[key] = filter_old_timestamps(self.ip_user_failures[key])
            if not self.ip_user_failures[key]:
                del self.ip_user_failures[key]
    
    def _is_valid_ip(self, ip_address: str) -> bool:
        """Check if a string is a valid IP address."""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    def _is_ip_whitelisted(self, ip_address: str) -> bool:
        """
        Check if an IP is in the whitelist.
        
        Args:
            ip_address: IP to check
            
        Returns:
            True if whitelisted, False otherwise
        """
        # Check if the IP is directly in the whitelist
        if ip_address in self.whitelist:
            return True
            
        # Check if the IP is in any whitelisted network
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            for network in self.whitelist_networks:
                if ip_obj in network:
                    return True
        except ValueError:
            # If the IP is invalid, it's not whitelisted
            pass
            
        return False
    
    def _configure_whitelist(self, whitelist: List[str]) -> None:
        """
        Configure IP whitelist.
        
        Args:
            whitelist: List of IPs and networks (CIDR notation) to whitelist
        """
        for item in whitelist:
            item = item.strip()
            if not item:
                continue
                
            try:
                # Check if it's a CIDR network
                if '/' in item:
                    network = ipaddress.ip_network(item, strict=False)
                    self.whitelist_networks.append(network)
                else:
                    # It's a single IP
                    ip = ipaddress.ip_address(item)
                    self.whitelist.add(item)
            except ValueError as e:
                logger.warning(f"Invalid whitelist entry '{item}': {e}")
    
    def cleanup_old_events(self) -> None:
        """Clean up old events to prevent memory growth."""
        self._cleanup_old_failures()
        
        # Clear alert set periodically to allow re-alerting for persistent attackers
        self.recent_alerts.clear()