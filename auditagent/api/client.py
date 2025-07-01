import aiohttp
import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger('auditdog.api_client')

class ApiClient:
    """Client for communicating with the AuditDog API."""
    
    def __init__(self, api_url: str, timeout: int = 10):
        self.api_url = api_url.rstrip('/')
        self.timeout = timeout
        self.session = None
        self._closing = False
        
    async def get_session(self):
        """Get or create an aiohttp ClientSession."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )
        return self.session
        
    async def close(self):
        """Close the HTTP session."""
        if self._closing:
            return
            
        self._closing = True
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None
        self._closing = False
            
    async def assess_command_risk(self, command_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send a command to the backend API for risk assessment.
        
        Args:
            command_event: Command event data
            
        Returns:
            Dictionary with risk assessment or None if request failed
        """
        try:
            session = await self.get_session()
            
            # Format request data
            request_data = {
                "command": command_event.get("command", ""),
                "arguments": command_event.get("arguments", ""),
                "username": command_event.get("user", "unknown"),
                "working_directory": command_event.get("working_directory", ""),
                "timestamp": command_event.get("timestamp")
            }
            
            url = f"{self.api_url}/commands/risk-assessment"
            
            async with session.post(url, json=request_data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"API error ({response.status}): {error_text}")
                    return None
                    
                return await response.json()
                
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error: {str(e)}")
        except asyncio.TimeoutError:
            logger.error(f"Request timed out after {self.timeout}s")
        except Exception as e:
            logger.error(f"Unexpected error in API request: {str(e)}")
            
        return None
    
    async def send_brute_force_alert(
        self, 
        ip_address: str,
        username: str,
        failure_count: int,
        threshold: int,
        is_blocked: bool,
        block_minutes: int = 0
    ) -> Dict[str, Any]:
        """
        Send notification about an SSH brute force attack.
        
        Args:
            ip_address: The attacker's IP address
            username: The username that was targeted
            failure_count: Number of failed attempts
            threshold: The configured threshold that was exceeded
            is_blocked: Whether the IP was blocked
            block_minutes: How long the IP was blocked for (if applicable)
            
        Returns:
            Response data or None if request failed
        """
        try:
            session = await self.get_session()
            
            # Format request data
            params = {
                "ip_address": ip_address,
                "username": username,
                "failure_count": failure_count,
                "threshold": threshold,
                "is_blocked": is_blocked,
                "block_minutes": block_minutes
            }
            
            url = f"{self.api_url}/ssh-security/brute-force-alert"
            
            async with session.post(url, params=params) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"API error ({response.status}): {error_text}")
                    return None
                    
                return await response.json()
                    
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error in notification request: {str(e)}")
        except asyncio.TimeoutError:
            logger.error(f"Notification request timed out after {self.timeout}s")
        except Exception as e:
            logger.error(f"Unexpected error in notification API request: {str(e)}")
                
        return None