import json
import httpx
import logging
from fastapi import HTTPException
from typing import Dict, Any

from app.core.config import settings
from app.schemas.command import CommandRiskRequest, CommandRiskResponse, RiskLevel

logger = logging.getLogger(__name__)


class OpenAIService:
    """Service for interacting with the OpenAI API."""
    
    async def assess_command_risk(self, command_data: CommandRiskRequest) -> CommandRiskResponse:
        """
        Assess the security risk level of a command using OpenAI.
        
        Args:
            command_data: Data about the command execution
            
        Returns:
            Risk assessment with level and explanation
        """
        try:
            # System prompt instructing the LLM what to do
            system_prompt = """
            You are a Linux security expert analyzing commands for potential security risks.
            Evaluate the given command and classify it into one of these risk levels:
            
            - critical: Commands that could cause severe system damage, data loss, or security breaches
              Examples: rm -rf /, dd if=/dev/zero of=/dev/sda, wget malicious_script | bash
            
            - high: Commands that modify system configuration, add users, change permissions
              Examples: chmod 777 /etc/passwd, useradd, visudo, chown -R
            
            - medium: Commands that access sensitive data or establish network connections
              Examples: cat /etc/shadow, ssh, nc, curl with credentials
            
            - low: Information gathering or standard utility commands
              Examples: ls, find, ps, grep

            - minimal: Basic navigation or display commands
              Examples: cd, pwd, echo, date
            
            Analyze the full context including:
            - The command itself and its arguments
            - User executing the command (root is higher risk)
            - Working directory (commands in system directories may be higher risk)
            
            Respond ONLY with a JSON object containing:
            {
              "risk_level": "one of [critical, high, medium, low, minimal]",
              "reason": "brief explanation of risk assessment"
            }
            """
            
            # User prompt containing the command to analyze
            user_prompt = f"""
            Analyze this command execution:
            
            Command: {command_data.command}
            Arguments: {command_data.arguments}
            Username: {command_data.username}
            Working Directory: {command_data.working_directory or "unknown"}
            """
            
            # Prepare request to OpenAI API
            openai_url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {settings.OPENAI_API_KEY}"
            }
            
            payload = {
                "model": "gpt-4",  # Or other suitable model
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.1,  # Low temperature for consistent responses
                "max_tokens": 300
            }

            # Make API call to OpenAI
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    openai_url,
                    headers=headers,
                    json=payload
                )
                
                if response.status_code != 200:
                    logger.error(f"OpenAI API error: {response.text}")
                    raise HTTPException(
                        status_code=500,
                        detail="Error communicating with OpenAI API"
                    )
                
                response_data = response.json()
                
            # Extract and parse response
            ai_response = response_data["choices"][0]["message"]["content"].strip()
            
            try:
                # Parse JSON response
                risk_data = json.loads(ai_response)
                
                # Validate the returned risk level
                risk_level = risk_data.get("risk_level", "").lower()
                
                if risk_level not in [e.value for e in RiskLevel]:
                    logger.warning(f"Invalid risk level '{risk_level}' returned by OpenAI, defaulting to medium")
                    risk_level = "medium"
                
                reason = risk_data.get("reason", "No reason provided by risk assessment engine")
                
                return CommandRiskResponse(risk_level=risk_level, reason=reason)
            
            except json.JSONDecodeError:
                logger.error(f"Failed to parse OpenAI response as JSON: {ai_response}")
                return CommandRiskResponse(
                    risk_level="medium",
                    reason="Error parsing risk assessment. Defaulting to medium risk."
                )
                
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            logger.exception(f"Unexpected error in command risk assessment: {str(e)}")
            return CommandRiskResponse(
                risk_level="medium",
                reason=f"Error during risk assessment: {str(e)}. Defaulting to medium risk."
            )