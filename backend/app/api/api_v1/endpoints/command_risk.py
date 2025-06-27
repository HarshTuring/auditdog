# backend/app/api/api_v1/endpoints/command_risk.py
from fastapi import APIRouter, HTTPException, status, Query

from app.schemas.command import CommandRiskRequest, CommandRiskResponse
from app.services.openai_service import OpenAIService
from datetime import datetime
from typing import Dict, Any, Optional

from app.schemas.command import CommandRiskRequest, CommandRiskResponse, RiskLevel
from app.services.openai_service import OpenAIService
from app.services.telegram_service import TelegramService
from app.core.config import settings

router = APIRouter(prefix="/commands", tags=["commands"])


@router.post("/risk-assessment", response_model=CommandRiskResponse)
async def assess_command_risk(command_data: CommandRiskRequest,):
    """
    Analyze a command execution for security risks.
    
    This endpoint uses OpenAI to assess the security implications of
    the provided command and sends alerts via Telegram if the risk
    exceeds the configured threshold.
    
    Returns a risk assessment with a risk level and explanation.
    """
    openai_service = OpenAIService()
    telegram_service = TelegramService()
    
    # Get risk assessment from OpenAI
    assessment = await openai_service.assess_command_risk(command_data)
    
    if assessment.risk_level.numeric_value >= settings.TELEGRAM_RISK_THRESHOLD.numeric_value:
        # Send alert via Telegram
        await telegram_service.send_command_alert(
            command=command_data.command,
            arguments=command_data.arguments,
            username=command_data.username,
            risk_assessment=assessment,
            working_directory=command_data.working_directory,
            source_ip=command_data.source_ip
        )
    
    return assessment


@router.post("/telegram-test", response_model=Dict[str, Any])
async def test_telegram_notification():
    """
    Send a test notification to configured Telegram chats.
    
    Use this endpoint to verify that your Telegram bot configuration is working correctly.
    """
    telegram_service = TelegramService()
    return await telegram_service.test_notification()