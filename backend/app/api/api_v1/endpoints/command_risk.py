# backend/app/api/api_v1/endpoints/command_risk.py
from fastapi import APIRouter, HTTPException, status

from app.schemas.command import CommandRiskRequest, CommandRiskResponse
from app.services.openai_service import OpenAIService

router = APIRouter(prefix="/commands", tags=["commands"])


@router.post("/risk-assessment", response_model=CommandRiskResponse)
async def assess_command_risk(command_data: CommandRiskRequest):
    """
    Analyze a command execution for security risks.
    
    This endpoint uses OpenAI to assess the security implications of
    the provided command, considering:
    - The command and its arguments
    - The user executing it
    - The working directory
    
    Returns a risk assessment with a risk level and explanation.
    """
    openai_service = OpenAIService()
    assessment = await openai_service.assess_command_risk(command_data)
    return assessment