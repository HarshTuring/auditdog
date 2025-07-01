# Update backend/app/api/api_v1/router.py
from fastapi import APIRouter

from app.api.api_v1.endpoints import events, agent_integration, command_risk, ssh_security

api_router = APIRouter()

# Include route modules
api_router.include_router(events.router)
api_router.include_router(agent_integration.router)
api_router.include_router(command_risk.router)  # Add the new command_risk router
api_router.include_router(ssh_security.router)

@api_router.get("/")
async def root():
    """Root endpoint for API v1."""
    return {
        "message": "Welcome to AuditDog API",
        "version": "1.0",
        "status": "operational"
    }