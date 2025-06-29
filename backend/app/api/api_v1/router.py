from fastapi import APIRouter

from app.api.api_v1.endpoints import events, agent_integration

api_router = APIRouter()

# Include route modules
api_router.include_router(events.router)
api_router.include_router(agent_integration.router)

@api_router.get("/")
async def root():
    """Root endpoint for API v1."""
    return {
        "message": "Welcome to AuditDog API",
        "version": "1.0",
        "status": "operational"
    }