from fastapi import APIRouter

api_router = APIRouter()

# We'll add these routes as we implement them:
# from app.api.api_v1.endpoints import events, stats, agents, alerts

@api_router.get("/")
async def root():
    """Root endpoint for API v1."""
    return {
        "message": "Welcome to AuditDog API",
        "version": "1.0",
        "status": "operational"
    }