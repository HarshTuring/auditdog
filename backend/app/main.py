import asyncio
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from app.api.api_v1.router import api_router
from app.db.init_db import check_db_connected, initialize_db
from app.core.config import settings

# Initialize FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.PROJECT_DESCRIPTION,
    version=settings.PROJECT_VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    # Check database connection
    is_db_connected = await check_db_connected()
    if not is_db_connected:
        raise Exception("Could not connect to the database")
    
    # Initialize database tables and data
    await initialize_db()


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}