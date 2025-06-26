from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import text

from app.db.base import Base
from app.db.session import engine
from app.models.event import SSHEvent  # Import all models to ensure they're registered


async def create_tables() -> None:
    """Create database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def check_db_connected() -> bool:
    """Check if the database is connected."""
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


async def initialize_db() -> None:
    """Initialize the database with required tables and initial data."""
    # Create tables if they don't exist
    await create_tables()
    
    # Here you can add seeding logic if needed
    # async with AsyncSessionLocal() as session:
    #    await seed_initial_data(session)