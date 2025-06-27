from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional


class RiskLevel(str, Enum):
    """Risk levels for command execution."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class CommandBase(BaseModel):
    """Base model with common fields for command events."""
    command: str = Field(..., description="The command that was executed")
    arguments: str = Field("", description="Arguments passed to the command")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When the command was executed")
    username: str = Field(..., description="User who executed the command")
    working_directory: Optional[str] = Field(None, description="Directory where the command was executed")
    
    # Additional context
    source_ip: Optional[str] = Field(None, description="Source IP if available")
    process_id: Optional[int] = Field(None, description="Process ID of the command")
    command_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class CommandRiskRequest(CommandBase):
    """Request schema for command risk assessment."""
    pass


class CommandRiskResponse(BaseModel):
    """Response schema for command risk assessment."""
    risk_level: RiskLevel = Field(..., description="Assessed risk level of the command")
    reason: str = Field(..., description="Explanation for the risk assessment")